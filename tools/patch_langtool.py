#!/usr/bin/env python3
"""Create a separate, expanded CM 01/02 language editor from a known binary."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct


SUPPORTED_SHA256 = "b51d99260742857c454a7f4d67a029dd2fb4f9e7200ebda0c9a965860b7911ba"


def align(value, alignment):
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError("Invalid PE alignment")
    return (value + alignment - 1) & -alignment


def checksum(image, offset):
    total = 0
    for index in range(0, len(image), 2):
        if offset <= index < offset + 4:
            continue
        value = image[index]
        if index + 1 < len(image):
            value |= image[index + 1] << 8
        total += value
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return total + len(image)


def build_image(source, manifest):
    if len(source) != manifest["source_size"]:
        raise ValueError("Unsupported input size; the original executable is required")
    if hashlib.sha256(source).hexdigest() != manifest["source_sha256"]:
        raise ValueError("Unsupported input SHA-256; no files were changed")
    if source[:2] != b"MZ" or len(source) < 64:
        raise ValueError("Input is not a DOS/PE executable")
    pe = struct.unpack_from("<I", source, 0x3C)[0]
    if source[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Missing PE signature")
    machine, section_count = struct.unpack_from("<HH", source, pe + 4)
    optional_size = struct.unpack_from("<H", source, pe + 20)[0]
    optional = pe + 24
    table = optional + optional_size
    if machine != 0x14C or struct.unpack_from("<H", source, optional)[0] != 0x10B:
        raise ValueError("Expected a 32-bit x86 PE executable")
    if struct.unpack_from("<I", source, optional + 28)[0] != 0x400000:
        raise ValueError("Unexpected image base")
    section_alignment, file_alignment = struct.unpack_from("<II", source, optional + 32)
    image_size, header_size = struct.unpack_from("<II", source, optional + 56)
    if table + (section_count + 2) * 40 > header_size or header_size > len(source):
        raise ValueError("No room for the additional section headers")
    data_rva, data_size = manifest["data_rva"], manifest["data_size"]
    code_rva = manifest["code_rva"]
    code = bytes.fromhex(manifest["code"])
    if (not code or data_rva < image_size or data_size <= 0
            or code_rva < align(data_rva + data_size, section_alignment)
            or data_rva % section_alignment or code_rva % section_alignment):
        raise ValueError("Invalid appended-section layout")
    image = bytearray(source)
    last_end = header_size
    for patch in manifest["patches"]:
        offset = patch["offset"]
        before, after = bytes.fromhex(patch["before"]), bytes.fromhex(patch["after"])
        if (not before or len(before) != len(after) or offset < last_end
                or offset + len(before) > len(source)):
            raise ValueError("Invalid or overlapping patch range")
        if source[offset:offset + len(before)] != before:
            raise ValueError(f"Original-byte check failed at file offset {offset:#x}")
        image[offset:offset + len(after)] = after
        last_end = offset + len(before)
    code_offset = align(len(image), file_alignment)
    code_size = align(len(code), file_alignment)
    image.extend(b"\0" * (code_offset - len(image)))
    image.extend(code)
    image.extend(b"\0" * (code_size - len(code)))
    sections = (
        (b".lgdata", data_size, data_rva, 0, 0, 0xC0000080),
        (b".lgcode", len(code), code_rva, code_size, code_offset, 0x60000020),
    )
    for index, (name, virtual_size, rva, raw_size, raw_offset, flags) in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", image, table + (section_count + index) * 40,
                         name, virtual_size, rva, raw_size, raw_offset, 0, 0, 0, 0, flags)
    struct.pack_into("<H", image, pe + 6, section_count + 2)
    old_code = struct.unpack_from("<I", source, optional + 4)[0]
    old_bss = struct.unpack_from("<I", source, optional + 12)[0]
    struct.pack_into("<I", image, optional + 4, old_code + code_size)
    struct.pack_into("<I", image, optional + 12, old_bss + data_size)
    struct.pack_into("<I", image, optional + 56,
                     align(code_rva + len(code), section_alignment))
    old_stack = struct.unpack_from("<I", source, optional + 72)[0]
    struct.pack_into("<I", image, optional + 72, max(old_stack, 8 * 1024 * 1024))
    struct.pack_into("<I", image, optional + 64, checksum(image, optional + 64))
    return bytes(image)


def write_output(path, image):
    with path.open("xb") as stream:
        stream.write(image)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Unmodified original langtool.exe")
    parser.add_argument("output", type=Path, help="New executable; must not already exist")
    args = parser.parse_args()
    manifest_path = Path(__file__).with_name("langtool-expansion.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest["source_sha256"] != SUPPORTED_SHA256:
            raise ValueError("Unrecognized patch manifest")
        if args.input.resolve() == args.output.resolve():
            raise ValueError("Input and output must be different files")
        if args.output.exists():
            raise ValueError("Output already exists; refusing to overwrite it")
        image = build_image(args.input.read_bytes(), manifest)
        write_output(args.output, image)
    except (OSError, ValueError, KeyError, struct.error) as error:
        parser.exit(1, f"Error: {error}\n")
    print(f"Created {args.output}")
    print(f"SHA-256: {hashlib.sha256(image).hexdigest()}")


if __name__ == "__main__":
    main()
