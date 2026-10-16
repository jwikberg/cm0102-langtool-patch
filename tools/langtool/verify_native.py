"""Execute original or patched reader/writer machine code with CRT I/O hooks."""

import io
import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP,
    UC_X86_REG_EBX, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
    UC_X86_REG_ECX,
)

ROOT = Path(__file__).parent


class Machine:
    def __init__(self, data, manifest):
        assert len(data) == manifest["source_size"]
        assert hashlib.sha256(data).hexdigest() == manifest["source_sha256"]
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(0x400000, 0x500000)
        pe = pefile.PE(data=data)
        self.uc.mem_write(0x400000, data[:pe.OPTIONAL_HEADER.SizeOfHeaders])
        for section in pe.sections:
            self.uc.mem_write(0x400000 + section.VirtualAddress, section.get_data())
        for patch in manifest["patches"]:
            before = bytes.fromhex(patch["before"])
            assert data[patch["offset"]:patch["offset"] + len(before)] == before
            address = 0x400000 + pe.get_rva_from_offset(patch["offset"])
            self.uc.mem_write(address, bytes.fromhex(patch["after"]))
        self.uc.mem_write(0x400000 + manifest["code_rva"], bytes.fromhex(manifest["code"]))
        self.uc.mem_map(0x10000000, 0x1000000)
        self.uc.mem_map(0x20000000, 0x200000)
        self.heap = 0x10000000
        self.file = None
        self.files = {}
        self.input_files = {}
        self.output_files = {}
        self.allocations = []
        self.errors = []
        self.translation_capacity = manifest["translation_capacity"]
        self.uc.hook_add(UC_HOOK_CODE, self.hook)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self.invalid)

    def invalid(self, uc, access, address, size, value, user):
        raise AssertionError(
            f"Invalid memory {address:x}, size {size}, instruction {uc.reg_read(UC_X86_REG_EIP):x}"
        )

    def alloc(self, size):
        address = self.heap
        self.heap += (size + 31) & -16
        assert self.heap < 0x11000000
        self.uc.mem_write(address, b"\0" * size + b"\xa5" * 16)
        self.allocations.append((address, size))
        return address

    def words(self, address, count):
        return struct.unpack(f"<{count}I", self.uc.mem_read(address, count * 4))

    def string(self, address):
        result = bytearray()
        while True:
            block = bytes(self.uc.mem_read(address + len(result), 1))
            if block == b"\0":
                return bytes(result)
            result += block
            assert len(result) < 65536

    def hook(self, uc, address, size, user):
        hooks = {
            0x442D76: self.fread,
            0x442E5E: self.fwrite,
            0x4430C0: self.fseek,
            0x442F68: self.ftell,
            0x441D7E: self.new,
            0x441D73: lambda args: 0,
            0x441D8C: self.sprintf,
            0x4427B5: self.fopen,
            0x4426CE: lambda args: 0,
            0x44327F: self.fgetc,
            0x443499: self.fscanf,
            0x443465: self.sscanf,
            0x4029B0: self.error,
            0x410DB0: self.error,
        }
        if address not in hooks:
            return
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret, *args = self.words(esp, 7)
        result = hooks[address](args)
        uc.reg_write(UC_X86_REG_EAX, result & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_ESP, esp + 4)
        uc.reg_write(UC_X86_REG_EIP, ret)

    def error(self, args):
        self.errors.append(args)
        raise AssertionError(f"Native error callback: {[hex(x) for x in args]}")

    def fread(self, args):
        address, size, count, handle = args[:4]
        data = self.files.get(handle, self.file).read(size * count)
        self.uc.mem_write(address, data)
        return len(data) // size

    def fwrite(self, args):
        address, size, count, handle = args[:4]
        return self.files.get(handle, self.file).write(
            bytes(self.uc.mem_read(address, size * count))
        ) // size

    def fseek(self, args):
        handle, offset, origin = args[:3]
        offset = struct.unpack("<i", struct.pack("<I", offset))[0]
        self.files.get(handle, self.file).seek(offset, origin)
        return 0

    def ftell(self, args):
        return self.files.get(args[0], self.file).tell()

    def fopen(self, args):
        name, mode = self.string(args[0]), self.string(args[1])
        handle = self.alloc(32)
        if mode.startswith(b"r"):
            stream = io.BytesIO(self.input_files[name].replace(b"\r\n", b"\n"))
        else:
            assert mode.startswith(b"w"), mode
            stream = io.BytesIO()
            self.output_files[name] = stream
        self.files[handle] = stream
        return handle

    def fgetc(self, args):
        handle = args[0]
        value = self.files[handle].read(1)
        if not value:
            self.uc.mem_write(handle + 12, struct.pack("<I", 0x10))
            return 0xFFFFFFFF
        return value[0]

    def fscanf(self, args):
        handle, fmt, target = args[:3]
        assert self.string(fmt) == b"%s", self.string(fmt)
        stream = self.files[handle]
        result = bytearray()
        value = stream.read(1)
        while value and value in b" \t\r\n\v\f":
            value = stream.read(1)
        while value and value not in b" \t\r\n\v\f":
            result += value
            value = stream.read(1)
        if value:
            stream.seek(-1, io.SEEK_CUR)
        else:
            self.uc.mem_write(handle + 12, struct.pack("<I", 0x10))
        if not result:
            return 0xFFFFFFFF
        self.uc.mem_write(target, bytes(result) + b"\0")
        return 1

    def sscanf(self, args):
        text, fmt, target = args[:3]
        assert self.string(fmt) == b"%d", self.string(fmt)
        value = int(self.string(text))
        self.uc.mem_write(target, struct.pack("<i", value))
        return 1

    def new(self, args):
        return self.alloc(args[0])

    def sprintf(self, args):
        target, fmt, value = args[:3]
        format_string = self.string(fmt)
        assert format_string == b"extract_arguments() : Duplicate argument comment (%s)", format_string
        data = format_string.replace(b"%s", self.string(value))
        self.uc.mem_write(target, data + b"\0")
        return len(data)

    def call(self, address, *args, this=None, cleanup=0):
        stack = 0x201FF000
        stop = 0x7FF0A5
        self.uc.mem_write(stack, struct.pack(f"<{len(args) + 1}I", stop, *args))
        registers = (UC_X86_REG_EBX, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI)
        for index, register in enumerate(registers):
            self.uc.reg_write(register, 0x12345678 + index * 0x11111111)
        self.uc.reg_write(UC_X86_REG_ESP, stack)
        if this is not None:
            self.uc.reg_write(UC_X86_REG_ECX, this)
        self.uc.emu_start(address, stop, count=20000000)
        assert self.uc.reg_read(UC_X86_REG_EIP) == stop
        assert self.uc.reg_read(UC_X86_REG_ESP) == stack + 4 + cleanup
        for index, register in enumerate(registers):
            assert self.uc.reg_read(register) == 0x12345678 + index * 0x11111111
        return self.uc.reg_read(UC_X86_REG_EAX)

    def read(self, data, index):
        self.file = io.BytesIO(data)
        count = struct.unpack_from("<I", data, 4)[0]
        languages = struct.unpack_from("<I", data, 8)[0]
        session = self.alloc(20)
        self.uc.mem_write(session, struct.pack("<5I", count, languages, 0, 1, 0))
        record = self.alloc(2052)
        translations = self.alloc((languages - 1) * self.translation_capacity)
        self.uc.mem_write(record + 2048, struct.pack("<I", translations))
        assert self.call(0x415B70, session, record, index) == 1
        assert self.uc.mem_read(record + 2052, 16) == b"\xa5" * 16
        assert self.uc.mem_read(translations + (languages - 1) * self.translation_capacity, 16) == b"\xa5" * 16
        return session, record, translations


def field(value):
    assert len(value) <= 2047
    return value + b"\0" * (2048 - len(value))


def database(source, translated, count=2):
    languages = len(translated) + 1
    identifiers = [0, 2, 3, 4, 5, 6, 7, 8, 9, 10] if languages == 10 else list(range(languages))
    record = field(source) + b"\0" * 30
    record += b"".join(field(text) + struct.pack("<10i", *([-1] * 10)) for text in translated)
    return struct.pack(f"<{3 + languages}I", 1, count, languages, *identifiers) + record * count


def verify_import(original, manifest):
    machine = Machine(original, manifest)
    names = [b"ENG_UK", b"FRA", b"DEU", b"ITA", b"ESP",
             b"DAN", b"NED", b"NOR", b"POR", b"SVE"]
    source = b"<%s - " + b"A" * 2038 + b"> X"
    plain = [b"E" * 2047] + [bytes([65 + n]) * 2047 for n in range(9)]
    annotated = [source] + [source[:-2] + b"B" * 2046] * 9
    lines = [b"#", b"10", *names, b"#"]
    for row in (plain, annotated):
        lines.extend(name + b": " + text for name, text in zip(names, row))
        lines.append(b"#")
    machine.input_files[b"boundary.txt"] = b"\n".join(lines) + b"\n"
    source_name, output_name = machine.alloc(32), machine.alloc(32)
    machine.uc.mem_write(source_name, b"boundary.txt\0")
    machine.uc.mem_write(output_name, b"boundary.ldb\0")
    assert machine.call(0x414440, source_name, output_name, 0) == 1
    data = machine.output_files[b"boundary.ldb"].getvalue()
    assert struct.unpack_from("<13I", data) == (1, 2, 10, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10)
    assert len(data) == 52 + 2 * 20870
    for index in range(2):
        row = data[52 + index * 20870:52 + (index + 1) * 20870]
        key = row[:2048].split(b"\0")[0]
        assert key in (plain[0], source)
        for column in range(9):
            offset = 2078 + column * 2088
            text = row[offset:offset + 2048].split(b"\0")[0]
            indices = struct.unpack_from("<10i", row, offset + 2048)
            if key == plain[0]:
                assert text == plain[column + 1]
                assert indices == (-1,) * 10
            else:
                assert text == b"\x08" + b"B" * 2046
                assert indices == (0,) + (-1,) * 9
    for address, size in machine.allocations:
        assert machine.uc.mem_read(address + size, 16) == b"\xa5" * 16
    for bad_column in (0, 1):
        invalid = Machine(original, manifest)
        row = list(plain)
        row[bad_column] = b"X" * 2048
        lines = [b"#", b"10", *names, b"#"]
        lines.extend(name + b": " + text for name, text in zip(names, row))
        lines.append(b"#")
        invalid.input_files[b"invalid.txt"] = b"\n".join(lines) + b"\n"
        source_name, output_name = invalid.alloc(32), invalid.alloc(32)
        invalid.uc.mem_write(source_name, b"invalid.txt\0")
        invalid.uc.mem_write(output_name, b"invalid.ldb\0")
        try:
            invalid.call(0x414440, source_name, output_name, 0)
        except AssertionError as error:
            assert "Native error callback:" in str(error)
            assert not invalid.output_files
        else:
            raise AssertionError("Oversized ASCII import accepted")
    print("Native importer: complete 2047-byte fields and 4091-byte annotated input, guarded allocations")


def verify_display(original, manifest):
    machine = Machine(original, manifest)
    source, encoded, decoded = machine.alloc(32768), machine.alloc(65536), machine.alloc(32768)
    machine.uc.mem_write(source, b"\n" * 32767 + b"\0")
    machine.call(0x4312F0, encoded, source)
    assert machine.string(encoded) == b"\\n" * 32767
    machine.call(0x431350, decoded, encoded)
    assert machine.string(decoded) == b"\n" * 32767
    for value, expected in ((b"a\\z", b"a\\z"), (b"a\\", b"a\\"),
                            (b"a\\\\n", b"a\\\n"), (b'a\\"', b'a\\"')):
        machine.uc.mem_write(encoded, value + b"\0")
        machine.call(0x431350, decoded, encoded)
        assert machine.string(decoded) == expected
    for address, size in machine.allocations:
        assert machine.uc.mem_read(address + size, 16) == b"\xa5" * 16
    machine.uc.mem_write(encoded, b"x" * 65535 + b"\0")
    before = bytes(machine.uc.mem_read(decoded, 32768))
    try:
        machine.call(0x431350, decoded, encoded)
    except AssertionError as error:
        assert "Native error callback:" in str(error)
        assert bytes(machine.uc.mem_read(decoded, 32768)) == before
        assert machine.words(manifest["guard_state"], 1) == (1,)
    else:
        raise AssertionError("Display decode overflow accepted")
    print("Native display helpers: 32767/65534-byte newline round trip; 65535-byte overflow refused")


class EditorMachine(Machine):
    def hook(self, uc, address, size, user):
        if address not in (0x40F5A0, 0x4116E0, 0x40C920, 0x40DBD0):
            return super().hook(uc, address, size, user)
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret, *args = self.words(esp, 5)
        result = 0
        if address == 0x40F5A0:
            result = len(self.string(args[1])) * 8
        if address == 0x4116E0:
            widget = uc.reg_read(UC_X86_REG_ECX)
            caption = self.string(widget + 0x80)
            cursor = self.words(widget + 0x44, 1)[0]
            assert len(caption) <= 255
            assert cursor == 0xFFFFFFFF or cursor <= len(caption)
        uc.reg_write(UC_X86_REG_EAX, result)
        uc.reg_write(UC_X86_REG_ESP, esp + (8 if address == 0x4116E0 else 4))
        uc.reg_write(UC_X86_REG_EIP, ret)


def verify_editor(original, manifest):
    machine = EditorMachine(original, manifest)
    root = machine.alloc(0x12FC24)
    widget = root + 0xBB034
    source = machine.alloc(65536)
    machine.uc.mem_write(source, b"A" * 2047 + b"\0")
    arguments = (
        root, widget, 0, 8, 0, 0, 640, 20, 0, 1, 0,
        0, 0, 0, 0, 0, source, 65535, 0, 0, 0xFFFFFFFF,
    )
    machine.call(0x411300, *arguments, this=widget, cleanup=84)
    full = manifest["ui_data_base"] + 65536
    assert machine.words(widget + 0x54, 1) == (full,)
    assert machine.string(full) == b"A" * 2047
    assert machine.string(widget + 0x80) == b"A" * 255
    machine.uc.mem_write(widget + 0x44, struct.pack("<I", 0))

    def key(value, character=0):
        machine.uc.mem_write(0x4BFA60, struct.pack("<I", value))
        machine.uc.mem_write(0x4BFA7C, struct.pack("<I", character))
        machine.call(0x4050C0, 0, this=root, cleanup=4)

    key(0x23)
    key(8)
    key(ord("Z"), ord("Z"))
    assert machine.string(full) == b"A" * 2046 + b"Z"
    key(ord("X"), ord("X"))
    assert machine.string(full) == b"A" * 2046 + b"ZX"
    key(0x24)
    key(0x2E)
    assert machine.string(full) == b"A" * 2045 + b"ZX"
    key(13)
    assert machine.words(widget + 0x44, 1) == (0xFFFFFFFF,)
    machine.uc.mem_write(0x4BFAC4, struct.pack("<I", root))
    machine.uc.mem_write(source, b"\\n" * 2047 + b"\0")
    machine.call(0x411EA0, source, 0, this=widget, cleanup=8)
    assert machine.string(full) == b"\\n" * 2047
    assert machine.string(widget + 0x80) == (b"\\n" * 128)[:255]
    ids = machine.alloc(44)
    machine.uc.mem_write(ids, struct.pack("<11I", *range(11)))
    for row in range(11):
        machine.uc.reg_write(UC_X86_REG_EBP, row)
        machine.uc.reg_write(UC_X86_REG_ECX, ids)
        machine.uc.reg_write(UC_X86_REG_EDI, 0)
        machine.uc.emu_start(0x42EB7F, 0x42EBA4, count=1000)
        assert machine.uc.reg_read(UC_X86_REG_EBX) == row * 65536
        assert machine.uc.reg_read(UC_X86_REG_EDI) == machine.words(0x45112C + row * 4, 1)[0]
    machine.uc.mem_write(full, b"X" * 65535 + b"\0")
    machine.uc.mem_write(widget + 0x44, struct.pack("<I", 0))
    key(0x23)
    try:
        key(ord("Y"), ord("Y"))
    except AssertionError as error:
        assert "Native error callback:" in str(error)
        assert machine.string(full) == b"X" * 65535
        assert machine.words(0x4BFA60, 1) == (0,)
        assert machine.words(0x4BFA7C, 1) == (0,)
    else:
        raise AssertionError("Display-capacity overflow accepted by native keyboard hook")
    for address, size in machine.allocations:
        assert machine.uc.mem_read(address + size, 16) == b"\xa5" * 16
    print("Native editor: persistent text, bounded captions, edit/setter ABI and all 11 language-row offsets")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Original langtool.exe")
    parser.add_argument("manifest", type=Path, help="Generated patch manifest")
    parser.add_argument("--database", type=Path, help="Optional installed language.ldb")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    original = args.input.read_bytes()
    verify_import(original, manifest)
    verify_display(original, manifest)
    verify_editor(original, manifest)
    machine = Machine(original, manifest)
    source = b"E" * 2047
    translated = [bytes([ord("A") + index]) * 2047 for index in range(9)]
    data = database(source, translated)
    for index in (0, 1):
        session, record, text = machine.read(data, index)
        assert machine.string(record) == source
        for column in range(9):
            assert machine.string(text + column * machine.translation_capacity) == translated[column]
        assert machine.call(0x415DD0, session, record) == 1
        saved = machine.file.getvalue()
        assert len(saved) == len(data)
        start = 52 + index * 20870
        assert saved[:start] == data[:start]
        assert saved[start:start + 2048] == data[start:start + 2048]
        assert saved[start + 2048] == 0
        assert saved[start + 2078:] == data[start + 2078:]
        print(f"Native reader/writer: record {index}, source and all translations 2047 bytes, semantic round trip")
    data = database(b"E" * 2047, [b"T" * 2047] * 10)
    session, record, text = machine.read(data, 1)
    assert machine.call(0x415DD0, session, record) == 1
    assert machine.file.getvalue() == data
    print("Native reader/writer: original 11-language support retained")
    source = b"<%s - " + b"A" * 2038 + b"> X"
    compact = b"\x08" + b"B" * 2046
    row = field(source) + b"%s~" + b"\0" * 27
    row += (field(compact) + struct.pack("<10i", 0, *([-1] * 9))) * 9
    data = struct.pack("<13I", 1, 2, 10, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10) + row * 2
    session, record, text = machine.read(data, 1)
    expected = source[:-2] + b"B" * 2046
    for column in range(9):
        assert machine.string(text + column * machine.translation_capacity) == expected
    assert len(expected) > 2047
    assert machine.call(0x415DD0, session, record) == 1
    saved = machine.file.getvalue()
    assert saved[:52 + 20870] == data[:52 + 20870]
    assert saved[52 + 20870:52 + 20870 + 2048] == field(source)
    for column in range(9):
        begin = 52 + 20870 + 2078 + column * 2088
        assert saved[begin:begin + 2048].split(b"\0")[0] == compact
        assert saved[begin + 2048:begin + 2088] == struct.pack("<10i", 0, *([-1] * 9))
    print("Native reader/writer: 2047-byte disk fields with 4091-byte annotated translations")
    source = b"prefix <%s - name> and <%d - count>"
    compact = b"count \x08 and name \x08"
    row = field(source) + b"%s~%d~" + b"\0" * 24
    mapping = struct.pack("<10i", 1, 0, *([-1] * 8))
    row += (field(compact) + mapping) * 9
    data = struct.pack("<13I", 1, 2, 10, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10) + row * 2
    session, record, text = machine.read(data, 0)
    for column in range(9):
        assert machine.string(text + column * machine.translation_capacity) == (
            b"count <%d - count> and name <%s - name>"
        )
    assert machine.call(0x415DD0, session, record) == 1
    assert machine.file.getvalue()[52 + 2078:52 + 20870] == row[2078:]
    print("Native reader/writer: reordered argument indices preserved in all translations")
    for bad_value in (b"x" * 2048, b"unknown <%s - missing>"):
        data = database(b"source", [b"valid"] * 9)
        session, record, text = machine.read(data, 0)
        machine.uc.mem_write(text, bad_value + b"\0")
        before = machine.file.getvalue()
        try:
            machine.call(0x415DD0, session, record)
        except AssertionError as error:
            assert "Native error callback:" in str(error)
            assert machine.file.getvalue() == before
        else:
            raise AssertionError("Invalid translation accepted")
    print("Native writer: oversized/unknown-argument edits rejected before any database write")
    if not args.database:
        return
    data = args.database.read_bytes()
    for index in (0, 100, 4903, 9806):
        session, record, text = machine.read(data, index)
        expected = data[52 + index * 20870:52 + index * 20870 + 2048].split(b"\0")[0]
        assert machine.string(record) == expected
        assert machine.call(0x415DD0, session, record) == 1
        saved = machine.file.getvalue()
        begin, end = 52 + index * 20870, 52 + (index + 1) * 20870
        assert saved[:begin] == data[:begin]
        assert saved[end:] == data[end:]
        before = data[begin:end]
        after = saved[begin:end]
        assert before[:2048].split(b"\0")[0] == after[:2048].split(b"\0")[0]
        assert before[2048:2078].split(b"\0")[0] == after[2048:2078].split(b"\0")[0]
        for column in range(9):
            offset = 2078 + column * 2088
            assert before[offset:offset + 2048].split(b"\0")[0] == after[offset:offset + 2048].split(b"\0")[0]
            assert before[offset + 2048:offset + 2088] == after[offset + 2048:offset + 2088]
        print(f"Native reader/writer: installed record {index}, semantic round trip and untouched neighbours")


if __name__ == "__main__":
    main()
