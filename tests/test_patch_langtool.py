import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "patch_langtool", Path(__file__).resolve().parents[1] / "tools/patch_langtool.py"
)
patcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(patcher)


def fixture():
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", image, 0x84, 0x14C, 1)
    struct.pack_into("<H", image, 0x94, 0xE0)
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<I", image, optional + 72, 0x100000)
    image[0x210:0x212] = b"\x55\x8b"
    manifest = {
        "source_size": len(image),
        "source_sha256": hashlib.sha256(image).hexdigest(),
        "data_rva": 0x2000,
        "data_size": 0x2000,
        "code_rva": 0x4000,
        "code": "c3",
        "patches": [{"offset": 0x210, "before": "558b", "after": "9090"}],
    }
    return bytes(image), manifest


class PatchTests(unittest.TestCase):
    def test_sections_patch_and_checksum(self):
        source, manifest = fixture()
        image = patcher.build_image(source, manifest)
        self.assertEqual(source[0x210:0x212], b"\x55\x8b")
        self.assertEqual(image[0x210:0x212], b"\x90\x90")
        self.assertEqual(struct.unpack_from("<H", image, 0x86)[0], 3)
        self.assertEqual(struct.unpack_from("<I", image, 0x98 + 56)[0], 0x5000)
        self.assertEqual(struct.unpack_from("<I", image, 0x98 + 72)[0], 0x800000)
        table = 0x98 + 0xE0
        data = struct.unpack_from("<8sIIIIIIHHI", image, table + 40)
        code = struct.unpack_from("<8sIIIIIIHHI", image, table + 80)
        self.assertEqual(data[:5], (b".lgdata\0", 0x2000, 0x2000, 0, 0))
        self.assertEqual(data[-1], 0xC0000080)
        self.assertEqual(code[-1], 0x60000020)
        self.assertEqual(image[code[4]], 0xC3)
        self.assertEqual(struct.unpack_from("<I", image, 0x98 + 64)[0],
                         patcher.checksum(image, 0x98 + 64))

    def test_hash_guard(self):
        source, manifest = fixture()
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            patcher.build_image(source[:-1] + b"\x01", manifest)

    def test_original_byte_guard(self):
        source, manifest = fixture()
        manifest["patches"][0]["before"] = "0000"
        with self.assertRaisesRegex(ValueError, "Original-byte"):
            patcher.build_image(source, manifest)

    def test_overlapping_patches_rejected(self):
        source, manifest = fixture()
        manifest["patches"] *= 2
        with self.assertRaisesRegex(ValueError, "overlapping"):
            patcher.build_image(source, manifest)

    def test_sections_cannot_overlap(self):
        source, manifest = fixture()
        manifest["code_rva"] = 0x3000
        with self.assertRaisesRegex(ValueError, "section"):
            patcher.build_image(source, manifest)

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "langtool.exe"
            output.write_bytes(b"original")
            with self.assertRaises(FileExistsError):
                patcher.write_output(output, b"replacement")
            self.assertEqual(output.read_bytes(), b"original")


if __name__ == "__main__":
    unittest.main()
