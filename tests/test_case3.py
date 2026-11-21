"""Tests for FAT32 case 3 recovery."""

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bai_lam import BaiLam
from binio import AnhDia
from recovery.case3 import jpeg_fail_pos, recover_case3, validate_jpeg
from tienich import ThuMucKetQua


class QuietLog:
    def buoc(self, *args, **kwargs):
        pass

    quyet_dinh = buoc
    canh_bao = buoc


def make_progressive_jpeg(size=2100):
    dqt = b"\xff\xdb" + (67).to_bytes(2, "big") + bytes([0]) + bytes(range(64))
    sof = b"\xff\xc2" + (11).to_bytes(2, "big") + bytes([
        8, 0, 1, 0, 1, 1, 1, 0x11, 0
    ])
    sos = b"\xff\xda" + (8).to_bytes(2, "big") + bytes([1, 1, 0, 0, 0x3f, 0])
    header = b"\xff\xd8" + dqt + sof + sos
    if size < len(header) + 2:
        raise ValueError("JPEG size too small")
    return header + (b"\x11" * (size - len(header) - 2)) + b"\xff\xd9"


def build_case3_image(path, jpeg):
    bps = 512
    spc = 2
    reserved = 32
    fat_count = 2
    fat_sectors = 20
    root = 2
    clusters = 40
    cluster_size = bps * spc
    data_offset = (reserved + fat_count * fat_sectors) * bps
    total = reserved + fat_count * fat_sectors + clusters * spc

    boot = bytearray(bps)
    boot[:3] = b"\xeb\x58\x90"
    struct.pack_into("<H", boot, 11, bps)
    boot[13] = spc
    struct.pack_into("<H", boot, 14, reserved)
    boot[16] = fat_count
    boot[21] = 0xF8
    struct.pack_into("<I", boot, 32, total)
    struct.pack_into("<I", boot, 36, fat_sectors)
    struct.pack_into("<I", boot, 44, root)
    boot[510:] = b"\x55\xaa"

    fat = bytearray(fat_sectors * bps)
    struct.pack_into("<I", fat, 0, 0x0FFFFFF8)
    struct.pack_into("<I", fat, 4, 0x0FFFFFFF)
    struct.pack_into("<I", fat, root * 4, 0x0FFFFFFF)
    # FAT for fragment 1 and fragment 2 is erased (cluster 0/free).
    struct.pack_into("<I", fat, 3 * 4, 0)
    struct.pack_into("<I", fat, 6 * 4, 0)
    struct.pack_into("<I", fat, 7 * 4, 0)

    directory = bytearray(cluster_size)
    entry = bytearray(32)
    entry[:11] = b"FRAGMENTJPG"
    entry[11] = 0x20
    struct.pack_into("<H", entry, 20, 0)
    struct.pack_into("<H", entry, 26, 3)
    struct.pack_into("<I", entry, 28, len(jpeg))
    directory[:32] = entry

    with open(path, "wb") as stream:
        stream.truncate(total * bps)
        stream.seek(0)
        stream.write(boot)
        stream.seek(reserved * bps)
        stream.write(fat)
        stream.seek((reserved + fat_sectors) * bps)
        stream.write(fat)
        stream.seek(data_offset + (root - 2) * cluster_size)
        stream.write(directory)
        stream.seek(data_offset + (3 - 2) * cluster_size)
        stream.write(jpeg[:cluster_size])
        stream.seek(data_offset + (4 - 2) * cluster_size)
        stream.write(b"\xff\x10" + b"\0" * (cluster_size - 2))
        stream.seek(data_offset + (6 - 2) * cluster_size)
        stream.write(jpeg[cluster_size:2 * cluster_size])
        stream.seek(data_offset + (7 - 2) * cluster_size)
        stream.write(jpeg[2 * cluster_size:])


class Case3Tests(unittest.TestCase):
    def test_validates_progressive_jpeg_shape(self):
        jpeg = make_progressive_jpeg()
        self.assertIsNone(jpeg_fail_pos(jpeg))
        self.assertEqual(validate_jpeg(jpeg), "structure")

    def test_recovers_split_jpeg_fragments(self):
        jpeg = make_progressive_jpeg(2100)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case3.img"
            build_case3_image(path, jpeg)
            out = ThuMucKetQua(str(Path(tmp) / "out"))

            with AnhDia(str(path)) as img:
                recover_case3(img, out, QuietLog())

            result = Path(out.goc) / "FRAGMENT.JPG"
            self.assertEqual(result.read_bytes(), jpeg)

    def test_bailam_dispatches_case3(self):
        with patch("recovery.case3.recover_case3", return_value="result") as run:
            log = QuietLog()
            self.assertEqual(BaiLam(log).case3("img", "out"), "result")
            run.assert_called_once_with("img", "out", log)


if __name__ == "__main__":
    unittest.main()