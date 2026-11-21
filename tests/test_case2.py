"""Tests for FAT32 case 2 recovery."""

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bai_lam import BaiLam
from binio import AnhDia
from recovery.case2 import _plausible_content, recover_case2
from tienich import ThuMucKetQua


class QuietLog:
    def buoc(self, *args, **kwargs):
        pass

    quyet_dinh = buoc
    canh_bao = buoc


def build_case2_image(path, payload=b"Recovered text\r\nfor case 2.\r\n" * 60, name=b"RECOVER TXT"):
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
    struct.pack_into("<I", fat, 5 * 4, 6)
    struct.pack_into("<I", fat, 6 * 4, 0x0FFFFFFF)

    directory = bytearray(cluster_size)
    entry = bytearray(32)
    entry[:11] = name
    entry[11] = 0x20
    struct.pack_into("<H", entry, 20, 0)
    struct.pack_into("<H", entry, 26, 0)  # damaged FirstCluster
    struct.pack_into("<I", entry, 28, len(payload))
    directory[:32] = entry
    directory[32:64] = b"\0" * 32

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
        stream.seek(data_offset + (5 - 2) * cluster_size)
        stream.write(payload[:cluster_size])
        stream.seek(data_offset + (6 - 2) * cluster_size)
        stream.write(payload[cluster_size:])


class Case2Tests(unittest.TestCase):
    def test_plausible_content_accepts_printable_text(self):
        self.assertTrue(_plausible_content("TXT", b"hello\r\nworld\n"))
        self.assertFalse(_plausible_content("TXT", b"\x00\x01\x02\x03"))

    def test_recovers_file_with_damaged_first_cluster(self):
        payload = b"Recovered text\r\nfor case 2.\r\n" * 60
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case2.img"
            build_case2_image(path, payload)
            out = ThuMucKetQua(str(Path(tmp) / "out"))

            with AnhDia(str(path)) as img:
                recover_case2(img, out, QuietLog())

            result = Path(out.goc) / "RECOVER.TXT"
            self.assertEqual(result.read_bytes(), payload)

    def test_bailam_dispatches_case2(self):
        with patch("recovery.case2.recover_case2", return_value="result") as run:
            log = QuietLog()
            self.assertEqual(BaiLam(log).case2("img", "out"), "result")
            run.assert_called_once_with("img", "out", log)


if __name__ == "__main__":
    unittest.main()