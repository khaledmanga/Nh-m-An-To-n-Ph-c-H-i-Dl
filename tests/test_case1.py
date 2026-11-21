"""Case-1 tests with generated layouts, names and chains different from the public sample."""

import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from bai_lam import BaiLam
from binio import AnhDia
from recovery.case1 import (Fat32Reader, FileEntry,
                            infer_geometry, recover_case1)
from tienich import ThuMucKetQua


ROOT = Path(__file__).resolve().parents[1]


class QuietLog:
    def __init__(self):
        self.records = []

    def buoc(self, message, **values):
        self.records.append((message, values))

    quyet_dinh = buoc
    canh_bao = buoc


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def build_image(path, spc=2, reserved=47, root=5, long_name=False, clusters=66000):
    # Sparse image: enough clusters for FAT32 without using all that disk space.
    bps = 512
    fat_sectors = (clusters + 2 + 127) // 128 + 3  # add padding, not the sample FAT size
    total = reserved + 2 * fat_sectors + clusters * spc
    data_offset = (reserved + 2 * fat_sectors) * bps
    cluster_size = spc * bps
    payload = bytes((i * 7) % 256 for i in range(cluster_size + 73))
    boot = bytearray(512)
    boot[:3] = b'\xeb\x58\x90'
    struct.pack_into('<H', boot, 11, bps)
    boot[13] = 64  # damage all 3 fields in main + backup
    struct.pack_into('<H', boot, 14, 12)
    boot[16] = 2
    boot[21] = 0xF8
    struct.pack_into('<I', boot, 32, total)
    struct.pack_into('<I', boot, 36, fat_sectors + 11)
    struct.pack_into('<I', boot, 44, root)
    struct.pack_into('<H', boot, 50, 6)
    boot[510:] = b'\x55\xaa'
    fat = bytearray(fat_sectors * bps)
    # Set the top 4 bits too; the 2 file clusters are not adjacent.
    for index, value in [(0, 0xFFFFFFF8), (1, 0xFFFFFFFF), (root, 0xFFFFFFFF),
                         (9, 0xFFFFFFFF), (13, 0xA0000015), (21, 0xFFFFFFF8)]:
        struct.pack_into('<I', fat, index * 4, value)

    def entry(name, first, size, directory=False):
        result = bytearray(32)
        result[:11] = name
        result[11] = 0x10 if directory else 0x20
        struct.pack_into('<H', result, 20, first >> 16)
        struct.pack_into('<H', result, 26, first & 0xFFFF)
        struct.pack_into('<I', result, 28, size)
        return result

    file_entry = entry(b'ALTERED BIN', 13, len(payload))
    file_name = 'ALTERED.BIN'
    lfn = b''
    if long_name:
        file_name = 'new name.bin'
        checksum = 0
        for byte in file_entry[:11]:
            checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 255
        text = (file_name + '\0').encode('utf-16le').ljust(26, b'\xff')
        lfn = bytearray(32)
        lfn[0], lfn[11], lfn[13] = 0x41, 0x0F, checksum
        lfn[1:11], lfn[14:26], lfn[28:32] = text[:10], text[10:22], text[22:]
    with open(path, 'wb') as stream:
        stream.truncate(total * bps)
        for offset, data in [(0, boot), (6 * bps, boot), (reserved * bps, fat),
                             ((reserved + fat_sectors) * bps, fat),
                             (data_offset + (root - 2) * cluster_size,
                              entry(b'OTHER      ', 9, 0, True)),
                             (data_offset + 7 * cluster_size, lfn + file_entry),
                             (data_offset + 11 * cluster_size, payload[:cluster_size]),
                             (data_offset + 19 * cluster_size, payload[cluster_size:])]:
            stream.seek(offset)
            stream.write(data)
    return (spc, reserved, fat_sectors), {'OTHER/' + file_name: payload}


class Case1Tests(unittest.TestCase):
    def test_changed_layout_names_fragmentation_and_input_unchanged(self):
        for spc, reserved, root in [(1, 47, 5), (2, 71, 7), (4, 103, 11)]:
            with self.subTest(spc=spc), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'changed.img'
                expected, files = build_image(path, spc, reserved, root)
                before = sha256(path)
                log = QuietLog()
                out = ThuMucKetQua(str(Path(tmp) / 'out'))
                with AnhDia(path) as img:
                    geometry = recover_case1(img, out, log)
                self.assertEqual((geometry.sectors_per_cluster, geometry.reserved_sectors,
                                  geometry.fat_size_sectors), expected)
                for name, data in files.items():
                    self.assertEqual((Path(out.goc) / name).read_bytes(), data)
                self.assertEqual(before, sha256(path))
                saved = [values for message, values in log.records if message == 'Đã lưu file']
                self.assertEqual(saved[0]['sha256'], hashlib.sha256(next(iter(files.values()))).hexdigest())

    def test_directory_evidence_rejects_other_cluster_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'more_candidates.img'
            expected, _ = build_image(path, spc=1, clusters=140000)
            with AnhDia(path) as img:
                geometry = infer_geometry(img, QuietLog())
            self.assertEqual(geometry.sectors_per_cluster, expected[0])

    def test_output_cannot_alias_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'source.img'
            build_image(path)
            out = ThuMucKetQua(str(Path(tmp) / 'out'))
            target = Path(out.goc) / 'OTHER/ALTERED.BIN'
            target.parent.mkdir()
            os.link(path, target)
            before = sha256(path)
            with AnhDia(path) as img:
                with self.assertRaisesRegex(ValueError, 'ghi đè'):
                    recover_case1(img, out, QuietLog())
            self.assertEqual(before, sha256(path))

    def test_long_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'lfn.img'
            _, files = build_image(path, long_name=True)
            out = ThuMucKetQua(str(Path(tmp) / 'out'))
            with AnhDia(path) as img:
                recover_case1(img, out, QuietLog())
            for name, data in files.items():
                self.assertEqual((Path(out.goc) / name).read_bytes(), data)

    def test_loop_free_bad_and_out_of_range_links_fail(self):
        for link in (13, 0, 0x0FFFFFF7, 66002):
            with self.subTest(link=link), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'bad.img'
                expected, _ = build_image(path)
                with open(path, 'r+b') as stream:
                    for fat_start in (expected[1], expected[1] + expected[2]):
                        stream.seek(fat_start * 512 + 13 * 4)
                        stream.write(struct.pack('<I', link))
                with AnhDia(path) as img:
                    with self.assertRaisesRegex(ValueError, 'tìm thấy 0'):
                        infer_geometry(img, QuietLog())

    def test_inconsistent_fat_copies_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'copies.img'
            expected, _ = build_image(path)
            with open(path, 'r+b') as stream:
                stream.seek((expected[1] + expected[2]) * 512 + 13 * 4)
                stream.write(struct.pack('<I', 0xFFFFFFFF))
            with AnhDia(path) as img:
                with self.assertRaisesRegex(ValueError, 'tìm thấy 0'):
                    infer_geometry(img, QuietLog())

    def test_truncated_volume_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'short.img'
            build_image(path)
            with open(path, 'r+b') as stream:
                stream.truncate(4096)
            with AnhDia(path) as img:
                with self.assertRaisesRegex(ValueError, 'thiếu byte'):
                    infer_geometry(img, QuietLog())

    def test_ambiguous_layout_is_not_guessed(self):
        class AcceptAnyReader:
            def __init__(self, img, geometry):
                pass

            def iter_files(self):
                return [FileEntry('dummy', 1, 3, 0)]

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'ambiguous.img'
            build_image(path, spc=1, clusters=140000)
            with AnhDia(path) as img:
                with self.assertRaisesRegex(ValueError, 'tìm thấy 2'):
                    infer_geometry(img, QuietLog(), reader_factory=AcceptAnyReader)

    def test_replacement_reader_is_used_with_inferred_geometry(self):
        used = []

        class SharedReaderAdapter:
            def __init__(self, img, geometry):
                used.append(geometry)
                self.reader = Fat32Reader(img, geometry)

            def iter_files(self):
                return self.reader.iter_files()

            def read_file(self, entry):
                return self.reader.read_file(entry)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'adapter.img'
            expected, files = build_image(path)
            out = ThuMucKetQua(str(Path(tmp) / 'out'))
            with AnhDia(path) as img:
                recover_case1(img, out, QuietLog(), reader_factory=SharedReaderAdapter)
            self.assertGreaterEqual(len(used), 2)
            self.assertEqual(used[-1].reserved_sectors, expected[1])
            for name, data in files.items():
                self.assertEqual((Path(out.goc) / name).read_bytes(), data)

    def test_bailam_dispatches_case1(self):
        with patch('recovery.case1.recover_case1', return_value='result') as run:
            log = QuietLog()
            self.assertEqual(BaiLam(log).case1('img', 'out'), 'result')
            run.assert_called_once_with('img', 'out', log)

    @unittest.skipUnless((ROOT / 'samples/fat32/case1.img').exists(), 'Public samples not installed')
    def test_public_sample_all_hashes_paths_and_no_input_write(self):
        sample = ROOT / 'samples/fat32/case1.img'
        answers = json.loads(sample.with_suffix('.json').read_text())
        before = sha256(sample)
        with tempfile.TemporaryDirectory() as tmp, AnhDia(sample) as img:
            out = ThuMucKetQua(tmp)
            BaiLam(QuietLog()).case1(img, out)
            out.ket_thuc()
            for entry in answers['files']:
                result = Path(tmp) / entry['path']
                self.assertEqual(result.stat().st_size, entry['size'])
                self.assertEqual(sha256(result), entry['sha256'])
            self.assertEqual(len(out.tong), len(answers['files']))
            self.assertTrue((Path(tmp) / 'SHA256SUMS').exists())
        self.assertEqual(before, sha256(sample))


if __name__ == '__main__':
    unittest.main()
