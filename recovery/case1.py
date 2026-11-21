"""FAT32 case 1: infer the 3 damaged boot fields, then extract files.

Run with recover.py --case 1. Image paths come from the CLI.
"""

from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import time


FAT_MASK = 0x0FFFFFFF
EOC = 0x0FFFFFF8

# Keep unusual images from making the search run forever (these are safety limits)
MAX_FAT_HEADERS = 64
MAX_DIRECTORY_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 10000
TIME_LIMIT = 540  # leave time for output (assignment allows 600s/image)


@dataclass(frozen=True)
class BootFields:
    bytes_per_sector: int
    total_sectors: int
    fat_count: int
    root_cluster: int
    media: int
    backup_sector: int
    sectors_per_cluster: int  # these 3 values are observations -> not trusted geometry
    reserved_sectors: int
    fat_size_sectors: int


@dataclass(frozen=True)
class Geometry:
    boot: BootFields
    sectors_per_cluster: int
    reserved_sectors: int
    fat_size_sectors: int

    @property
    def cluster_size(self):
        return self.boot.bytes_per_sector * self.sectors_per_cluster

    @property
    def fat_offset(self):
        return self.reserved_sectors * self.boot.bytes_per_sector

    @property
    def data_offset(self):
        # reserved + all FATs -> first data sect (= cluster 2)
        return (self.reserved_sectors + self.boot.fat_count * self.fat_size_sectors) * self.boot.bytes_per_sector

    @property
    def cluster_count(self):
        data_sectors = self.boot.total_sectors - self.data_offset // self.boot.bytes_per_sector

        return data_sectors // self.sectors_per_cluster

    def cluster_offset(self, cluster):
        if not 2 <= cluster < self.cluster_count + 2:
            raise ValueError(f"Cluster ngoài vùng data: {cluster}")

        return self.data_offset + (cluster - 2) * self.cluster_size


@dataclass(frozen=True)
class FileEntry:
    path: str
    size: int
    first_cluster: int
    offset: int
    clusters: tuple = ()  # cluster list for log evidence


def read_boot(img, log):
    # Volume image only: byte 0 = boot (not a MBR)
    if img.doc(510, 2) != b'\x55\xaa':
        raise ValueError("Không thấy boot signature 55 AA")
    fields = [
        ('bytes_per_sector', 0x0B, 2), ('sectors_per_cluster', 0x0D, 1),
        ('reserved_sectors', 0x0E, 2), ('fat_count', 0x10, 1),
        ('media', 0x15, 1), ('total_sectors', 0x20, 4),
        ('fat_size_sectors', 0x24, 4), ('root_cluster', 0x2C, 4),
        ('backup_sector', 0x32, 2),
    ]
    values = {}

    for name, offset, size in fields:
        values[name] = img.so(offset, size)
        log.buoc('boot: ' + name, offset=offset, gia_tri=values[name])

    boot = BootFields(**values)
    if boot.bytes_per_sector not in (512, 1024, 2048, 4096):
        raise ValueError("BytesPerSector không hợp lệ / nằm ngoài case 1")
    if boot.total_sectors * boot.bytes_per_sector > img.kich_thuoc or not boot.total_sectors:
        raise ValueError("Volume bị thiếu byte hoặc TotalSectors sai")
    if boot.fat_count != 2 or img.u16(0x28) & 0x80:
        raise ValueError("Case 1 này cần 2 FAT mirrored, như ảnh của đề")
    if img.u16(0x11) or img.u16(0x16) or img.u16(0x2A):
        raise ValueError("BPB không phải FAT32 version 0")

    # Backup is damaged too -> log it as evidence (not as answer)
    backup = boot.backup_sector * boot.bytes_per_sector
    if boot.backup_sector not in (0, 0xFFFF) and backup + 512 <= img.kich_thuoc:
        for name, offset, size in fields:
            if name in ('sectors_per_cluster', 'reserved_sectors', 'fat_size_sectors'):
                log.buoc('backup: ' + name, offset=backup + offset,
                         gia_tri=img.so(backup + offset, size))

    return boot


def check_time(deadline):
    if time.monotonic() > deadline:
        raise ValueError("Hết thời gian tìm layout; không chọn đại một candidate")


# ===== FAT32 reader =====
# If the shared fat32/ reader is ready, might pass an adapter as reader_factory
class Fat32Reader:
    """Read directories and files using an explicit FAT32 geometry."""

    def __init__(self, img, geometry):
        self.img = img
        self.geometry = geometry
        self.deadline = time.monotonic() + TIME_LIMIT
        self.used_clusters = set()
        self.files = []

    def chain(self, first_cluster):
        result, seen = [], set()
        cluster = first_cluster

        while True:
            check_time(self.deadline)
            self.geometry.cluster_offset(cluster)  # check range before reading the FAT
            if cluster in seen:
                raise ValueError(f"FAT chain bị loop ở cluster {cluster}")
            seen.add(cluster)
            result.append(cluster)

            # FAT32 uses the low 28 bits -> the top 4 are not part of the cluster number
            next_cluster = self.img.u32(self.geometry.fat_offset + cluster * 4) & FAT_MASK
            if next_cluster >= EOC:
                return result
            if next_cluster < 2 or next_cluster >= 0x0FFFFFF0:
                raise ValueError(f"FAT link rỗng/bad/reserved tại cluster {cluster}")
            cluster = next_cluster

    def claim(self, chain):
        if self.used_clusters.intersection(chain):
            raise ValueError("Hai file/thư mục dùng chung cluster")
        self.used_clusters.update(chain)

    def file_chain(self, entry):
        if entry.size == 0:
            if entry.first_cluster != 0:
                raise ValueError("File rỗng nhưng vẫn có chain: ngoài phạm vi ảnh bài này")

            return []
        chain = self.chain(entry.first_cluster)
        needed = (entry.size + self.geometry.cluster_size - 1) // self.geometry.cluster_size

        # Only boot is damaged in case 1 -> chain length + file size must agree
        if len(chain) != needed:
            raise ValueError(f"Size/chain không khớp: {entry.path}, {len(chain)} != {needed}")

        return chain

    def read_file(self, entry):
        data = bytearray()
        remaining = entry.size

        for cluster in self.file_chain(entry):
            count = min(remaining, self.geometry.cluster_size)
            data.extend(self.img.doc(self.geometry.cluster_offset(cluster), count))
            remaining -= count

        return bytes(data)

    def iter_files(self):
        self.used_clusters.clear()
        self.files = []

        # Use a stack instead of recursion -> claim() catches dir loops
        pending = [('', self.geometry.boot.root_cluster)]
        paths = set()
        entries_seen = 0

        while pending:
            prefix, first = pending.pop()
            chain = self.chain(first)
            self.claim(chain)
            if len(chain) * self.geometry.cluster_size > MAX_DIRECTORY_BYTES:
                raise ValueError("Directory quá lớn so với bộ ảnh bài tập")

            long_entries = []
            finished = False

            for cluster in chain:
                base = self.geometry.cluster_offset(cluster)
                block = self.img.doc(base, self.geometry.cluster_size)

                for pos in range(0, len(block), 32):
                    check_time(self.deadline)
                    raw = block[pos:pos + 32]
                    if raw[0] == 0:
                        finished = True
                        break
                    if raw[0] == 0xE5:  # deleted entry -> skip
                        long_entries.clear()
                        continue
                    if raw[11] == 0x0F:
                        long_entries.append(raw)
                        if len(long_entries) > 20:
                            raise ValueError("LFN dài bất thường")
                        continue

                    entries_seen += 1
                    if entries_seen > MAX_ENTRIES:
                        raise ValueError("Quá nhiều directory entries")
                    if raw[11] & 0xC0:
                        raise ValueError("Directory attribute không hợp lệ")
                    if raw[11] & 0x08:  # volume label (not file)
                        long_entries.clear()
                        continue

                    name = decode_name(raw, long_entries)
                    long_entries.clear()
                    if name in ('.', '..'):
                        continue
                    if not name or any(ord(c) < 32 or c in '/\\:*?"<>|' for c in name):
                        raise ValueError("Tên file không hợp lệ")
                    path = prefix + name
                    if path.casefold() in paths:
                        raise ValueError("Trùng đường dẫn trong directory")
                    paths.add(path.casefold())

                    first_cluster = ((int.from_bytes(raw[20:22], 'little') << 16)
                                     | int.from_bytes(raw[26:28], 'little')) & FAT_MASK
                    size = int.from_bytes(raw[28:32], 'little')
                    if raw[11] & 0x10:
                        if size:
                            raise ValueError("Directory có size khác 0")
                        pending.append((path + '/', first_cluster))
                    else:
                        entry = FileEntry(path, size, first_cluster, base + pos)
                        file_clusters = self.file_chain(entry)
                        self.claim(file_clusters)
                        self.files.append(replace(entry, clusters=tuple(file_clusters)))
                if finished:
                    break

        return list(self.files)


def decode_name(raw, long_entries):
    # read BOTH 8.3 names and LFN entries to preserve the original names
    if long_entries:
        count = len(long_entries)
        checksum = 0

        for byte in raw[:11]:
            checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 0xFF

        for i, part in enumerate(long_entries):
            expected = count - i + (0x40 if i == 0 else 0)
            if part[0] != expected or part[13] != checksum or part[12] or part[26:28] != b'\0\0':
                raise ValueError("LFN sequence/checksum không khớp")
        encoded = b''.join(part[1:11] + part[14:26] + part[28:32]

                           for part in reversed(long_entries))
        units = [encoded[i:i + 2] for i in range(0, len(encoded), 2)]
        if b'\0\0' in units:
            units = units[:units.index(b'\0\0')]
        name = b''.join(units).decode('utf-16le')
        if not name or len(name) > 255 or '\uffff' in name:
            raise ValueError("LFN name không hợp lệ")

        return name
    base = raw[:8].decode('ascii').rstrip(' ')
    extension = raw[8:11].decode('ascii').rstrip(' ')
    if raw[12] & 0x08:
        base = base.lower()
    if raw[12] & 0x10:
        extension = extension.lower()

    return base + ('.' + extension if extension else '')


# ===== Infer layout from image bytes (neither JSON answer nor a clean image) =====
def find_fat_headers(img, boot, deadline):
    hits = []
    end = boot.total_sectors * boot.bytes_per_sector
    offset = boot.bytes_per_sector

    # FAT[0]: low byte = media, remaining bits = 1 (ignore top 4)
    signature = bytes((boot.media, 0xFF, 0xFF))

    while offset + 8 <= end:
        check_time(deadline)
        offset = img.tim(signature, offset, end, buoc=boot.bytes_per_sector)
        if offset < 0:
            break
        if offset + 8 <= end:
            first = img.u32(offset) & FAT_MASK
            second = img.u32(offset + 4) & 0x03FFFFFF  # ignore dirty/status flags
            if first == (0x0FFFFF00 | boot.media) and second == 0x03FFFFFF:
                hits.append(offset)
                if len(hits) > MAX_FAT_HEADERS:
                    raise ValueError("Quá nhiều FAT header candidates, cần xem lại ảnh")
        offset += boot.bytes_per_sector

    return hits


def same_bytes(img, first, second, length, deadline):
    # Compare small chunks -> no need to load the whole image into RAM
    for pos in range(0, length, 1024 * 1024):
        check_time(deadline)
        count = min(1024 * 1024, length - pos)
        if img.doc(first + pos, count) != img.doc(second + pos, count):
            return False

    return True


def infer_geometry(img, log, reader_factory=Fat32Reader):
    boot = read_boot(img, log)
    deadline = time.monotonic() + TIME_LIMIT
    headers = find_fat_headers(img, boot, deadline)
    log.quyet_dinh('Các FAT header candidates', offsets=headers)

    accepted = []

    for i, first in enumerate(headers):
        reserved = first // boot.bytes_per_sector
        if not 1 <= reserved <= 0xFFFF:  # BPB_RsvdSecCnt is only 16 bits
            continue

        for second in headers[i + 1:]:
            fat_bytes = second - first
            if second + fat_bytes > boot.total_sectors * boot.bytes_per_sector:
                continue
            if not same_bytes(img, first, second, fat_bytes, deadline):
                log.quyet_dinh('Loại cặp FAT: nội dung 2 bản không khớp', offsets=[first, second])
                continue
            fat_sectors = fat_bytes // boot.bytes_per_sector
            log.quyet_dinh('Hai FAT giống nhau; khoảng cách = kích thước FAT',
                          offsets=[first, second], fat_size_sectors=fat_sectors,
                          reserved_sectors=reserved)

            for spc in (1, 2, 4, 8, 16, 32, 64, 128):
                check_time(deadline)
                geometry = Geometry(boot, spc, reserved, fat_sectors)
                try:
                    if geometry.cluster_count < 65525:
                        raise ValueError('Số cluster quá ít cho FAT32')
                    if (geometry.cluster_count + 2) * 4 > fat_bytes:
                        raise ValueError('FAT không đủ entry cho vùng data')
                    geometry.cluster_offset(boot.root_cluster)
                    reader = reader_factory(img, geometry)
                    if isinstance(reader, Fat32Reader):
                        reader.deadline = deadline
                    entries = reader.iter_files()
                    if not entries or not any(entry.size for entry in entries):
                        raise ValueError('Không tìm được file có dữ liệu')
                    accepted.append(geometry)
                    log.quyet_dinh('Layout qua kiểm tra directory + size/chain + không cross-link',
                                  sectors_per_cluster=spc, files=len(entries))
                except (ValueError, UnicodeError) as error:
                    log.quyet_dinh('Loại layout', sectors_per_cluster=spc, reason=str(error))
    if len(accepted) != 1:
        raise ValueError(f'Cần đúng 1 layout, tìm thấy {len(accepted)}; không đoán khi thiếu bằng chứng')

    geometry = accepted[0]
    log.quyet_dinh('Chọn layout phục hồi', sectors_per_cluster=geometry.sectors_per_cluster,
                  reserved_sectors=geometry.reserved_sectors,
                  fat_size_sectors=geometry.fat_size_sectors,
                  cluster_size=geometry.cluster_size, fat_offset=geometry.fat_offset,
                  data_offset=geometry.data_offset,
                  root_offset=geometry.cluster_offset(boot.root_cluster))

    return geometry


# ===== Case 1 extraction =====
def recover_case1(img, out, log, reader_factory=Fat32Reader):
    geometry = infer_geometry(img, log, reader_factory)
    reader = reader_factory(img, geometry)
    entries = reader.iter_files()

    # Check every output path first -> none can overwrite the input image.
    targets = [Path(out.goc) / entry.path for entry in entries]
    targets.append(Path(out.goc) / 'SHA256SUMS')

    for target in targets:
        source = Path(img.duong_dan)
        if target.resolve() == source.resolve() or (target.exists() and target.samefile(source)):
            raise ValueError('Output không được ghi đè ảnh đầu vào')

    for entry in entries:
        log.buoc('Directory entry: ' + entry.path, offset=entry.offset,
                 gia_tri={'size': entry.size, 'first_cluster': entry.first_cluster})
        log.quyet_dinh('Đọc file bằng layout đã suy ra', path=entry.path,
                      clusters=list(getattr(entry, 'clusters', ())),
                      fat_entry_offset=geometry.fat_offset + entry.first_cluster * 4,
                      first_data_offset=(geometry.cluster_offset(entry.first_cluster)
                                         if entry.size else None))

        data = reader.read_file(entry)
        if len(data) != entry.size:
            raise ValueError('Reader trả thiếu/thừa byte: ' + entry.path)

        out.luu(entry.path, data)
        log.quyet_dinh('Đã lưu file', path=entry.path, size=len(data),
                      sha256=hashlib.sha256(data).hexdigest())

    log.quyet_dinh('Case 1 hoàn tất', files=len(entries))

    return geometry
