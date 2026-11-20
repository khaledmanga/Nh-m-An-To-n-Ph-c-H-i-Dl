from dataclasses import dataclass
import itertools
import math
import os


EOC_MIN = 0x0FFFFFF8
BAD_CLUSTER = 0x0FFFFFF7
MASK_FAT = 0x0FFFFFFF


@dataclass
class Fat32:
    img: object
    volume_offset: int
    volume_size: int
    bps: int
    spc: int
    reserved: int
    fat_count: int
    fat_size: int
    root_cluster: int
    fat_offset: int
    data_offset: int
    cluster_size: int
    max_cluster: int

    @classmethod
    def mo(cls, img, log):
        candidates = []
        if img.kich_thuoc >= 512 and img.doc(510, 2) == b'\x55\xaa':
            for i in range(4):
                e = 446 + i * 16
                ptype = img.u8(e + 4)
                lba = img.u32(e + 8)
                sectors = img.u32(e + 12)
                if ptype != 0 and lba and sectors:
                    # Khong chi tin partition type: kiem tra BPB thuc te o tung partition.
                    candidates.append((lba * 512, sectors * 512,
                                       f"MBR partition {i + 1}, type 0x{ptype:02X}"))
        candidates.append((0, img.kich_thuoc, "superfloppy/boot sector tai offset 0"))

        last_error = None
        for vol_off, vol_size, source in candidates:
            try:
                if vol_off < 0 or vol_off + 512 > img.kich_thuoc:
                    continue
                if img.doc(vol_off + 510, 2) != b'\x55\xaa':
                    continue
                bps = img.u16(vol_off + 0x0B)
                spc = img.u8(vol_off + 0x0D)
                reserved = img.u16(vol_off + 0x0E)
                fats = img.u8(vol_off + 0x10)
                root_entries = img.u16(vol_off + 0x11)
                total16 = img.u16(vol_off + 0x13)
                fatsz16 = img.u16(vol_off + 0x16)
                total32 = img.u32(vol_off + 0x20)
                fatsz32 = img.u32(vol_off + 0x24)
                root = img.u32(vol_off + 0x2C) & MASK_FAT

                if bps not in (512, 1024, 2048, 4096):
                    continue
                if spc == 0 or spc & (spc - 1):
                    continue
                if reserved == 0 or fats == 0 or fatsz32 == 0:
                    continue
                
                if root_entries != 0 or fatsz16 != 0:
                    continue
                total_sectors = total32 or total16
                if total_sectors == 0:
                    continue
                calculated_size = total_sectors * bps
                if vol_size > 0:
                    volume_size = min(vol_size, calculated_size)
                else:
                    volume_size = calculated_size
                fat_rel = reserved * bps
                data_rel = (reserved + fats * fatsz32) * bps
                cluster_size = bps * spc
                data_bytes = calculated_size - data_rel
                cluster_count = data_bytes // cluster_size
                max_cluster = cluster_count + 1
                fat_offset = vol_off + fat_rel
                data_offset = vol_off + data_rel
                if root < 2 or root > max_cluster:
                    continue
                if fat_offset + fatsz32 * bps > img.kich_thuoc:
                    continue
                if data_offset + data_bytes > img.kich_thuoc:
                    continue
                if fatsz32 * bps // 4 < max_cluster + 1:
                    continue
                log.buoc("Nhan dien FAT32", offset=vol_off, gia_tri=source)
                log.buoc("Doc BPB_BytsPerSec", offset=vol_off + 0x0B, gia_tri=bps)
                log.buoc("Doc BPB_SecPerClus", offset=vol_off + 0x0D, gia_tri=spc)
                log.buoc("Doc BPB_RsvdSecCnt", offset=vol_off + 0x0E, gia_tri=reserved)
                log.buoc("Doc BPB_NumFATs", offset=vol_off + 0x10, gia_tri=fats)
                log.buoc("Doc BPB_FATSz32", offset=vol_off + 0x24, gia_tri=fatsz32)
                log.buoc("Doc BPB_RootClus", offset=vol_off + 0x2C, gia_tri=root)
                log.quyet_dinh("Tinh cac vung FAT32 tu BPB", fat_offset=fat_offset,
                               data_offset=data_offset, cluster_size=cluster_size,
                               max_cluster=max_cluster)
                return cls(img, vol_off, calculated_size, bps, spc, reserved,
                           fats, fatsz32, root, fat_offset, data_offset,
                           cluster_size, max_cluster)
            except (ValueError, OverflowError) as e:
                last_error = e
        raise ValueError(f"Khong tim thay boot sector FAT32 hop le: {last_error or 'khong khop BPB'}")

    def cluster_offset(self, cluster):
        if cluster < 2 or cluster > self.max_cluster:
            raise ValueError(f"cluster ngoai pham vi: {cluster}")
        off = self.data_offset + (cluster - 2) * self.cluster_size
        if off + self.cluster_size > self.img.kich_thuoc:
            raise ValueError(f"cluster vuot qua kich thuoc anh: {cluster}")
        return off

    def fat(self, cluster):
        if cluster < 0:
            raise ValueError("cluster am")
        off = self.fat_offset + cluster * 4
        return self.img.u32(off) & MASK_FAT

    def chain(self, start, limit=None):
        """Doc chuoi FAT, tra ve None neu gap loop/cluster hong/ngoai pham vi."""
        if start < 2 or start > self.max_cluster:
            return None
        if limit is None:
            limit = self.max_cluster
        result, seen = [], set()
        cur = start
        while len(result) <= limit:
            if cur < 2 or cur > self.max_cluster or cur in seen:
                return None
            seen.add(cur)
            result.append(cur)
            nxt = self.fat(cur)
            if EOC_MIN <= nxt <= MASK_FAT:
                return result
            if nxt == 0 or nxt == 1 or nxt == BAD_CLUSTER or nxt >= 0x0FFFFFF0:
                return None
            cur = nxt
        return None

    def read_chain(self, chain, size):
        chunks = []
        remain = size
        for c in chain:
            n = min(remain, self.cluster_size)
            if n <= 0:
                break
            chunks.append(self.img.doc(self.cluster_offset(c), n))
            remain -= n
        if remain:
            raise ValueError("chuoi cluster ngan hon kich thuoc file")
        return b"".join(chunks)


def _decode_sfn(raw):
    name = raw[:8].decode("cp437", errors="replace").rstrip()
    ext = raw[8:11].decode("cp437", errors="replace").rstrip()
    if name.startswith("\x05"):
        name = "\xE5" + name[1:]
    return name + ("." + ext if ext else "")


def _lfn_piece(entry):
    raw = entry[1:11] + entry[14:26] + entry[28:32]
    for i in range(0, len(raw), 2):
        if raw[i:i + 2] in (b"\x00\x00", b"\xff\xff"):
            raw = raw[:i]
            break
    return raw


def _directory_entries(fs, directory_chain):
    data = b"".join(fs.img.doc(fs.cluster_offset(c), fs.cluster_size) for c in directory_chain)
    lfn = {}
    for pos in range(0, len(data) - 31, 32):
        e = data[pos:pos + 32]
        first = e[0]
        if first == 0x00:
            break
        if first == 0xE5:
            lfn.clear()
            continue
        attr = e[11]
        if attr == 0x0F:
            order = first & 0x1F
            if order:
                lfn[order] = _lfn_piece(e)
            continue
        if attr & 0x08:  # volume label
            lfn.clear()
            continue
        if lfn:
            name_bytes = b"".join(lfn[k] for k in sorted(lfn))
            name = name_bytes.decode("utf-16le", errors="replace")
        else:
            name = _decode_sfn(e[:11])
        lfn.clear()
        if name in (".", ".."):
            continue
        high = (e[20] | (e[21] << 8))
        low = (e[26] | (e[27] << 8))
        first_cluster = ((high << 16) | low) & MASK_FAT
        size = int.from_bytes(e[28:32], "little")
        cluster_index = pos // fs.cluster_size
        within_cluster = pos % fs.cluster_size
        entry_offset = fs.cluster_offset(directory_chain[cluster_index]) + within_cluster
        yield {"name": name, "attr": attr, "cluster": first_cluster,
               "size": size, "entry_offset": entry_offset,
               "is_dir": bool(attr & 0x10)}


def _walk_tree(fs, log):
    owned = set()
    files = []
    visited_dirs = set()

    def visit_dir(start, path):
        if start in visited_dirs:
            return
        visited_dirs.add(start)
        chain = fs.chain(start)
        if not chain:
            log.canh_bao("Bo qua directory co FAT chain khong hop le", cluster=start, path=path)
            return
        owned.update(chain)
        for ent in _directory_entries(fs, chain):
            full = f"{path}/{ent['name']}" if path else ent["name"]
            if ent["is_dir"]:
                if ent["cluster"] >= 2:
                    visit_dir(ent["cluster"], full)
                continue
            if ent["size"] == 0 or ent["cluster"] < 2:
                # Cluster=0 voi file co size > 0 la entry bi hong; xu ly sau.
                if ent["size"] > 0 and ent["cluster"] < 2:
                    ent["path"] = full
                    files.append(ent)
                continue
            ch = fs.chain(ent["cluster"])
            if ch:
                owned.update(ch)
            ent["path"] = full
            files.append(ent)

    visit_dir(fs.root_cluster, "")
    return files, owned


def _plausible_content(ext, data):
    head = data[:16]
    ext = ext.upper()
    if ext in ("JPG", "JPEG"):
        return data.startswith(b"\xFF\xD8\xFF") and b"\xFF\xD9" in data[-32:]
    if ext == "PNG":
        return data.startswith(b"\x89PNG\r\n\x1a\n") and b"IEND" in data[-64:]
    if ext == "PDF":
        return data.startswith(b"%PDF-")
    if ext in ("TXT", "CSV", "MD"):
        try:
            s = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return False
        if not s:
            return True
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in s)
        return printable / len(s) >= 0.90
    return False


def recover_case2(img, out, log):
    fs = Fat32.mo(img, log)
    log.buoc("Bat dau duyet cay thu muc tu RootClus", gia_tri=fs.root_cluster)
    entries, owned = _walk_tree(fs, log)
    damaged = [e for e in entries if e["cluster"] < 2 and e["size"] > 0]
    if not damaged:
        log.quyet_dinh("Khong tim thay directory entry co FirstCluster hong")
        return
    log.buoc("Tim thay cac directory entry co FirstCluster khong hop le", gia_tri=len(damaged))

    incoming = set()
    allocated = []
    for c in range(2, fs.max_cluster + 1):
        nxt = fs.fat(c)
        if nxt not in (0, 1, BAD_CLUSTER) and not (EOC_MIN <= nxt <= MASK_FAT) and 2 <= nxt <= fs.max_cluster:
            incoming.add(nxt)
        if nxt != 0 and nxt != 1 and nxt != BAD_CLUSTER:
            allocated.append(c)
    starts = [c for c in allocated if c not in incoming and c not in owned]
    log.buoc("Quet FAT de tim cluster da cap phat khong co predecessor", gia_tri=len(starts))

    chains = []
    for start in starts:
        ch = fs.chain(start)
        if not ch or any(c in owned for c in ch):
            continue
        chains.append((start, ch))

    options = {}
    for idx, ent in enumerate(damaged):
        need = math.ceil(ent["size"] / fs.cluster_size)
        ext = os.path.splitext(ent["name"])[1].lstrip(".").upper()
        valid = []
        for start, ch in chains:
            if len(ch) != need:
                continue
            try:
                data = fs.read_chain(ch, ent["size"])
            except ValueError:
                continue
            if _plausible_content(ext, data):
                valid.append((start, ch, data))
        options[idx] = valid
        log.buoc("Loc chuoi ung vien theo kich thuoc va dinh dang", gia_tri={
            "path": ent["path"], "clusters_can": need, "ung_vien": len(valid)})

    order = sorted(range(len(damaged)), key=lambda i: len(options[i]))
    solutions = []

    def search(k, used, chosen):
        if len(solutions) > 1:
            return
        if k == len(order):
            solutions.append(dict(chosen))
            return
        i = order[k]
        for candidate in options[i]:
            start = candidate[0]
            if start in used:
                continue
            used.add(start)
            chosen[i] = candidate
            search(k + 1, used, chosen)
            chosen.pop(i, None)
            used.remove(start)

    search(0, set(), {})
    if not solutions:
        missing = [damaged[i]["path"] for i in order if not options[i]]
        raise ValueError("Khong ghep duoc chuoi FAT cho cac file: " + ", ".join(missing or [e["path"] for e in damaged]))
    if len(solutions) != 1:
        raise ValueError("Co nhieu cach ghep chuoi FAT hop le; dung lai de tranh gan nham file")

    chosen = solutions[0]
    for i, ent in enumerate(damaged):
        start, chain, data = chosen[i]
        log.quyet_dinh("Ghep directory entry voi chuoi FAT", path=ent["path"],
                       first_cluster=start, chain_length=len(chain), file_size=ent["size"])
        out.luu(ent["path"], data)
    log.buoc("Hoan tat phuc hoi Scenario 2", gia_tri=len(damaged))
