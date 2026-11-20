"""FAT32 case 3: chuoi FAT cua file JPEG bi xoa (ca 2 bang FAT), file bi chia 2 manh.

Con lai: first cluster va size trong directory entry.
Y tuong:
  * N = ceil(size / cluster_size) cluster can tim.
  * Manh 1: first .. first+k-1 (k chua biet, 1 <= k < N).
  * Manh 2: s .. L lien tuc, L = s + (N-k) - 1. Khoang trong G = s - (first+k) = L - N + 1 - first
    khong phu thuoc k  ->  moi G trong [1, 64] cho dung 1 cluster cuoi L.
  * Loc L: byte cuoi file phai la FF D9 (EOI) dung vi tri (size-1) % cluster_size trong cluster L.
  * Loc k: cac cluster cua 2 manh phai dang free trong ca 2 FAT va khong thuoc file nao khac;
    sau do giai ma Huffman (baseline JPEG) toan bo file ghep: moi ma Huffman hop le, so khoi
    du kich thuoc anh, cac marker RST dung thu tu, ket thuc dung tai FF D9.
  * Giai ma file doc lien tuc tu first cho vi tri loi p  ->  k <= p // cluster_size (can tren).
"""
import math
import os

from fat32_case2 import Fat32, _walk_tree, EOC_MIN, MASK_FAT

MAX_GAP = 64           # theo de: manh 2 nam trong 64 cluster sau manh 1
FALLBACK_GAP = 1024    # mo rong neu khong tim duoc trong cua so chuan
JPEG_EXT = ("JPG", "JPEG", "JPE", "JFIF")


# =====================================================================  JPEG
class JpegError(Exception):
    def __init__(self, pos, msg):
        super().__init__(f"{msg} (byte {pos})")
        self.pos = pos
        self.msg = msg


class _Huff:
    """Bang Huffman dang lookup 16 bit: peek16 -> (do dai ma, gia tri)."""

    def __init__(self, counts, symbols):
        self.lut_len = [0] * 65536
        self.lut_val = [0] * 65536
        code = 0
        k = 0
        for length in range(1, 17):
            for _ in range(counts[length - 1]):
                if code >= (1 << length):
                    raise ValueError("bang Huffman vuot khong gian ma")
                shift = 16 - length
                lo = code << shift
                hi = lo + (1 << shift)
                sym = symbols[k]
                for p in range(lo, hi):
                    self.lut_len[p] = length
                    self.lut_val[p] = sym
                code += 1
                k += 1
            code <<= 1


def _u16(data, pos):
    if pos + 2 > len(data):
        raise JpegError(len(data), "het du lieu khi doc u16")
    return (data[pos] << 8) | data[pos + 1]


def _entropy_segments(data, pos):
    """Tach du lieu entropy tu pos den marker (khong phai RST/00).
    Tra ve (segments, end): moi segment = (bytes_da_bo_stuffing, offset_goc_tung_byte, rst_marker_ket_thuc)."""
    segs = []
    buf = bytearray()
    offs = []
    n = len(data)
    i = pos
    while True:
        if i >= n:
            segs.append((bytes(buf), offs, None))
            return segs, n
        b = data[i]
        if b != 0xFF:
            buf.append(b)
            offs.append(i)
            i += 1
            continue
        if i + 1 >= n:
            segs.append((bytes(buf), offs, None))
            return segs, n
        m = data[i + 1]
        if m == 0x00:
            buf.append(0xFF)
            offs.append(i)
            i += 2
        elif 0xD0 <= m <= 0xD7:
            segs.append((bytes(buf), offs, m))
            buf = bytearray()
            offs = []
            i += 2
        elif m == 0xFF:   # fill byte truoc marker
            i += 1
        else:
            segs.append((bytes(buf), offs, None))
            return segs, i


def _decode_baseline_scan(data, pos, frame, scan, tables, restart):
    """Giai ma Huffman 1 scan baseline. Tra ve vi tri marker ngay sau scan."""
    comps = frame["comps"]
    hmax = max(c["h"] for c in comps.values())
    vmax = max(c["v"] for c in comps.values())
    X, Y = frame["x"], frame["y"]
    sc = scan["comps"]
    if len(sc) == 1:
        c = comps[sc[0]["id"]]
        bw = math.ceil(math.ceil(X * c["h"] / hmax) / 8)
        bh = math.ceil(math.ceil(Y * c["v"] / vmax) / 8)
        total_mcu = bw * bh
        layout = [(0, 1)]
    else:
        total_mcu = math.ceil(X / (8 * hmax)) * math.ceil(Y / (8 * vmax))
        layout = [(j, comps[s["id"]]["h"] * comps[s["id"]]["v"]) for j, s in enumerate(sc)]
    dc_tabs, ac_tabs = [], []
    for s in sc:
        dt = tables.get((0, s["td"]))
        at = tables.get((1, s["ta"]))
        if dt is None or at is None:
            raise JpegError(pos, "scan dung bang Huffman chua dinh nghia")
        dc_tabs.append(dt)
        ac_tabs.append(at)

    segs, end = _entropy_segments(data, pos)
    per_seg = restart if restart else total_mcu
    need_segs = math.ceil(total_mcu / per_seg) if total_mcu else 1
    if len(segs) < need_segs:
        last = segs[-1][1]
        raise JpegError(last[-1] if last else end, "thieu doan restart / het du lieu entropy")

    mcu = 0
    for si in range(need_segs):
        raw, offs, rst = segs[si]
        if si < need_segs - 1 and rst != 0xD0 + (si % 8):
            raise JpegError(offs[-1] + 2 if offs else end, "marker RST sai thu tu")
        nbits = len(raw) * 8
        # chuoi bit + 16 bit '1' de peek an toan o cuoi
        bits = (bin(int.from_bytes(raw, "big"))[2:].zfill(nbits) if raw else "") + "1" * 16
        i = 0
        n_mcu = min(per_seg, total_mcu - mcu)

        def fail(msg):
            # bao byte xa nhat co the anh huong (peek 16 bit) -> can tren an toan cho k
            b = min((i + 16) // 8, len(offs) - 1)
            raise JpegError(offs[b] if offs else end, msg)

        for _ in range(n_mcu):
            for j, nblk in layout:
                dt = dc_tabs[j]
                at = ac_tabs[j]
                for _b in range(nblk):
                    if i > nbits:
                        fail("het bit giua MCU")
                    p = int(bits[i:i + 16], 2)
                    ln = dt.lut_len[p]
                    if ln == 0:
                        fail("ma Huffman DC khong hop le")
                    t = dt.lut_val[p]
                    i += ln
                    if t > 11:
                        fail("do lon DC > 11")
                    i += t
                    k = 1
                    while k < 64:
                        if i > nbits:
                            fail("het bit giua MCU")
                        p = int(bits[i:i + 16], 2)
                        ln = at.lut_len[p]
                        if ln == 0:
                            fail("ma Huffman AC khong hop le")
                        rs = at.lut_val[p]
                        i += ln
                        r, s = rs >> 4, rs & 15
                        if s == 0:
                            if r == 15:
                                k += 16
                                continue
                            break
                        if s > 10:
                            fail("do lon AC > 10")
                        k += r
                        if k > 63:
                            fail("chi so he so AC vuot 63")
                        i += s
                        k += 1
                    if k > 64:
                        fail("ZRL vuot 63")
                    if i > nbits:
                        fail("het bit giua MCU")
        mcu += n_mcu
        # phan bit con lai chi duoc la padding '1' (< 8 bit)
        rest = nbits - i
        if rest >= 8 or bits[i:nbits] != "1" * rest:
            i = nbits
            fail("du lieu thua / padding sai sau MCU cuoi doan")
    if need_segs < len(segs):
        raise JpegError(end, "thua doan restart")
    return end


def _skip_scan_structural(data, pos):
    """Kiem tra cau truc entropy (progressive/khong ho tro): FF chi theo sau boi 00 hoac RST dung thu tu."""
    segs, end = _entropy_segments(data, pos)
    for si, (_, offs, rst) in enumerate(segs[:-1]):
        if rst != 0xD0 + (si % 8):
            raise JpegError(offs[-1] + 2 if offs else end, "marker RST sai thu tu")
    return end


VALID_MARKERS = set(range(0xC0, 0xFF)) - {0xC8, 0xD8} | {0x01}


def validate_jpeg(data):
    """Kiem tra file JPEG. Tra ve 'decode' (giai ma Huffman day du) hoac 'structure'
    (chi kiem tra cau truc, vd. progressive). Nem JpegError neu hong."""
    n = len(data)
    if n < 4 or data[0] != 0xFF or data[1] != 0xD8:
        raise JpegError(0, "thieu SOI FF D8")
    pos = 2
    frame = None
    tables = {}
    restart = 0
    scans = 0
    decoded_all = True
    while True:
        if pos >= n:
            raise JpegError(n - 1, "het file truoc EOI")
        if data[pos] != 0xFF:
            raise JpegError(pos, "mong doi marker")
        while pos + 1 < n and data[pos + 1] == 0xFF:
            pos += 1
        if pos + 1 >= n:
            raise JpegError(n - 1, "het file trong marker")
        m = data[pos + 1]
        if m not in VALID_MARKERS:
            raise JpegError(pos + 1, f"marker la FF {m:02X}")
        if m == 0xD9:
            if frame is None or scans == 0:
                raise JpegError(pos, "EOI truoc khi co frame/scan")
            if pos + 2 != n:
                raise JpegError(pos + 2, "con du lieu sau EOI")
            return "decode" if decoded_all else "structure"
        if m == 0x01 or 0xD0 <= m <= 0xD7:
            pos += 2
            continue
        seg_len = _u16(data, pos + 2)
        seg_end = pos + 2 + seg_len
        if seg_len < 2 or seg_end > n:
            raise JpegError(min(seg_end, n) - 1, "do dai segment khong hop le")
        body = data[pos + 4:seg_end]
        err_pos = seg_end - 1     # loi header: bao vi tri cuoi segment (can tren an toan)
        try:
            if m in (0xC0, 0xC1, 0xC2) or (0xC3 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC)):
                if frame is not None:
                    raise ValueError("nhieu SOF")
                y = (body[1] << 8) | body[2]
                x = (body[3] << 8) | body[4]
                nf = body[5]
                if x == 0 or y == 0 or nf == 0 or len(body) < 6 + 3 * nf:
                    raise ValueError("SOF sai")
                comps = {}
                for c in range(nf):
                    cid, hv, tq = body[6 + 3 * c:9 + 3 * c]
                    h, v = hv >> 4, hv & 15
                    if not (1 <= h <= 4 and 1 <= v <= 4):
                        raise ValueError("he so lay mau sai")
                    comps[cid] = {"h": h, "v": v}
                frame = {"marker": m, "x": x, "y": y, "comps": comps}
            elif m == 0xC4:
                q = 0
                while q < len(body):
                    tc, th = body[q] >> 4, body[q] & 15
                    counts = list(body[q + 1:q + 17])
                    if tc > 1 or th > 3 or len(counts) != 16:
                        raise ValueError("DHT sai")
                    total = sum(counts)
                    syms = list(body[q + 17:q + 17 + total])
                    if len(syms) != total:
                        raise ValueError("DHT thieu symbol")
                    tables[(tc, th)] = _Huff(counts, syms)
                    q += 17 + total
            elif m == 0xDD:
                restart = (body[0] << 8) | body[1]
            elif m == 0xDA:
                if frame is None:
                    raise ValueError("SOS truoc SOF")
                ns = body[0]
                sc = []
                for c in range(ns):
                    cid, tt = body[1 + 2 * c:3 + 2 * c]
                    if cid not in frame["comps"]:
                        raise ValueError("SOS tham chieu component la")
                    sc.append({"id": cid, "td": tt >> 4, "ta": tt & 15})
                ss, se, a = body[1 + 2 * ns:4 + 2 * ns]
                scan = {"comps": sc, "ss": ss, "se": se, "ah": a >> 4, "al": a & 15}
        except (IndexError, ValueError) as e:
            raise JpegError(err_pos, f"segment FF {m:02X} hong: {e}")

        pos = seg_end
        if m == 0xDA:
            scans += 1
            baseline = frame["marker"] in (0xC0, 0xC1) and scan["ss"] == 0 and scan["se"] == 63
            if baseline:
                pos = _decode_baseline_scan(data, pos, frame, scan, tables, restart)
            else:
                decoded_all = False
                pos = _skip_scan_structural(data, pos)


def jpeg_fail_pos(data):
    """None neu JPEG hop le, nguoc lai vi tri byte loi."""
    try:
        validate_jpeg(data)
        return None
    except JpegError as e:
        return e.pos


# =====================================================================  FAT32
def _fat2(fs, c):
    return fs.img.u32(fs.fat_offset + fs.fat_size * fs.bps + c * 4) & MASK_FAT


def _is_free(fs, c, owned):
    if c < 2 or c > fs.max_cluster or c in owned:
        return False
    if fs.fat(c) != 0:
        return False
    return fs.fat_count < 2 or _fat2(fs, c) == 0


def _read_clusters(fs, clusters, size):
    return fs.read_chain(clusters, size)


def _find_targets(fs, entries):
    """File co chuoi FAT khong dung voi size (bi xoa)."""
    targets = []
    for e in entries:
        if e["size"] == 0 or e["cluster"] < 2 or e["cluster"] > fs.max_cluster:
            continue
        need = math.ceil(e["size"] / fs.cluster_size)
        ch = fs.chain(e["cluster"])
        if ch is not None and len(ch) == need:
            continue
        e["need"] = need
        e["bad_chain"] = ch
        targets.append(e)
    return targets


def _search(fs, ent, owned, log, max_gap, check_free, check_tail):
    first, size, N = ent["cluster"], ent["size"], ent["need"]
    cs = fs.cluster_size
    tail = (size - 1) % cs           # vi tri byte cuoi file trong cluster cuoi

    # Chay free tu first: manh 1 khong the vuot qua cluster da cap phat
    run = 0
    c = first
    while run < N and c <= fs.max_cluster and (c == first or not check_free or _is_free(fs, c, owned)):
        run += 1
        c += 1

    # Can tren cho k: giai ma ban doc lien tuc
    kmax = min(N - 1, run)
    if first + N - 1 <= fs.max_cluster:
        contig = _read_clusters(fs, list(range(first, first + N)), size)
        p = jpeg_fail_pos(contig)
        if p is None:
            log.canh_bao("Doc lien tuc tu first cluster da la JPEG hop le (file co the khong bi phan manh)",
                         first_cluster=first)
            return [(0, N, first + N - 1, "decode", contig)]
        log.buoc("Giai ma JPEG doc lien tuc: loi dau tien tai byte cua file", gia_tri=p)
        kmax = min(kmax, p // cs)
    log.quyet_dinh("Gioi han do dai manh 1", k_max=kmax, chay_cluster_free=run, clusters_can=N)
    if kmax < 1:
        return []

    found = []
    for gap in range(1, max_gap + 1):
        L = first + N - 1 + gap
        if L > fs.max_cluster:
            break
        if check_tail:
            off = fs.cluster_offset(L)
            if fs.img.u8(off + tail) != 0xD9:
                continue
            if tail >= 1 and fs.img.u8(off + tail - 1) != 0xFF:
                continue
            log.buoc("Cluster co FF D9 dung vi tri byte cuoi file", offset=off + tail - 1,
                     gia_tri={"cluster": L, "gap": gap})
        if check_free and not _is_free(fs, L, owned):
            continue
        for k in range(kmax, 0, -1):
            s = L - N + k + 1
            frag2 = list(range(s, L + 1))
            if check_free and not all(_is_free(fs, x, owned) for x in frag2):
                continue
            chain = list(range(first, first + k)) + frag2
            data = _read_clusters(fs, chain, size)
            try:
                kind = validate_jpeg(data)
            except JpegError as e:
                log.buoc("Loai ung vien", gia_tri={"k": k, "s": s, "gap": gap, "ly_do": str(e)})
                continue
            log.buoc("Ung vien hop le", gia_tri={"k": k, "s": s, "L": L, "gap": gap, "kiem_tra": kind})
            found.append((gap, k, L, kind, data))
            if kind == "decode":
                break      # giai ma Huffman day du: k lon nhat hop le la dung
    return found


def _pick(found):
    strong = [f for f in found if f[3] == "decode"]
    pool = strong or found
    # uu tien gap nho, roi k lon (manh 1 dai nhat)
    pool.sort(key=lambda f: (f[0], -f[1]))
    return pool[0], len(pool)


def recover_case3(img, out, log):
    fs = Fat32.mo(img, log)
    log.buoc("Duyet cay thu muc tu RootClus", gia_tri=fs.root_cluster)
    entries, owned = _walk_tree(fs, log)
    targets = _find_targets(fs, entries)
    if not targets:
        log.quyet_dinh("Khong co file nao co chuoi FAT sai -> khong co gi de phuc hoi")
        return

    for ent in targets:
        ext = os.path.splitext(ent["name"])[1].lstrip(".").upper()
        first_off = fs.cluster_offset(ent["cluster"])
        head = fs.img.doc(first_off, 3)
        log.buoc("File co chuoi FAT bi xoa", offset=ent["entry_offset"], gia_tri={
            "path": ent["path"], "first_cluster": ent["cluster"], "size": ent["size"],
            "clusters_can": ent["need"], "fat[first]": fs.fat(ent["cluster"])})
        if ext not in JPEG_EXT and head != b"\xFF\xD8\xFF":
            log.canh_bao("Bo qua file khong phai JPEG", path=ent["path"])
            continue
        log.buoc("Chu ky dau file", offset=first_off, gia_tri=head.hex(" ").upper())
        known = len(ent["bad_chain"] or [ent["cluster"]])
        log.quyet_dinh("Tinh so cluster bi thieu tu size",
                       cong_thuc=f"ceil({ent['size']} / {fs.cluster_size}) = {ent['need']}",
                       cluster_da_biet=known, cluster_bi_thieu=ent["need"] - known)

        my_owned = owned - set(ent["bad_chain"] or [])
        found = []
        for max_gap, check_free, check_tail in ((MAX_GAP, True, True),
                                                (FALLBACK_GAP, True, True),
                                                (MAX_GAP, False, True),
                                                (FALLBACK_GAP, False, False)):
            log.buoc("Tim manh 2", gia_tri={"max_gap": max_gap, "check_free": check_free,
                                            "check_tail": check_tail})
            found = _search(fs, ent, my_owned, log, max_gap, check_free, check_tail)
            if found:
                break
        if not found:
            raise ValueError(f"Khong tim duoc manh 2 cho {ent['path']}")

        (gap, k, L, kind, data), n_cand = _pick(found)
        if n_cand > 1:
            log.canh_bao("Co nhieu ung vien hop le, chon gap nho nhat", so_ung_vien=n_cand)
        first, N = ent["cluster"], ent["need"]
        s = L - N + k + 1
        chain = list(range(first, first + k)) + list(range(s, L + 1))
        log.quyet_dinh("Chuoi vi tri cuoi cung", path=ent["path"],
                       manh_1=f"{first}-{first + k - 1} ({k} cluster)",
                       manh_2=f"{s}-{L} ({L - s + 1} cluster)" if k < N else "khong co",
                       gap=gap, kiem_tra=kind,
                       manh_2_offset=f"{fs.cluster_offset(s):#x}" if k < N else None,
                       chain=chain)
        out.luu(ent["path"], data)

    # Luu them cac file con nguyen chuoi FAT (de khong bat buoc, nhung giu du bo du lieu)
    damaged = {e["path"] for e in targets}
    for e in entries:
        if e["path"] in damaged or e["cluster"] < 2:
            continue
        ch = fs.chain(e["cluster"])
        if not ch:
            continue
        try:
            out.luu(e["path"], fs.read_chain(ch, e["size"]))
            log.buoc("Trich xuat file con nguyen", offset=e["entry_offset"],
                     gia_tri={"path": e["path"], "size": e["size"], "clusters": len(ch)})
        except ValueError as err:
            log.canh_bao("Khong doc duoc file con nguyen", path=e["path"], loi=str(err))
    log.buoc("Hoan tat phuc hoi Scenario 3")
