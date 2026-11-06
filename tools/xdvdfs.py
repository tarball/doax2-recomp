"""Minimal XDVDFS (Xbox/Xbox 360 game disc filesystem) reader.

Usage:
  python xdvdfs.py <iso> list
  python xdvdfs.py <iso> extract <path-in-image> <out-file>
  python xdvdfs.py <iso> hash <out.tsv>
  python xdvdfs.py <iso or listing> compare <iso or listing>

hash writes every file's path, size, start sector and SHA-256 (directories: <DIR>), then the volume's facts (partition
base, root directory, the volume descriptor's timestamp, the image's size) and the SHA-256 of the region before the
partition and of the partition's first 34 sectors, on lines starting with '#'. compare compares two such listings, or
two images (hashed first), file by file: identical (and moved), changed, added and removed.
"""
import datetime
import hashlib
import os
import struct
import sys

SECTOR = 2048
MAGIC = b"MICROSOFT*XBOX*MEDIA"
# Game partition offsets: plain XISO, XGD1, XGD2, XGD3
PARTITION_OFFSETS = [0, 0x18300000, 0xFD90000, 0x2080000]


def find_partition(f):
    for base in PARTITION_OFFSETS:
        f.seek(base + 32 * SECTOR)
        if f.read(20) == MAGIC:
            return base
    raise ValueError("No XDVDFS volume descriptor found")


def walk(f, base, sector, size, prefix=""):
    """Yields (path, is_dir, start_sector, size, attributes) for a directory's binary tree."""
    f.seek(base + sector * SECTOR)
    table = f.read(size)
    stack = [0]
    seen = set()
    while stack:
        off = stack.pop()
        if off in seen or off + 14 > len(table):
            continue
        seen.add(off)
        left, right, start, length, attr, nlen = struct.unpack_from("<HHIIBB", table, off)
        if left == 0xFFFF:  # padding
            continue
        name = table[off + 14:off + 14 + nlen].decode("latin-1")
        path = f"{prefix}/{name}"
        is_dir = bool(attr & 0x10)
        yield path, is_dir, start, length, attr
        if is_dir and length:
            yield from walk(f, base, start, length, path)
        if left:
            stack.append(left * 4)
        if right:
            stack.append(right * 4)


def open_volume(path):
    f = open(path, "rb")
    base = find_partition(f)
    f.seek(base + 32 * SECTOR + 20)
    root_sector, root_size = struct.unpack("<II", f.read(8))
    return f, base, root_sector, root_size


def hash_range(f, offset, length):
    h = hashlib.sha256()
    f.seek(offset)
    remaining = length
    while remaining:
        chunk = f.read(min(remaining, 8 << 20))
        if not chunk:
            break
        h.update(chunk)
        remaining -= len(chunk)
    return h.hexdigest()


def hash_image(iso):
    """The listing's lines for an image: its files with their SHA-256s, then its facts."""
    f, base, rs, rsz = open_volume(iso)
    with f:
        f.seek(base + 32 * SECTOR + 28)
        filetime = struct.unpack("<Q", f.read(8))[0]
        lines = []
        for path, is_dir, start, length, attr in sorted(walk(f, base, rs, rsz)):
            if is_dir:
                lines.append(f"{path}\t<DIR>\t{start}\t-\tattr=0x{attr:02X}")
            else:
                digest = hash_range(f, base + start * SECTOR, length)
                lines.append(f"{path}\t{length}\t{start}\t{digest}\tattr=0x{attr:02X}")
                print(f"{length:>12}  {digest[:16]}  {path}", flush=True)
        f.seek(0, 2)
        lines.append(f"# partition_base\t0x{base:X}")
        lines.append(f"# root\tsector={rs}\tsize={rsz}")
        lines.append(f"# volume_filetime\t0x{filetime:016X}")
        lines.append(f"# iso_size\t{f.tell()}")
        lines.append(f"# before_partition_sha256\t{hash_range(f, 0, base)}")
        lines.append(f"# partition_header_sha256\t{hash_range(f, base, 34 * SECTOR)}")
    return lines


def load_listing(path):
    """A listing's files (by lower-case path) and facts, from a listing or, for an image, by hashing it."""
    try:
        f, *_ = open_volume(path)
        f.close()
        print(f"hashing {path}", flush=True)
        lines = hash_image(path)
    except ValueError:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    files, facts = {}, {}
    for line in lines:
        if line.startswith("# "):
            key, value = line[2:].split("\t", 1)
            facts[key] = value
        elif line:
            p, size, start, digest, attr = line.split("\t")
            files[p.lower()] = (p, size, int(start), digest, attr)
    return files, facts


def filetime(text):
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(text, 16) // 10)


def compare(a_path, b_path):
    a, af = load_listing(a_path)
    b, bf = load_listing(b_path)
    same, changed = [], []
    for key in sorted(set(a) | set(b)):
        if key not in b:
            print(f"removed  {a[key][0]}  {a[key][1]}")
            continue
        if key not in a:
            print(f"added    {b[key][0]}  {b[key][1]}")
            continue
        pa, sa, sta, da, _ = a[key]
        _, sb, stb, db, _ = b[key]
        if sa == "<DIR>":
            continue
        if da == db:
            same.append((pa, int(sa), sta, stb))
        else:
            changed.append((pa, sa, sb, da, db))
    print(f"identical files: {len(same)} ({sum(s for _, s, _, _ in same):,} bytes)")
    for p, s, sta, stb in same:
        moved = "" if sta == stb else f"  (sector {sta} -> {stb})"
        print(f"  same     {p:<36} {s:>12,}{moved}")
    print(f"changed files: {len(changed)}")
    for p, sa, sb, da, db in changed:
        print(f"  changed  {p:<36} {int(sa):>12,} -> {int(sb):>12,}  ({int(sb) - int(sa):+,})")
        print(f"           {da}")
        print(f"           {db}")
    for key in sorted(set(af) | set(bf)):
        va, vb = af.get(key), bf.get(key)
        extra = ""
        if key == "volume_filetime" and va and vb:
            extra = f"  ({filetime(va)} UTC / {filetime(vb)} UTC)"
        print(f"# {key}: {'same' if va == vb else 'differs'}  {va} | {vb}{extra}")


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    iso, cmd = sys.argv[1], sys.argv[2]
    if cmd == "compare":
        compare(iso, sys.argv[3])
        return
    if cmd == "hash":
        lines = hash_image(iso)
        with open(sys.argv[3], "w", encoding="utf-8") as out:
            out.write("\n".join(lines) + "\n")
        return
    f, base, rs, rsz = open_volume(iso)
    entries = sorted(walk(f, base, rs, rsz))
    if cmd == "list":
        print(f"partition base 0x{base:X}")
        for p, d, s, l, _ in entries:
            print(f"{'<DIR>' if d else l:>12}  {p}")
    elif cmd == "extract":
        want = sys.argv[3].lower().lstrip("/")
        for p, d, s, l, _ in entries:
            if p.lower().lstrip("/") == want and not d:
                os.makedirs(os.path.dirname(os.path.abspath(sys.argv[4])), exist_ok=True)
                f.seek(base + s * SECTOR)
                with open(sys.argv[4], "wb") as out:
                    remaining = l
                    while remaining:
                        chunk = f.read(min(remaining, 1 << 20))
                        out.write(chunk)
                        remaining -= len(chunk)
                print(f"extracted {p} ({l} bytes)")
                return
        sys.exit(f"not found: {want}")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
