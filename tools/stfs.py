"""Reads Xbox 360 STFS packages (CON, LIVE and PIRS: title updates, downloadable content, saves).

Usage:
  python -I stfs.py info <package>
  python -I stfs.py list <package>
  python -I stfs.py extract <package> <directory>     (a new or empty directory)

info prints the package's metadata (content type; title ID, media ID, version and base version; the installer's type and
versions for title and system updates; names) and checks the hash tree: every data block's SHA-1 against its level-0
hash entry, every hash table below the top against its entry in the level above, and the top table against the volume
descriptor. list prints the files. extract writes the files under the directory, refusing names that would leave it or
that Windows treats specially, and says whether each file's blocks match their hashes. Nothing in a package is run.

The layout follows Velocity's and Xenia's readers: data blocks of 0x1000 bytes; a level-0 hash table (170 entries of
0x18 bytes: SHA-1, status, next block) before every 170 data blocks, a level-1 table after the first level-0 group of
every 28,900 blocks, a level-2 table after the first level-1 group; read-only packages keep one copy of each table,
the others two, and the entry above a table says which copy is current (the volume descriptor's flags for the top).
"""
import hashlib
import os
import struct
import sys

BLOCK = 0x1000
ENTRIES = 0xAA  # hash entries a table, and blocks a level-0 table covers
LEVEL1_BLOCKS = 0x70E4  # data blocks a level-1 table covers (170 * 170)
LEVEL2_BLOCKS = 0x4AF768  # and a level-2 table (170 ** 3)
CONTENT_TYPES = {
    0x00000001: "saved game", 0x00000002: "marketplace content", 0x00000003: "publisher",
    0x00001000: "Xbox 360 title", 0x00002000: "IPTV pause buffer", 0x00004000: "installed game",
    0x00005000: "Xbox original game", 0x00007000: "game on demand", 0x00009000: "avatar item",
    0x00010000: "profile", 0x00020000: "gamer picture", 0x00030000: "theme", 0x00040000: "cache file",
    0x00050000: "storage download", 0x00060000: "Xbox saved game", 0x00070000: "Xbox download",
    0x00080000: "game demo", 0x00090000: "video", 0x000A0000: "game title", 0x000B0000: "installer",
    0x000C0000: "game trailer", 0x000D0000: "arcade title", 0x000E0000: "XNA", 0x000F0000: "license store",
    0x00100000: "movie", 0x00200000: "TV", 0x00300000: "music video", 0x00400000: "game video",
    0x00500000: "podcast video", 0x00600000: "viral video", 0x02000000: "community game",
}
INSTALLER_TYPES = {
    b"SUPD": "system update", b"TUPD": "title update", b"P$SU": "system update progress cache",
    b"P$TU": "title update progress cache", b"P$TC": "title content progress cache",
}
# Names Windows opens as devices whatever the folder or extension.
RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {f"{p}{n}" for p in ("COM", "LPT") for n in "123456789"}


def be32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def le24(b, o):
    return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)


def be24(b, o):
    return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]


def version(v):
    """An XEX version word: major 4 bits, minor 4 bits, build 16 bits, QFE 8 bits."""
    return f"{v >> 28}.{(v >> 24) & 0xF}.{(v >> 8) & 0xFFFF}.{v & 0xFF}"


def utf16(b, o, n):
    return b[o:o + n].decode("utf-16-be", errors="replace").split("\0", 1)[0]


def fat_time(t):
    if not t:
        return "-"
    date, time = t >> 16, t & 0xFFFF
    return (f"{((date >> 9) & 0x7F) + 1980:04}-{(date >> 5) & 0xF:02}-{date & 0x1F:02} "
            f"{(time >> 11) & 0x1F:02}:{(time >> 5) & 0x3F:02}:{(time & 0x1F) * 2:02}")


class Package:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if len(d) < 0x971A:
            raise ValueError(f"too short for an STFS package ({len(d)} bytes)")
        self.magic = d[0:4]
        if self.magic not in (b"CON ", b"LIVE", b"PIRS"):
            raise ValueError(f"not an STFS package (magic {self.magic!r})")
        self.content_id = d[0x32C:0x340]
        self.header_size = be32(d, 0x340)
        self.content_type = be32(d, 0x344)
        self.metadata_version = be32(d, 0x348)
        self.content_size = struct.unpack_from(">Q", d, 0x34C)[0]
        self.media_id = be32(d, 0x354)
        self.version = be32(d, 0x358)
        self.base_version = be32(d, 0x35C)
        self.title_id = be32(d, 0x360)
        self.platform, self.exe_type, self.disc_number, self.disc_count = d[0x364:0x368]
        self.savegame_id = be32(d, 0x368)
        self.console_id = d[0x36C:0x371]
        self.profile_id = struct.unpack_from(">Q", d, 0x371)[0]
        vd = 0x379  # the STFS volume descriptor; its block fields are little-endian
        self.vd_size = d[vd]
        self.vd_flags = d[vd + 2]
        self.file_table_blocks = d[vd + 3] | (d[vd + 4] << 8)
        self.file_table_start = le24(d, vd + 5)
        self.top_hash = d[vd + 8:vd + 0x1C]
        self.allocated_blocks = be32(d, vd + 0x1C)
        self.unallocated_blocks = be32(d, vd + 0x20)
        self.data_file_count = be32(d, 0x39D)
        self.data_file_size = struct.unpack_from(">Q", d, 0x3A1)[0]
        self.volume_type = be32(d, 0x3A9)  # 0 STFS, 1 SVOD
        self.device_id = d[0x3FD:0x411]
        self.display_name = utf16(d, 0x411, 0x80)
        self.description = utf16(d, 0xD11, 0x80)
        self.publisher = utf16(d, 0x1611, 0x80)
        self.title_name = utf16(d, 0x1691, 0x80)
        self.transfer_flags = d[0x1711]
        self.thumb_size, self.title_thumb_size = struct.unpack_from(">II", d, 0x1712)
        self.installer = None
        if self.content_type == 0x000B0000 and len(d) >= 0x971A + 12:
            kind = d[0x971A:0x971E]
            if kind in (b"SUPD", b"TUPD"):
                self.installer = (kind, be32(d, 0x971E), be32(d, 0x9722))
            else:
                self.installer = (kind, None, None)
        if self.volume_type != 0:
            raise ValueError(f"volume type {self.volume_type} (SVOD) isn't read here, only STFS")
        # Read-only packages (flag bit 0) keep one copy of each hash table, the others two.
        self.copies_shift = 0 if self.vd_flags & 1 else 1
        self.steps = (0xAB, 0x718F) if self.copies_shift == 0 else (0xAC, 0x723A)
        self.first_table = (self.header_size + 0xFFF) & ~0xFFF
        n = self.allocated_blocks
        self.top_level = 0 if n <= ENTRIES else 1 if n <= LEVEL1_BLOCKS else 2

    # Where blocks and tables are, counted in blocks from the first hash table (Velocity's numbering).
    def backing_block(self, n):
        sh = self.copies_shift
        r = (((n + ENTRIES) // ENTRIES) << sh) + n
        if n < ENTRIES:
            return r
        if n < LEVEL1_BLOCKS:
            return r + (((n + LEVEL1_BLOCKS) // LEVEL1_BLOCKS) << sh)
        return (1 << sh) + r + (((n + LEVEL1_BLOCKS) // LEVEL1_BLOCKS) << sh)

    def table_block(self, n, level):
        """The backing block of the hash table at `level` that covers data block n (its first copy)."""
        sh = self.copies_shift
        if level == 0:
            if n < ENTRIES:
                return 0
            num = (n // ENTRIES) * self.steps[0] + (((n // LEVEL1_BLOCKS) + 1) << sh)
            return num if n < LEVEL1_BLOCKS else num + (1 << sh)
        if level == 1:
            return self.steps[0] if n < LEVEL1_BLOCKS else (1 << sh) + (n // LEVEL1_BLOCKS) * self.steps[1]
        return self.steps[1]

    def block_offset(self, n):
        return self.first_table + self.backing_block(n) * BLOCK

    def block(self, n):
        o = self.block_offset(n)
        return self.data[o:o + BLOCK]

    def table_offset(self, n, level):
        """The file offset of the current copy of the level's table covering data block n: the top table's copy is
        the volume descriptor's (flag bit 1), each lower one's the status bit 0x40 of its entry in the table above."""
        second = bool(self.vd_flags & 2)
        for upper in range(self.top_level, level, -1):
            o = self.first_table + self.table_block(n, upper) * BLOCK + (BLOCK if second and self.copies_shift else 0)
            o += ((n // ENTRIES ** upper) % ENTRIES) * 0x18
            second = bool(self.data[o + 0x14] & 0x40)
        return self.first_table + self.table_block(n, level) * BLOCK + (BLOCK if second and self.copies_shift else 0)

    def hash_entry(self, n, level=0):
        """(SHA-1, status, next block) of the entry for data block n in its level's table."""
        o = self.table_offset(n, level) + ((n // ENTRIES ** level) % ENTRIES) * 0x18
        return self.data[o:o + 0x14], self.data[o + 0x14], be24(self.data, o + 0x15)

    def check_block(self, n):
        return hashlib.sha1(self.block(n)).digest() == self.hash_entry(n)[0]

    def check_tree(self):
        """Counts of (checked, bad) for each level's tables against the level above, and whether the top table
        matches the volume descriptor."""
        out = {}
        for level in range(1, self.top_level + 1):
            span = ENTRIES ** level  # data blocks a table at level - 1 covers
            checked = bad = 0
            for first in range(0, self.allocated_blocks, span):
                o = self.table_offset(first, level - 1)
                if hashlib.sha1(self.data[o:o + BLOCK]).digest() != self.hash_entry(first, level)[0]:
                    bad += 1
                checked += 1
            out[level - 1] = (checked, bad)
        o = self.table_offset(0, self.top_level)
        top = hashlib.sha1(self.data[o:o + BLOCK]).digest() == self.top_hash
        return out, top

    def chain(self, start, count):
        blocks, n = [], start
        for _ in range(count):
            if n >= self.allocated_blocks:
                raise ValueError(f"block chain leaves the package at block {n}")
            blocks.append(n)
            n = self.hash_entry(n)[2]
        return blocks

    def files(self):
        table = b"".join(self.block(n) for n in self.chain(self.file_table_start, self.file_table_blocks))
        entries = []
        for i in range(len(table) // 0x40):
            e = table[i * 0x40:(i + 1) * 0x40]
            flags = e[0x28]
            name_len = flags & 0x3F
            if name_len == 0:  # a free entry
                continue
            if e[0] == 0:  # the end of the listing (Velocity's rule)
                break
            entries.append({
                "index": i,
                "name": e[:name_len].decode("latin-1"),
                "dir": bool(flags & 0x80),
                "consecutive": bool(flags & 0x40),
                "blocks": le24(e, 0x29),
                "start": le24(e, 0x2F),
                "parent": struct.unpack_from(">H", e, 0x32)[0],
                "size": be32(e, 0x34),
                "updated": be32(e, 0x38),
                "accessed": be32(e, 0x3C),
            })
        return entries

    def path_of(self, entries, entry):
        by_index = {e["index"]: e for e in entries}
        parts, e, seen = [entry["name"]], entry, set()
        while e["parent"] != 0xFFFF:
            if e["parent"] in seen or e["parent"] not in by_index:
                raise ValueError(f"bad directory chain for {entry['name']!r}")
            seen.add(e["parent"])
            e = by_index[e["parent"]]
            parts.append(e["name"])
        return "/".join(reversed(parts))

    def file_blocks(self, entry):
        if entry["consecutive"]:
            return list(range(entry["start"], entry["start"] + entry["blocks"]))
        return self.chain(entry["start"], entry["blocks"])

    def read_file(self, entry):
        if entry["size"] > entry["blocks"] * BLOCK:
            raise ValueError(f"{entry['name']!r}: {entry['size']} bytes in {entry['blocks']} blocks")
        blocks = self.file_blocks(entry)
        return b"".join(self.block(n) for n in blocks)[:entry["size"]], blocks


def info(p):
    print(f"magic {p.magic.decode()}  header size 0x{p.header_size:X}  metadata version {p.metadata_version}  "
          f"content ID {p.content_id.hex().upper()}")
    print(f"content type 0x{p.content_type:08X} ({CONTENT_TYPES.get(p.content_type, '?')})  "
          f"content size 0x{p.content_size:X}")
    print(f"title ID {p.title_id:08X}  media ID {p.media_id:08X}  version 0x{p.version:08X} ({version(p.version)})  "
          f"base version 0x{p.base_version:08X} ({version(p.base_version)})")
    print(f"platform {p.platform}  executable type {p.exe_type}  disc {p.disc_number}/{p.disc_count}  "
          f"savegame ID {p.savegame_id:08X}")
    print(f"console ID {p.console_id.hex()}  profile ID {p.profile_id:016X}  device ID {p.device_id.hex()}")
    print(f"volume: descriptor size 0x{p.vd_size:X} flags 0x{p.vd_flags:02X} "
          f"({'read-only, one copy of each hash table' if p.vd_flags & 1 else 'two copies of each hash table'}), "
          f"file table {p.file_table_blocks} block(s) at {p.file_table_start}, "
          f"allocated {p.allocated_blocks}, unallocated {p.unallocated_blocks}, hash levels {p.top_level + 1}")
    print(f"data files {p.data_file_count}, size 0x{p.data_file_size:X}; transfer flags 0x{p.transfer_flags:02X}")
    print(f"display name: {p.display_name!r}")
    print(f"description: {p.description!r}")
    print(f"publisher: {p.publisher!r}  title: {p.title_name!r}")
    print(f"thumbnail {p.thumb_size} bytes, title thumbnail {p.title_thumb_size} bytes")
    if p.installer:
        kind, base, ver = p.installer
        label = INSTALLER_TYPES.get(kind, "?")
        if base is None:
            print(f"installer: {kind!r} ({label})")
        else:
            print(f"installer: {kind.decode()} ({label}), base version 0x{base:08X} ({version(base)}), "
                  f"version 0x{ver:08X} ({version(ver)})")
    print(f"package bytes {len(p.data)} (0x{len(p.data):X})")
    tables, top = p.check_tree()
    print(f"top hash table (level {p.top_level}) matches the volume descriptor: {top}")
    for level, (checked, bad) in sorted(tables.items()):
        print(f"level-{level} hash tables that match their entry above: {checked - bad} of {checked}")
    bad = [n for n in range(p.allocated_blocks) if not p.check_block(n)]
    print(f"data blocks whose SHA-1 matches their hash entry: {p.allocated_blocks - len(bad)} of {p.allocated_blocks}"
          + (f" (bad: {bad[:10]})" if bad else ""))


def listing(p):
    entries = p.files()
    print(f"files ({len(entries)}):")
    for e in entries:
        kind = "<DIR>" if e["dir"] else f"{e['size']:>10}"
        extra = ""
        if not e["dir"]:
            content, blocks = p.read_file(e)
            bad = sum(1 for n in blocks if not p.check_block(n))
            extra = f"  sha256 {hashlib.sha256(content).hexdigest()}  bad blocks {bad}"
        print(f"{kind}  {p.path_of(entries, e)}  start {e['start']} blocks {e['blocks']} "
              f"{'consecutive' if e['consecutive'] else 'chained'}  updated {fat_time(e['updated'])}{extra}")


def safe_parts(rel):
    parts = rel.split("/")
    for part in parts:
        if part in ("", ".", "..") or any(c in part for c in '\\:*?"<>|') or any(ord(c) < 32 for c in part):
            return None
        if part != part.rstrip(". ") or part.split(".", 1)[0].upper() in RESERVED_NAMES:
            return None
    return parts


def extract(p, out_dir):
    if os.path.exists(out_dir) and (not os.path.isdir(out_dir) or os.listdir(out_dir)):
        sys.exit(f"{out_dir} isn't a new or empty directory")
    entries = p.files()
    os.makedirs(out_dir, exist_ok=True)
    root = os.path.realpath(out_dir)
    for e in entries:
        rel = p.path_of(entries, e)
        parts = safe_parts(rel)
        target = os.path.realpath(os.path.join(root, *parts)) if parts else None
        if not target or not target.startswith(root + os.sep):
            sys.exit(f"refusing the name {rel!r}")
        if e["dir"]:
            os.makedirs(target, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        content, blocks = p.read_file(e)
        bad = [n for n in blocks if not p.check_block(n)]
        with open(target, "xb") as f:
            f.write(content)
        print(f"extracted {rel} ({len(content)} bytes, {len(blocks)} blocks, "
              f"{'all hashes match' if not bad else f'{len(bad)} bad block hashes'}) "
              f"sha256 {hashlib.sha256(content).hexdigest()}")


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("info", "list", "extract") or (sys.argv[1] == "extract") != (len(sys.argv) == 4):
        sys.exit(__doc__)
    p = Package(sys.argv[2])
    if sys.argv[1] == "info":
        info(p)
    elif sys.argv[1] == "list":
        listing(p)
    else:
        extract(p, sys.argv[3])


if __name__ == "__main__":
    main()
