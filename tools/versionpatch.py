"""Builds, applies and checks a version patch: what turns one version of a game's files (a disc's executable and
archives) into another version's, made from the older version's own bytes plus what the patch carries. For DOA4, a
1.0 disc into Rev 1; for DOAX2, the disc's executable into Title Update 2's (analysis/version_patches.md).

Usage:
  python -I versionpatch.py build <out.vpatch> <versions> <pieces> [--engine E] [--no-code] [--functions <tsv>]
  python -I versionpatch.py compare <versions> <pieces> [--no-code]
  python -I versionpatch.py apply <patch> <source version> <out dir>
  python -I versionpatch.py verify <patch> <versions>
  python -I versionpatch.py info <patch>
  python -I versionpatch.py seeds <dir>

Versions (build, compare and verify need both, apply only the source):
  --source-disc <iso>, --target-disc <iso>       a disc image (its default.xex is decrypted and unpacked here)
  --source-xex <xex> <pe>, --target-xex <xex> <pe>
                                                 an executable as a XEX (only its header is read) and its image, for one
                                                 that isn't on a disc (a title update's: tools\\patchxex, tools\\xexpe.py)
Pieces:
  the executable, always: "default.xex/header" (the XEX header, which the runtime copies into guest memory) and
  "default.xex/image" (the image the runtime loads)
  --afs <path>     an AFS archive on both discs, entry by entry: identical entries are copies of the source's, changed
                   ones are matched against the source's entry of the same index (repeatable)
  --file <path>    any other file on both discs, as a whole (repeatable)
  --font <afs>:<entry>:<source table>:<source pages>:<target table>:<target pages>
                   (DOA4's kind of font: 1024x1024 8-bit tiled pages of 32x32 glyph cells, and a page table in each
                   executable, 16 bytes a page: texture, glyph count, size, the glyph list's address) the target's
                   pages are composed from the source's cells by code point (in the applier too, from the two images'
                   tables), so the patch carries only the cells the source lacks or drew differently
  --no-fonts       with --font: the composed pages are the result; the patch carries no glyph cells, and glyphs the
                   source lacks are blank
  --keep <afs>:<entry>
                   the source's entry stands for the target's (the same size; it goes where the target's would): the
                   patch carries nothing for it, and the result differs from the target there (repeatable)
  --no-code        the target image's code sections (its executable PE sections, which the game's code module already
                   holds) are left out: zero in the result, and recorded as unclaimed
  --leave <name>   another section of the target image left out the same way (repeatable), e.g. .pdata, the code's
                   exception tables, which only exception dispatch reads
Options:
  --engine ops-lzma (default) | ops-lzms | ops-raw | msdelta   (see below)
  --functions <tsv>  tools\\buildcompare.py match's TSV for the two images, to split the code's bytes by function kind

A piece names its source's size and SHA-256 (apply checks them first), its result's (the target with its unclaimed
ranges zero; apply checks it last) and the full target's. apply writes default.xex (the target's file, re-encrypted
and compressed as the source's was, when nothing is unclaimed), default.pe (the image) and the archives and files,
and an extent list per archive (what comes from the source file, from composed font pages and from the patch: how
the runtime would serve it without writing it out). verify applies in memory and compares every byte with the target
version's: the bytes that differ must lie in the ranges the patch declares (unclaimed, kept, composed font pages).

Engines, per piece:
  ops-lzma  operations on the source: COPY (source bytes), ADD (source bytes plus a difference stream, zero where they
            agree: moved addresses come out as a few bytes, bsdiff's idea) and INSERT (new bytes), their three streams
            compressed with LZMA (Python's lzma; the game decompresses them with the LZMA SDK's decoder): the only
            engine the game reads. A changed archive entry is stored as the cheapest of its matched operations, the
            same with unrelated runs (pictures) inserted, or inserted whole.
  ops-lzms  the same streams compressed with Windows' Compression API (LZMS, cabinet.dll), which Wine and Proton
            have only as placeholders (the engine before LZMA)
  ops-raw   the same streams uncompressed (a release's zip deflates them)
  msdelta   Windows' Delta Compression API (msdelta.dll's CreateDeltaB/ApplyDeltaB), one raw delta per piece (archives
            stay operations, entry by entry; compare gives msdelta's size for their changed entries)
compare gives every engine's size, and as standard references zstd's patch-from (the source as a prefix dictionary,
Python's compression.zstd) and the streams with zip's deflate.

seeds writes made-up patches (pseudo-random bytes, no game's) for the patch reader's fuzz harness to start from
(tools\\versionpatch_fuzz).

Nothing read from a disc or a download is run.
"""
import ctypes
import hashlib
import io
import lzma
import os
import random
import struct
import sys
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import xdvdfs  # noqa: E402

MAGIC = b"VPAT"
VERSION = 1
ENGINES = {"ops-lzms": 1, "ops-raw": 2, "msdelta": 3, "ops-lzma": 4}
ENGINE_NAMES = {v: k for k, v in ENGINES.items()}
OP_COPY, OP_ADD, OP_INSERT, OP_SKIP = 0, 1, 2, 3
OP_SIZE = 17  # u8 op, i64 source seek, u64 length
RETAIL_KEY = bytes.fromhex("20B185A59D28FDC340583FBB0896BF91")


def sha256(data):
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------------------------------------------------
# A patch's streams. ops-lzma's, as the game reads them (runtime/version_patch.cpp, the LZMA SDK's decoder): nothing for
# no bytes, else LZMA's 5 property bytes (lc 3, lp 0, pb 2 and the dictionary's size, preset 9's 64 MB, which the
# game's one-call decoder doesn't allocate) and the data, which ends with an end marker: liblzma's .lzma format without
# its header's 8-byte size (unknown there).

LZMA_PRESET = 9 | lzma.PRESET_EXTREME
LZMA_UNKNOWN_SIZE = b"\xff" * 8


def lzma_compress(data):
    if not data:
        return b""
    alone = lzma.compress(bytes(data), format=lzma.FORMAT_ALONE, preset=LZMA_PRESET)
    if alone[5:13] != LZMA_UNKNOWN_SIZE:
        raise ValueError("LZMA: liblzma's .lzma header has a size")
    return alone[:5] + alone[13:]


def lzma_decompress(data, size):
    if not size:
        if data:
            raise ValueError("LZMA: an empty stream has bytes")
        return b""
    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    out = decompressor.decompress(bytes(data[:5]) + LZMA_UNKNOWN_SIZE + bytes(data[5:]))
    if not decompressor.eof or decompressor.unused_data or len(out) != size:
        raise ValueError("LZMA: the stream isn't the recorded size")
    return out


def compress_stream(engine, data):
    """A piece's stream as its engine (ops-lzma, ops-lzms or ops-raw) stores it."""
    if engine == "ops-raw":
        return bytes(data)
    return lzms_compress(data) if engine == "ops-lzms" else lzma_compress(data)


def decompress_stream(engine, data, size):
    if engine == "ops-raw":
        if len(data) != size:
            raise ValueError("a raw stream isn't the recorded size")
        return bytes(data)
    return lzms_decompress(data, size) if engine == "ops-lzms" else lzma_decompress(data, size)


# ---------------------------------------------------------------------------------------------------------------------
# Windows: AES through BCrypt, LZMS through the Compression API, deltas through msdelta.

def aes_cbc(key, data, encrypt=False):
    """AES-128-CBC with a zero IV over the whole blocks of `data` (the rest is left as it is)."""
    dll = ctypes.WinDLL("bcrypt.dll")
    alg, hkey = ctypes.c_void_p(), ctypes.c_void_p()
    if dll.BCryptOpenAlgorithmProvider(ctypes.byref(alg), ctypes.c_wchar_p("AES"), None, 0):
        raise OSError("BCryptOpenAlgorithmProvider")
    try:
        mode = ctypes.create_unicode_buffer("ChainingModeCBC")
        if dll.BCryptSetProperty(alg, ctypes.c_wchar_p("ChainingMode"), mode, ctypes.sizeof(mode), 0):
            raise OSError("BCryptSetProperty")
        kbuf = ctypes.create_string_buffer(bytes(key), 16)
        if dll.BCryptGenerateSymmetricKey(alg, ctypes.byref(hkey), None, 0, kbuf, 16, 0):
            raise OSError("BCryptGenerateSymmetricKey")
        try:
            n = len(data) & ~15
            buf = ctypes.create_string_buffer(bytes(data[:n]), max(n, 1))
            iv = ctypes.create_string_buffer(16)
            done = ctypes.c_ulong()
            fn = dll.BCryptEncrypt if encrypt else dll.BCryptDecrypt
            if fn(hkey, buf, n, None, iv, 16, buf, n, ctypes.byref(done), 0) or done.value != n:
                raise OSError("BCryptEncrypt/BCryptDecrypt")
            return buf.raw[:n] + bytes(data[n:])
        finally:
            dll.BCryptDestroyKey(hkey)
    finally:
        dll.BCryptCloseAlgorithmProvider(alg, 0)


COMPRESS_ALGORITHM_LZMS = 5


def lzms_compress(data):
    if not data:
        return b""
    dll = ctypes.WinDLL("cabinet.dll")
    handle = ctypes.c_void_p()
    if not dll.CreateCompressor(COMPRESS_ALGORITHM_LZMS, None, ctypes.byref(handle)):
        raise OSError("CreateCompressor(LZMS)")
    try:
        src = ctypes.create_string_buffer(bytes(data), len(data))
        cap = len(data) + len(data) // 8 + 65536
        dst = ctypes.create_string_buffer(cap)
        out = ctypes.c_size_t()
        if not dll.Compress(handle, src, ctypes.c_size_t(len(data)), dst, ctypes.c_size_t(cap), ctypes.byref(out)):
            raise OSError(f"Compress(LZMS): error {ctypes.GetLastError()}")
        return dst.raw[:out.value]
    finally:
        dll.CloseCompressor(handle)


def lzms_decompress(data, size):
    if not size:
        return b""
    dll = ctypes.WinDLL("cabinet.dll")
    handle = ctypes.c_void_p()
    if not dll.CreateDecompressor(COMPRESS_ALGORITHM_LZMS, None, ctypes.byref(handle)):
        raise OSError("CreateDecompressor(LZMS)")
    try:
        src = ctypes.create_string_buffer(bytes(data), max(len(data), 1))
        dst = ctypes.create_string_buffer(size)
        out = ctypes.c_size_t()
        if not dll.Decompress(handle, src, ctypes.c_size_t(len(data)), dst, ctypes.c_size_t(size), ctypes.byref(out)):
            raise OSError(f"Decompress(LZMS): error {ctypes.GetLastError()}")
        if out.value != size:
            raise ValueError("LZMS: the stream isn't the recorded size")
        return dst.raw[:size]
    finally:
        dll.CloseDecompressor(handle)


class DELTA_INPUT(ctypes.Structure):
    _fields_ = [("lpStart", ctypes.c_void_p), ("uSize", ctypes.c_size_t), ("Editable", ctypes.c_int)]


class DELTA_OUTPUT(ctypes.Structure):
    _fields_ = [("lpStart", ctypes.c_void_p), ("uSize", ctypes.c_size_t)]


def _msdelta():
    dll = ctypes.WinDLL("msdelta.dll")
    dll.CreateDeltaB.argtypes = [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, DELTA_INPUT, DELTA_INPUT, DELTA_INPUT,
                                 DELTA_INPUT, DELTA_INPUT, ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(DELTA_OUTPUT)]
    dll.CreateDeltaB.restype = ctypes.c_int
    dll.ApplyDeltaB.argtypes = [ctypes.c_int64, DELTA_INPUT, DELTA_INPUT, ctypes.POINTER(DELTA_OUTPUT)]
    dll.ApplyDeltaB.restype = ctypes.c_int
    dll.DeltaFree.argtypes = [ctypes.c_void_p]
    return dll


def msdelta_create(source, target):
    """A raw delta (DELTA_FILE_TYPE_RAW, no flags, no hash) from source to target."""
    dll = _msdelta()
    s = ctypes.create_string_buffer(bytes(source), max(len(source), 1))
    t = ctypes.create_string_buffer(bytes(target), max(len(target), 1))
    empty = DELTA_INPUT(None, 0, 0)
    out = DELTA_OUTPUT()
    if not dll.CreateDeltaB(1, 0, 0, DELTA_INPUT(ctypes.cast(s, ctypes.c_void_p), len(source), 0),
                            DELTA_INPUT(ctypes.cast(t, ctypes.c_void_p), len(target), 0), empty, empty, empty, None, 0,
                            ctypes.byref(out)):
        raise OSError(f"CreateDeltaB: error {ctypes.GetLastError()}")
    try:
        return ctypes.string_at(out.lpStart, out.uSize)
    finally:
        dll.DeltaFree(out.lpStart)


def msdelta_apply(source, delta):
    dll = _msdelta()
    s = ctypes.create_string_buffer(bytes(source), max(len(source), 1))
    d = ctypes.create_string_buffer(bytes(delta), max(len(delta), 1))
    out = DELTA_OUTPUT()
    if not dll.ApplyDeltaB(0, DELTA_INPUT(ctypes.cast(s, ctypes.c_void_p), len(source), 0),
                           DELTA_INPUT(ctypes.cast(d, ctypes.c_void_p), len(delta), 0), ctypes.byref(out)):
        raise OSError(f"ApplyDeltaB: error {ctypes.GetLastError()}")
    try:
        return ctypes.string_at(out.lpStart, out.uSize)
    finally:
        dll.DeltaFree(out.lpStart)


# ---------------------------------------------------------------------------------------------------------------------
# XEX2: the header, and the image of an encrypted, basic-compressed executable (as the runtime's disc::Unpack does) or
# of an uncompressed one; and the way back.

def be32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def xex_opt(xex, key):
    for i in range(be32(xex, 20)):
        if be32(xex, 24 + i * 8) == key:
            return be32(xex, 28 + i * 8)
    return None


def xex_header(xex):
    if xex[:4] != b"XEX2":
        raise ValueError("not an XEX2 file")
    return bytes(xex[:be32(xex, 8)])


def xex_session_key(xex):
    s = be32(xex, 16)
    return aes_cbc(RETAIL_KEY, xex[s + 0x150:s + 0x160])


def xex_unpack(xex):
    """The image of a XEX with basic or no compression, decrypted with the retail key when it's encrypted."""
    header_size, s = be32(xex, 8), be32(xex, 16)
    info = xex_opt(xex, 0x3FF)
    info_size = be32(xex, info)
    enc, comp = struct.unpack_from(">HH", xex, info + 4)
    payload = bytes(xex[header_size:])
    if enc == 1:
        payload = aes_cbc(xex_session_key(xex), payload)
    image_size = be32(xex, s + 4)
    if comp == 0:
        return payload[:image_size] + bytes(max(0, image_size - len(payload)))
    if comp != 1:
        raise ValueError(f"compression {comp} isn't handled")
    image = bytearray(image_size)
    src = dst = 0
    for i in range(info_size // 8 - 1):
        data, zeros = struct.unpack_from(">II", xex, info + 8 + i * 8)
        image[dst:dst + data] = payload[src:src + data]
        src += data
        dst += data + zeros
    return bytes(image)


def xex_pack(header, image, size):
    """The XEX file from its header and image, the inverse of xex_unpack for a file `size` bytes long (the payload's
    tail past its blocks is encrypted zeros)."""
    header_size = be32(header, 8)
    info = xex_opt(header, 0x3FF)
    info_size = be32(header, info)
    enc, comp = struct.unpack_from(">HH", header, info + 4)
    if comp == 0:
        payload = bytearray(image) + bytes(max(0, size - header_size - len(image)))
    elif comp == 1:
        payload = bytearray()
        pos = 0
        for i in range(info_size // 8 - 1):
            data, zeros = struct.unpack_from(">II", header, info + 8 + i * 8)
            payload += image[pos:pos + data]
            pos += data + zeros
        payload += bytes(size - header_size - len(payload))
    else:
        raise ValueError(f"compression {comp} isn't repacked")
    if enc == 1:
        payload = aes_cbc(xex_session_key(header), bytes(payload), encrypt=True)
    return bytes(header) + bytes(payload)


def pe_sections(image):
    """(name, virtual address, virtual size, characteristics) of an image's PE sections."""
    e = struct.unpack_from("<I", image, 0x3C)[0]
    n = struct.unpack_from("<H", image, e + 6)[0]
    opt = struct.unpack_from("<H", image, e + 20)[0]
    out = []
    for i in range(n):
        o = e + 24 + opt + i * 40
        name = image[o:o + 8].rstrip(b"\0").decode("latin-1")
        vsize, va = struct.unpack_from("<II", image, o + 8)
        flags = struct.unpack_from("<I", image, o + 36)[0]
        out.append((name, va, vsize, flags))
    return out


def merge_ranges(ranges):
    merged = []
    for a, b in sorted(ranges):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def code_ranges(image):
    """The image offsets of its executable sections (IMAGE_SCN_MEM_EXECUTE or CNT_CODE), merged."""
    ranges = sorted([va, min(len(image), va + vsize)] for name, va, vsize, flags in pe_sections(image)
                    if flags & 0x20000020 and va < len(image))
    merged = []
    for a, b in ranges:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return [tuple(r) for r in merged]


# ---------------------------------------------------------------------------------------------------------------------
# Discs, archives and fonts.

class Disc:
    def __init__(self, path):
        self.path = path
        self.f, self.base, rs, rsz = xdvdfs.open_volume(path)
        self.files = {}
        for p, is_dir, sector, length, _ in xdvdfs.walk(self.f, self.base, rs, rsz):
            if not is_dir:
                self.files[p.lower().lstrip("/")] = (self.base + sector * xdvdfs.SECTOR, length)

    def read(self, path):
        key = path.replace("\\", "/").lower().lstrip("/")
        if key not in self.files:
            raise FileNotFoundError(f"{path} isn't in {self.path}")
        start, size = self.files[key]
        self.f.seek(start)
        return self.f.read(size)


def afs_entries(data):
    """(offset, size) of each entry, and the name table's (offset, size)."""
    if data[:4] != b"AFS\0":
        raise ValueError("not an AFS archive")
    count = struct.unpack_from("<I", data, 4)[0]
    if 8 + count * 8 + 8 > len(data):
        raise ValueError("the AFS table doesn't fit")
    entries = [struct.unpack_from("<II", data, 8 + i * 8) for i in range(count)]
    return entries, struct.unpack_from("<II", data, 8 + count * 8)


def _tiled_offset(x, y, width):
    """A texel's byte offset in an 8-bit Xenos tiled 2D texture (UModel's and Xenia's formula)."""
    aligned = (width + 31) & ~31
    macro = ((x >> 5) + (y >> 5) * (aligned >> 5)) << 7
    micro = (x & 7) + ((y & 0xE) << 2)
    offset = macro + ((micro & ~0xF) << 1) + (micro & 0xF) + ((y & 1) << 4)
    return (((offset & ~0x1FF) << 3) + ((y & 16) << 7) + ((offset & 0x1C0) << 2) +
            (((((y & 8) >> 2) + (x >> 3)) & 3) << 6) + (offset & 0x3F))


_CELLS = None


def cell_offsets():
    """For each of a 1024x1024 8-bit tiled page's 1,024 cells of 32x32, its texels' byte offsets."""
    global _CELLS
    if _CELLS is None:
        _CELLS = [[_tiled_offset((c % 32) * 32 + x, (c // 32) * 32 + y, 1024) for y in range(32) for x in range(32)]
                  for c in range(1024)]
    return _CELLS


def xpr_textures(blob):
    """{index: (data offset in the package, width, height, format)} of an XPR2 package's textures."""
    if blob[:4] != b"XPR2":
        raise ValueError("not an XPR2 package")
    header_size, data_size, n = struct.unpack_from(">III", blob, 4)
    out = {}
    for k in range(n):
        kind, roff, rsize, _ = struct.unpack_from(">4sIII", blob, 16 + k * 16)
        if rsize < 24:
            continue
        f = struct.unpack_from(">6I", blob, 12 + roff + rsize - 24)
        out[k] = (12 + header_size + (f[1] & 0xFFFFF000), (f[2] & 0x1FFF) + 1, ((f[2] >> 13) & 0x1FFF) + 1, f[1] & 0x3F)
    return out


def font_table(image, image_base, address, pages):
    """{code point: (texture, cell)} and the textures, from a font's page table (16 bytes a page: texture, glyph
    count, size, the glyph list's address; a list is big-endian 16-bit code points)."""
    where, textures = {}, []
    for p in range(pages):
        tex, count, size, ptr = struct.unpack_from(">IIII", image, address - image_base + p * 16)
        if count > 1024:
            raise ValueError("a font page with more than 1,024 glyphs")
        textures.append(tex)
        for i, c in enumerate(struct.unpack_from(f">{count}H", image, ptr - image_base)):
            where.setdefault(c, (tex, i))
    return where, textures


def compose_font(source_xpr, source_where, target_where, target_textures):
    """The target's font pages, one after another (1 MB each, in the order its page table lists them), made of the
    source package's glyph cells by code point; glyphs the source lacks are blank. Returns them and the counts."""
    cells = cell_offsets()
    tex = xpr_textures(source_xpr)
    pages = {t: bytearray(0x100000) for t in target_textures}
    composed = blank = 0
    for c, (t, cell) in target_where.items():
        if c not in source_where:
            blank += 1
            continue
        st, sc = source_where[c]
        so = tex[st][0]
        page = pages[t]
        for a, b in zip(cells[sc], cells[cell]):
            page[b] = source_xpr[so + a]
        composed += 1
    return b"".join(bytes(pages[t]) for t in target_textures), composed, blank


# ---------------------------------------------------------------------------------------------------------------------
# Versions: where a version's files come from.

class Version:
    def __init__(self, disc=None, xex=None, pe=None):
        self.disc = Disc(disc) if disc else None
        self._xex = open(xex, "rb").read() if xex else None
        self._image = open(pe, "rb").read() if pe else None

    def xex(self):
        if self._xex is None:
            self._xex = self.disc.read("default.xex")
        return self._xex

    def image(self):
        if self._image is None:
            self._image = xex_unpack(self.xex())
        return self._image

    def image_base(self):
        o = xex_opt(self.xex(), 0x10201)
        return o if o is not None else 0x82000000

    def file(self, path):
        if path == "default.xex/header":
            return xex_header(self.xex())
        if path == "default.xex/image":
            return self.image()
        if not self.disc:
            raise FileNotFoundError(f"{path}: no disc image given")
        return self.disc.read(path)


def parse_args(args):
    opts = {"source": {}, "target": {}, "afs": [], "file": [], "font": [], "leave": [], "keep": [], "engine": "ops-lzma",
            "no_code": False, "no_fonts": False, "functions": None}
    rest = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--source-disc", "--target-disc"):
            opts[a[2:8]]["disc"] = args[i + 1]
            i += 2
        elif a in ("--source-xex", "--target-xex"):
            opts[a[2:8]]["xex"], opts[a[2:8]]["pe"] = args[i + 1], args[i + 2]
            i += 3
        elif a in ("--afs", "--file", "--font", "--leave", "--keep"):
            opts[a[2:]].append(args[i + 1])
            i += 2
        elif a in ("--engine", "--functions"):
            opts[a[2:]] = args[i + 1]
            i += 2
        elif a in ("--no-code", "--no-fonts"):
            opts[a[2:].replace("-", "_")] = True
            i += 1
        elif a.startswith("--"):
            sys.exit(f"unknown option {a}")
        else:
            rest.append(a)
            i += 1
    if opts["engine"] not in ENGINES:
        sys.exit(f"unknown engine {opts['engine']}")
    return opts, rest


def version(o):
    return Version(o.get("disc"), o.get("xex"), o.get("pe")) if o else None


# ---------------------------------------------------------------------------------------------------------------------
# Matching a target against a source: operations in target order.

WORD = 4
KEY = 8


def make_index(src):
    """Every 4-aligned 8-byte key of the source (its first place), but runs of one repeated word."""
    index = {}
    get = index.setdefault
    for i in range(0, len(src) - KEY + 1, WORD):
        k = src[i:i + KEY]
        if k[:4] != k[4:]:
            get(k, i)
    return index


def _exact(src, s, tgt, t, limit):
    """How many bytes agree from src[s:] and tgt[t:], at most `limit`."""
    n, step = 0, 4096
    while n < limit:
        m = min(step, limit - n)
        if src[s + n:s + n + m] == tgt[t + n:t + n + m]:
            n += m
        elif m <= 16:
            while n < limit and src[s + n] == tgt[t + n]:
                n += 1
            return n
        else:
            step = max(16, m // 8)
    return n


def _score(src, s, tgt, t, words):
    """How many of the next `words` words agree at this alignment (whole words; a word that differs in one byte, as
    a moved address does, counts half)."""
    if s < 0:
        return 0
    n = min(words, (len(tgt) - t) // WORD, (len(src) - s) // WORD)
    score = 0.0
    for i in range(0, n * WORD, WORD):
        a, b = src[s + i:s + i + WORD], tgt[t + i:t + i + WORD]
        if a == b:
            score += 1
        elif _same_bytes(a, b) == 3:
            score += 0.5
    return score


def _same_bytes(a, b):
    return (a[0] == b[0]) + (a[1] == b[1]) + (a[2] == b[2]) + (a[3] == b[3])


def _forward(src, s, tgt, t, limit):
    """Extends an alignment word by word while at least half the bytes of a 16-word window agree (moved addresses
    keep most of their bytes); the length up to its last word with an agreeing byte."""
    window, good, n, best = [], 0, 0, 0
    while n + WORD <= limit:
        a, b = src[s + n:s + n + WORD], tgt[t + n:t + n + WORD]
        if a == b:
            run = _exact(src, s + n, tgt, t + n, limit - n)
            run -= run % WORD
            n += run
            best = n
            window, good = [4] * 16, 64
            continue
        k = _same_bytes(a, b)
        window.append(k)
        good += k
        if len(window) > 16:
            good -= window.pop(0)
        n += WORD
        if k >= 2:
            best = n
        if len(window) >= 8 and good * 2 < len(window) * 4:
            break
    tail = limit - best
    if 0 < tail < WORD and src[s + best:s + best + tail] == tgt[t + best:t + best + tail]:
        best += tail
    return best


def _backward(src, s, tgt, t, limit):
    """The same backwards from (s, t), over at most `limit` bytes: how far back the alignment reaches."""
    window, good, n, best = [], 0, 0, 0
    while n + WORD <= limit and s - n - WORD >= 0:
        k = _same_bytes(src[s - n - WORD:s - n], tgt[t - n - WORD:t - n])
        window.append(k)
        good += k
        if len(window) > 16:
            good -= window.pop(0)
        n += WORD
        if k >= 2:
            best = n
        if len(window) >= 8 and good * 2 < len(window) * 4:
            break
    return best


def match(src, tgt, start=0, end=None, index=None):
    """(OP_ADD, source offset, length) and (OP_INSERT, 0, length) operations covering tgt[start:end]."""
    end = len(tgt) if end is None else end
    if index is None:
        index = make_index(src)
    ops, delta = [], None
    t = pending = start
    while t + KEY <= end:
        cands = []
        if delta is not None:
            cands.append(t + delta)
        hit = index.get(tgt[t:t + KEY])
        if hit is not None and hit not in cands:
            cands.append(hit)
        if hit is None:
            # The same bytes at another alignment (mod 4) in the source: packed data that moved by an odd amount.
            for k in (1, 2, 3):
                h = index.get(tgt[t + k:t + k + KEY]) if t + k + KEY <= end else None
                if h is not None and h - k >= 0 and h - k not in cands:
                    cands.append(h - k)
                    break
        best_s, best = None, 11
        for s in cands:
            if 0 <= s <= len(src) - WORD:
                sc = _score(src, s, tgt, t, 32)
                if sc > best:
                    best_s, best = s, sc
        if best_s is None:
            t += WORD
            continue
        s = best_s
        back = _backward(src, s, tgt, t, t - pending)
        fwd = _forward(src, s, tgt, t, min(end - t, len(src) - s))
        if fwd == 0:
            t += WORD
            continue
        if t - back > pending:
            ops.append((OP_INSERT, 0, t - back - pending))
        ops.append((OP_ADD, s - back, back + fwd))
        delta = s - t
        t = pending = t + fwd
    if pending < end:
        ops.append((OP_INSERT, 0, end - pending))
    return ops


def encode(src, tgt, ops):
    """The three streams of a piece from its operations (ops cover the whole target, OP_SKIP for unclaimed ranges):
    control (u8 op, i64 source seek from the previous source operation's end, u64 length), the ADD difference bytes
    (target - source, mod 256) and the INSERT bytes. An ADD whose difference is all zero is written as a COPY."""
    control, diff, extra = io.BytesIO(), bytearray(), bytearray()
    t = s_end = 0
    kinds = bytearray(len(tgt))  # per target byte: 0 copied, 1 added and the same, 2 added and changed, 3 inserted, 4 unclaimed
    for op, s, n in ops:
        if op == OP_SKIP:
            control.write(struct.pack("<BqQ", OP_SKIP, 0, n))
            kinds[t:t + n] = b"\4" * n
        elif op == OP_INSERT:
            control.write(struct.pack("<BqQ", OP_INSERT, 0, n))
            extra += tgt[t:t + n]
            kinds[t:t + n] = b"\3" * n
        else:
            a, b = src[s:s + n], tgt[t:t + n]
            if a == b:
                control.write(struct.pack("<BqQ", OP_COPY, s - s_end, n))
            else:
                d = bytes(((y - x) & 0xFF) for x, y in zip(a, b)) if n < 64 else _bytewise_sub(a, b)
                control.write(struct.pack("<BqQ", OP_ADD, s - s_end, n))
                diff += d
                kinds[t:t + n] = d.translate(_KIND_OF_DIFF)
            s_end = s + n
        t += n
    if t != len(tgt):
        raise AssertionError("the operations don't cover the target")
    return control.getvalue(), bytes(diff), bytes(extra), kinds


_KIND_OF_DIFF = bytes([1] + [2] * 255)  # an ADD's byte: 1 the same as the source's, 2 changed


def _bytewise_sub(a, b):
    """(b - a) mod 256 byte by byte, without carries, for long runs: through 16-bit lanes so that each byte's borrow
    stays in its lane's spare byte."""
    n = len(a)
    spread_a = bytearray(2 * n)
    spread_b = bytearray(2 * n)
    spread_a[0::2] = a
    spread_b[0::2] = b
    # Each lane: (b + 0x100 - a), whose low byte is the difference and whose high byte absorbs the borrow.
    high = bytearray(2 * n)
    high[1::2] = b"\1" * n
    x = int.from_bytes(spread_b, "little") + int.from_bytes(high, "little") - int.from_bytes(spread_a, "little")
    return x.to_bytes(2 * n, "little")[0::2]


def decode(src, size, control, diff, extra):
    """Applies a piece's streams to its source: the result (unclaimed bytes zero) and its extents, (target offset,
    length, source offset or None for the patch's bytes, or -1 for zeros)."""
    out = bytearray(size)
    extents = []
    t = s_end = di = ei = 0
    if len(control) % OP_SIZE:
        raise ValueError("the control stream isn't whole operations")
    for i in range(0, len(control), OP_SIZE):
        op, seek, n = struct.unpack_from("<BqQ", control, i)
        if n > size - t:
            raise ValueError("an operation writes past the piece's end")
        if op == OP_SKIP:
            extents.append((t, n, -1))
        elif op == OP_INSERT:
            if n > len(extra) - ei:
                raise ValueError("the insert stream is short")
            out[t:t + n] = extra[ei:ei + n]
            ei += n
            extents.append((t, n, None))
        elif op in (OP_COPY, OP_ADD):
            s = s_end + seek
            if s < 0 or n > len(src) - s:
                raise ValueError("an operation reads outside its source")
            if op == OP_COPY:
                out[t:t + n] = src[s:s + n]
                extents.append((t, n, s))
            else:
                if n > len(diff) - di:
                    raise ValueError("the difference stream is short")
                out[t:t + n] = _bytewise_add(src[s:s + n], diff[di:di + n])
                di += n
                extents.append((t, n, None))
            s_end = s + n
        else:
            raise ValueError(f"unknown operation {op}")
        t += n
    if t != size or di != len(diff) or ei != len(extra):
        raise ValueError("the streams don't add up to the piece")
    return out, extents


def _bytewise_add(a, d):
    n = len(a)
    if n < 64:
        return bytes((x + y) & 0xFF for x, y in zip(a, d))
    spread_a = bytearray(2 * n)
    spread_d = bytearray(2 * n)
    spread_a[0::2] = a
    spread_d[0::2] = d
    x = int.from_bytes(spread_a, "little") + int.from_bytes(spread_d, "little")
    return x.to_bytes(2 * n + 1, "little")[0:2 * n:2]


# ---------------------------------------------------------------------------------------------------------------------
# Pieces.

def font_spec(spec):
    afs, entry, st, sp, tt, tp = spec.split(":")
    return dict(afs=afs.replace("\\", "/").lower().lstrip("/"), entry=int(entry), source_table=(int(st, 16), int(sp)),
                target_table=(int(tt, 16), int(tp)))


def composed_pages(spec, archive, source_image, source_base, target_image, target_base):
    """A --font's composed pages, from the source archive's entry and the two images' page tables."""
    entries, _ = afs_entries(archive)
    o, n = entries[spec["entry"]]
    swhere, _ = font_table(source_image, source_base, *spec["source_table"])
    twhere, ttex = font_table(target_image, target_base, *spec["target_table"])
    return compose_font(archive[o:o + n], swhere, twhere, ttex)


def make_pieces(opts, source, target, log=print):
    """The pieces: each a dict of its name, source bytes, target bytes, unclaimed ranges and result (the target with
    its unclaimed ranges zero, or with --no-fonts its font pages composed)."""
    pieces = []
    sh, th = source.file("default.xex/header"), target.file("default.xex/header")
    pieces.append(dict(name="default.xex/header", source=sh, target=th, unclaimed=[]))
    si, ti = source.image(), target.image()
    unclaimed = code_ranges(ti) if opts["no_code"] else []
    for name, va, vsize, flags in pe_sections(ti):
        if name in opts["leave"] and va < len(ti):
            unclaimed.append((va, min(len(ti), va + vsize)))
    unclaimed = merge_ranges(unclaimed)
    pieces.append(dict(name="default.xex/image", source=si, target=ti, unclaimed=unclaimed, header=th,
                       image_base=target.image_base()))
    fonts = [font_spec(f) for f in opts["font"]]
    for path in opts["afs"]:
        sa, ta = source.file(path), target.file(path)
        piece = dict(name=path, source=sa, target=ta, unclaimed=[], afs=True, font=None)
        for spec in fonts:
            if spec["afs"] == path.replace("\\", "/").lower().lstrip("/"):
                blob, n, blank = composed_pages(spec, sa, si, source.image_base(), ti, target.image_base())
                log(f"{path} entry {spec['entry']}: {n:,} glyph cells composed from the source's, {blank:,} it lacks")
                piece["font"] = dict(spec, blob=blob, cells=n, blank=blank, mode=2 if opts["no_fonts"] else 1)
                if opts["no_fonts"]:
                    # The composed pages are the result: written over the target entry's pages.
                    te, _ = afs_entries(ta)
                    o, size = te[spec["entry"]]
                    entry = bytearray(ta[o:o + size])
                    tex = xpr_textures(bytes(entry))
                    _, ttex = font_table(ti, target.image_base(), *spec["target_table"])
                    for k, t in enumerate(ttex):
                        p = tex[t][0]
                        entry[p:p + 0x100000] = blob[k * 0x100000:(k + 1) * 0x100000]
                    piece["result"] = ta[:o] + bytes(entry) + ta[o + size:]
        keeps = [int(k.split(":")[1]) for k in opts["keep"]
                 if k.split(":")[0].replace("\\", "/").lower().lstrip("/") == path.replace("\\", "/").lower().lstrip("/")]
        if keeps:
            result = bytearray(piece.get("result", ta))
            se, _ = afs_entries(sa)
            te, _ = afs_entries(ta)
            piece["kept"] = []
            for k in keeps:
                (so, sn), (to, tn) = se[k], te[k]
                if sn != tn:
                    sys.exit(f"{path} entry {k}: {sn:,} bytes in the source, {tn:,} in the target; it can't be kept")
                result[to:to + tn] = sa[so:so + sn]
                piece["kept"].append((to, to + tn))
                log(f"{path} entry {k}: the source's kept")
            piece["result"] = bytes(result)
        pieces.append(piece)
    for path in opts["file"]:
        pieces.append(dict(name=path, source=source.file(path), target=target.file(path), unclaimed=[]))
    for p in pieces:
        if "result" not in p:
            t = bytearray(p["target"])
            for a, b in p["unclaimed"]:
                t[a:b] = bytes(b - a)
            p["result"] = bytes(t)
    return pieces


def _entry_cost(src, entry, ops):
    """The stored size (LZMA) of an entry's operations, ops in entry-relative target order with source offsets into
    `src`."""
    diff, extra, t = bytearray(), bytearray(), 0
    for op, s, n in ops:
        if op == OP_INSERT:
            extra += entry[t:t + n]
        elif src[s:s + n] != entry[t:t + n]:
            diff += _bytewise_sub(src[s:s + n], entry[t:t + n]) if n >= 64 else                 bytes((y - x) & 0xFF for x, y in zip(src[s:s + n], entry[t:t + n]))
        t += n
    return len(lzma_compress(bytes(diff))) + len(lzma_compress(bytes(extra))) + len(ops) * 4


def cheapest(src, entry, ops):
    """Of an entry's operations as matched, the same with ADD runs that change most of their bytes (unrelated
    pictures, say) turned into inserts, and the whole entry inserted, the one that stores smallest."""
    dense = []
    t = 0
    for op, s, n in ops:
        if op == OP_ADD and n >= 64:
            a, b = src[s:s + n], entry[t:t + n]
            same = sum(1 for i in range(0, n, 4) if a[i:i + 4] == b[i:i + 4])
            if same * 4 < n // 4:  # under a quarter of its words the same
                op, s = OP_INSERT, 0
        if dense and dense[-1][0] == OP_INSERT and op == OP_INSERT:
            dense[-1] = (OP_INSERT, 0, dense[-1][2] + n)
        else:
            dense.append((op, s, n))
        t += n
    options = [ops, dense, [(OP_INSERT, 0, len(entry))]]
    costs = [_entry_cost(src, entry, o) for o in options]
    return options[costs.index(min(costs))], costs


def piece_ops(piece, log=print):
    """The operations that make a piece's result from its source (for a font piece, its source followed by the
    composed pages)."""
    src, tgt = piece["source"], piece["result"]
    t0 = time.time()
    ops = []
    if piece.get("afs"):
        se, _ = afs_entries(src)
        te, tnames = afs_entries(tgt)
        by_hash = {}
        for o, n in se:
            by_hash.setdefault((sha256(src[o:o + n]), n), o)
        font = piece.get("font")
        regions = sorted([(o, n, i) for i, (o, n) in enumerate(te)] + [(tnames[0], tnames[1], -1)])
        pos = 0
        for o, n, i in regions:
            if o < pos:
                raise ValueError(f"{piece['name']}: overlapping entries")
            if o > pos:
                ops.append((OP_INSERT, 0, o - pos))  # the table and the padding between entries
            pos = o + n
            if n == 0:
                continue
            entry = tgt[o:o + n]
            same = by_hash.get((sha256(entry), n))
            if same is not None:
                ops.append((OP_ADD, same, n))
                continue
            if font and i == font["entry"]:
                # Matched against the composed pages first, then the source's entry: a glyph's tile pieces occur in
                # both, and the composed pages hold them where the target does.
                so, sn = se[i]
                blob = font["blob"]
                sub_src = blob + src[so:so + sn]
                sub, costs = cheapest(sub_src, entry, match(sub_src, entry))
                log(f"  {piece['name']} entry {i}: stored as matched {costs[0]:,}, dense runs inserted {costs[1]:,}, "
                    f"inserted whole {costs[2]:,}")
                for op, s, k in sub:
                    if op == OP_INSERT:
                        ops.append((op, 0, k))
                        continue
                    # Offsets in the composed pages map past the archive (the applier appends them to it), those in
                    # the entry's own bytes to the archive.
                    while k:
                        if s < len(blob):
                            m = min(k, len(blob) - s)
                            ops.append((OP_ADD, len(src) + s, m))
                        else:
                            m = k
                            ops.append((OP_ADD, so + s - len(blob), m))
                        s += m
                        k -= m
            elif 0 <= i < len(se):
                so, sn = se[i]
                sub, costs = cheapest(src[so:so + sn], entry, match(src[so:so + sn], entry))
                log(f"  {piece['name']} entry {i}: stored as matched {costs[0]:,}, dense runs inserted {costs[1]:,}, "
                    f"inserted whole {costs[2]:,}")
                ops += [(op, s + so if op == OP_ADD else 0, k) for op, s, k in sub]
            else:
                ops.append((OP_INSERT, 0, n))
        if pos < len(tgt):
            ops.append((OP_INSERT, 0, len(tgt) - pos))
        source = src + (font["blob"] if font else b"")
    else:
        index = make_index(src)
        pos = 0
        for a, b in sorted(piece["unclaimed"]) + [(len(tgt), len(tgt))]:
            if a > pos:
                ops += match(src, tgt, pos, a, index)
            if b > a:
                ops.append((OP_SKIP, 0, b - a))
            pos = max(pos, b)
        source = src
    log(f"  {piece['name']}: {len(ops):,} operations in {time.time() - t0:.1f} s")
    return source, ops


# ---------------------------------------------------------------------------------------------------------------------
# The patch file. Little-endian: "VPAT", version, piece count, the target default.xex's file size; then each piece:
# its name; its source's size and SHA-256; its result's size and SHA-256 and the full target's SHA-256; its unclaimed
# ranges (count, then offset and length each); its kept ranges (the same: where the result holds the source's bytes
# instead of the target's, by --keep); the engine; a font composition (mode: 0 none, 1 the composed pages
# patched into the target's, 2 the composed pages as the result; the entry; the source table's address and pages; the
# target table's); its streams (count, then each one's stored and uncompressed sizes and its bytes).

def _str(s):
    b = s.encode("utf-8")
    return struct.pack("<H", len(b)) + b


def write_patch(path, entries, xex_size):
    out = io.BytesIO()
    out.write(MAGIC + struct.pack("<IIQ", VERSION, len(entries), xex_size))
    for e in entries:
        out.write(_str(e["name"]))
        out.write(struct.pack("<Q", e["source_size"]) + e["source_sha"])
        out.write(struct.pack("<Q", e["result_size"]) + e["result_sha"] + e["target_sha"])
        for ranges in (e["unclaimed"], e["kept"]):
            out.write(struct.pack("<I", len(ranges)))
            for a, b in ranges:
                out.write(struct.pack("<QQ", a, b - a))
        out.write(struct.pack("<I", ENGINES[e["engine"]]))
        f = e.get("font")
        out.write(struct.pack("<IIIIII", f["mode"], f["entry"], *f["source_table"], *f["target_table"]) if f
                  else bytes(24))
        out.write(struct.pack("<I", len(e["streams"])))
        for raw_size, stored in e["streams"]:
            out.write(struct.pack("<QQ", len(stored), raw_size))
            out.write(stored)
    data = out.getvalue()
    with open(path, "wb") as f:
        f.write(data)
    return len(data)


def read_patch(path):
    data = open(path, "rb").read()
    if data[:4] != MAGIC:
        raise ValueError("not a version patch")
    ver, count, xex_size = struct.unpack_from("<IIQ", data, 4)
    if ver != VERSION:
        raise ValueError(f"patch version {ver} isn't handled")
    p = 20

    def take(n):
        nonlocal p
        if n > len(data) - p:
            raise ValueError("the patch is truncated")
        p += n
        return data[p - n:p]

    entries = []
    for _ in range(count):
        e = {"name": take(struct.unpack("<H", take(2))[0]).decode("utf-8")}
        e["source_size"], e["source_sha"] = struct.unpack("<Q", take(8))[0], take(32)
        e["result_size"], e["result_sha"], e["target_sha"] = struct.unpack("<Q", take(8))[0], take(32), take(32)
        for key in ("unclaimed", "kept"):
            e[key] = []
            for _ in range(struct.unpack("<I", take(4))[0]):
                a, n = struct.unpack("<QQ", take(16))
                if a + n > e["result_size"]:
                    raise ValueError("a range past the piece's end")
                e[key].append((a, a + n))
        e["engine"] = ENGINE_NAMES.get(struct.unpack("<I", take(4))[0])
        if not e["engine"]:
            raise ValueError("unknown engine")
        mode, entry, sa, sp, ta, tp = struct.unpack("<IIIIII", take(24))
        if mode > 2:
            raise ValueError("unknown font mode")
        e["font"] = dict(mode=mode, entry=entry, source_table=(sa, sp), target_table=(ta, tp)) if mode else None
        e["streams"] = []
        for _ in range(struct.unpack("<I", take(4))[0]):
            stored, raw = struct.unpack("<QQ", take(16))
            e["streams"].append((raw, take(stored)))
        entries.append(e)
    if p != len(data):
        raise ValueError("trailing bytes after the last piece")
    return entries, len(data), xex_size


def piece_entry(piece, source, ops, engine, log=print):
    control, diff, extra, kinds = encode(source, piece["result"], ops)
    if engine == "msdelta" and piece.get("afs"):
        log(f"  {piece['name']}: an archive is patched entry by entry, with ops-lzma (compare gives msdelta's size)")
        engine = "ops-lzma"
    if engine == "msdelta":
        streams = [(len(piece["result"]), msdelta_create(piece["source"], piece["result"]))]
    else:
        streams = [(len(s), compress_stream(engine, s)) for s in (control, diff, extra)]
    f = piece.get("font")
    return dict(name=piece["name"], source_size=len(piece["source"]), source_sha=sha256(piece["source"]),
                result_size=len(piece["result"]), result_sha=sha256(piece["result"]), target_sha=sha256(piece["target"]),
                unclaimed=piece["unclaimed"], kept=piece.get("kept", []), engine=engine, streams=streams,
                font=dict(mode=f["mode"], entry=f["entry"], source_table=f["source_table"],
                          target_table=f["target_table"]) if f else None,
                raw=(control, diff, extra), kinds=kinds)


# ---------------------------------------------------------------------------------------------------------------------
# Applying.

def apply_entries(entries, source, log=print):
    """Each piece's result from the source version (checked before and after), in the patch's order: the header and
    the image come first, since a font composition reads the target image's glyph tables. {name: (result, extents)}"""
    results = {}
    for e in entries:
        src = source.file(e["name"])
        if len(src) != e["source_size"] or sha256(src) != e["source_sha"]:
            raise ValueError(f"{e['name']}: the source isn't the one this patch was made for")
        if e["engine"] == "msdelta":
            out = bytearray(msdelta_apply(src, e["streams"][0][1]))
            extents = [(0, len(out), None)]
        else:
            control, diff, extra = (decompress_stream(e["engine"], s, n) for n, s in e["streams"])
            if e["font"]:
                theader, timage = results["default.xex/header"][0], results["default.xex/image"][0]
                tbase = xex_opt(theader, 0x10201) or 0x82000000
                blob, _, _ = composed_pages(e["font"], src, source.image(), source.image_base(), timage, tbase)
                src = src + blob
            out, extents = decode(src, e["result_size"], control, diff, extra)
        if sha256(bytes(out)) != e["result_sha"]:
            raise ValueError(f"{e['name']}: the result isn't the one this patch was made for")
        results[e["name"]] = (bytes(out), extents)
        unclaimed = sum(b - a for a, b in e["unclaimed"])
        log(f"  {e['name']}: {len(out):,} bytes, SHA-256 {e['result_sha'].hex()[:16]}..., "
            + ("the target's" if e["result_sha"] == e["target_sha"] else
               f"the target's but for {unclaimed:,} unclaimed bytes" if unclaimed else "the composed font pages"))
    return results


# ---------------------------------------------------------------------------------------------------------------------
# What a piece's result is made of.

def _texty(c):
    """A UTF-16 character a game's text would hold: printable ASCII, Latin-1, general punctuation, Greek and Cyrillic,
    kana and CJK, Hangul, fullwidth forms."""
    return (0x20 <= c < 0x7F or c in (9, 10, 13) or 0xA0 <= c < 0x180 or 0x370 <= c < 0x530 or 0x2000 <= c < 0x2070 or
            0x3000 <= c < 0x3100 or 0x4E00 <= c < 0xA000 or 0xAC00 <= c < 0xD7A4 or 0xFF00 <= c < 0xFFF0)


def text_bytes(data, start=0, end=None):
    """How many of data[start:end]'s bytes are strings: NUL-terminated printable ASCII of at least 4 characters, or
    0-terminated big-endian UTF-16 of at least 3 characters a game's text would hold (an estimate: binary data rarely
    passes both tests)."""
    n = len(data) if end is None else end
    count, i = 0, start
    while i < n:
        j = i
        while j < n and (32 <= data[j] < 127 or data[j] in (9, 10, 13)):
            j += 1
        if j - i >= 4 and (j == n or data[j] == 0):
            count += j - i + (j < n)
            i = j + 1
            continue
        if i % 2 == 0:
            j = i
            while j + 1 < n and _texty((data[j] << 8) | data[j + 1]):
                j += 2
            if j - i >= 6 and (j + 1 >= n or (data[j] == 0 and data[j + 1] == 0)):
                count += j - i + 2 * (j + 1 < n)
                i = j + 2
                continue
        i += 1
    return min(count, n - start)


def regions_of(piece):
    """(start, end, label) of the places worth telling apart in a piece's target."""
    name, target = piece["name"], piece["target"]
    if name == "default.xex/image":
        # The XEX's resources (the title's SPA data) first: the image holds them where the PE's last sections (.idata,
        # .XBLD, .reloc, which the XEX's loader doesn't keep) would be.
        out = []
        header, base = piece["header"], piece["image_base"]
        r = xex_opt(header, 0x2FF)
        if r is not None:
            for k in range((be32(header, r) - 4) // 16):
                e = r + 4 + k * 16
                label = header[e:e + 8].rstrip(b"\0").decode("latin-1")
                a = be32(header, e + 8) - base
                out.append((a, min(len(target), a + be32(header, e + 12)), f"resource {label}"))
        for sname, va, vsize, flags in pe_sections(target):
            b = min(len(target), va + vsize)
            if va < len(target) and not any(a < b and va < e for a, e, _ in out):
                out.append((va, b, sname + (" (code)" if flags & 0x20000020 else "")))
        return sorted(out)
    if name == "default.xex/header":
        s = be32(target, 16)
        pages = be32(target, s + 0x180)
        return [(0, s, "optional header table"), (s, s + 0x184, "security info (signature, keys, digests)"),
                (s + 0x184, s + 0x184 + pages * 24, "page descriptors (a SHA-1 per page)"),
                (s + 0x184 + pages * 24, len(target), "optional headers' data")]
    if piece.get("afs"):
        te, tn = afs_entries(target)
        out = [(0, min([o for o, n in te if n] or [len(target)]), "table and padding")]
        out += [(o, o + n, f"entry {i}") for i, (o, n) in enumerate(te) if n]
        out.append((tn[0], tn[0] + tn[1], "name table"))
        return out
    return [(0, len(target), "file")]


def report(piece, entry, log=print):
    kinds = entry["kinds"]
    counts = [kinds.count(k) for k in range(5)]
    control, diff, extra = entry["raw"]
    stored = [len(s) for _, s in entry["streams"]]
    log(f"{piece['name']}: {len(kinds):,} bytes: copied {counts[0]:,}, in ADD runs {counts[1] + counts[2]:,} "
        f"({counts[2]:,} changed), inserted {counts[3]:,}, unclaimed {counts[4]:,}")
    if entry["engine"] == "msdelta":
        log(f"  stored: msdelta {stored[0]:,} bytes")
    else:
        log(f"  streams: control {len(control):,} ({len(control) // OP_SIZE:,} operations), difference {len(diff):,}, "
            f"insert {len(extra):,}; stored ({entry['engine']}) {stored[0]:,} + {stored[1]:,} + {stored[2]:,} = "
            f"{sum(stored):,} bytes")
    result = piece["result"]
    if piece.get("afs") and entry["engine"] != "msdelta":
        # Each region's own share of the difference and insert streams, compressed alone (their sum is somewhat more
        # than the streams compressed together).
        di = ei = 0
        offsets = []
        pos = 0
        for i in range(0, len(control), OP_SIZE):
            op, seek, n = struct.unpack_from("<BqQ", control, i)
            offsets.append((pos, n, op, di, ei))
            if op == OP_ADD:
                di += n
            elif op == OP_INSERT:
                ei += n
            pos += n
        costs = {}
        for a, b, label in regions_of(piece):
            d = bytearray()
            x = bytearray()
            for t, n, op, dpos, epos in offsets:
                lo, hi = max(a, t), min(b, t + n)
                if lo >= hi:
                    continue
                if op == OP_ADD:
                    d += diff[dpos + lo - t:dpos + hi - t]
                elif op == OP_INSERT:
                    x += extra[epos + lo - t:epos + hi - t]
            if d.count(0) != len(d) or x:
                costs[label] = (len(lzma_compress(bytes(d))) if d.count(0) != len(d) else 0, len(lzma_compress(bytes(x))))
        entry["costs"] = costs
    for a, b, label in regions_of(piece):
        seg = kinds[a:b]
        changed, inserted = seg.count(2), seg.count(3)
        if not (changed or inserted):
            continue
        # The inserted bytes that are text (in the executable's pieces; an archive's are mostly pictures).
        text = 0
        i = a if not piece.get("afs") else b
        while i < b:
            if kinds[i] != 3:
                i += 1
                continue
            j = i
            while j < b and kinds[j] == 3:
                j += 1
            text += text_bytes(result, i, j)
            i = j
        found = elsewhere(piece, kinds, a, b) if len(piece["source"]) < (64 << 20) else 0
        cost = entry.get("costs", {}).get(label)
        log(f"  {label:48} changed {changed:>10,}  inserted {inserted:>10,}  ("
            + ("" if piece.get("afs") else f"text {text:,}; ")
            + f"{found:,} of the inserted found elsewhere in the source)"
            + (f"; stored alone {cost[0]:,} + {cost[1]:,}" if cost else ""))
    return counts


_KEYSETS = {}


def elsewhere(piece, kinds, a, b):
    """How many inserted bytes in [a, b) lie in 8-byte aligned words that also occur, 4-aligned, anywhere in the
    piece's source: rearranged rather than new (an estimate; zero words don't count as found)."""
    src = piece["source"]
    keys = _KEYSETS.get(id(src))
    if keys is None:
        keys = {src[i:i + 8] for i in range(0, len(src) - 7, 4)}
        _KEYSETS.clear()
        _KEYSETS[id(src)] = keys
    tgt = piece["result"]
    found = 0
    for i in range(a - a % 4, b, 4):
        if kinds[i:i + 4] == b"" and i + 8 <= len(tgt):
            w = tgt[i:i + 8]
            if w != bytes(8) and w in keys:
                found += 4
    return found


def code_split(piece, kinds, functions_tsv, image_base, log=print):
    """The image's code bytes the patch carries, by the kind of function they're in: buildcompare.py match's TSV
    (target side, the second build) says which functions have the same code in both builds (their changed bytes are
    moved addresses) and which changed or are new."""
    sums = {}
    with open(functions_tsv, encoding="utf-8") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 5 or not p[2].startswith("0x"):
                continue
            o, n, status = int(p[2], 16) - image_base, int(p[3], 0), p[4]
            if not (0 <= o < len(kinds)):
                continue
            seg = kinds[o:o + n]
            c = sums.setdefault(status, [0, 0, 0, 0])
            c[0] += 1
            c[1] += len(seg)
            c[2] += seg.count(2)
            c[3] += seg.count(3)
    for status, (count, n, changed, inserted) in sorted(sums.items()):
        log(f"  code in {count:,} '{status}' functions or gaps ({n:,} bytes): changed {changed:,}, inserted {inserted:,}")
    return sums


# ---------------------------------------------------------------------------------------------------------------------
# Commands.

def cmd_build(out, opts):
    source, target = version(opts["source"]), version(opts["target"])
    if not source or not target:
        sys.exit("build needs a source and a target version")
    pieces = make_pieces(opts, source, target)
    entries = []
    for piece in pieces:
        src, ops = piece_ops(piece)
        entry = piece_entry(piece, src, ops, opts["engine"])
        report(piece, entry)
        if piece["name"] == "default.xex/image" and opts["functions"]:
            code_split(piece, entry["kinds"], opts["functions"], target.image_base())
        if piece.get("font"):
            log_font(piece, entry, target)
        entries.append(entry)
    size = write_patch(out, entries, len(target.xex()) if target.disc else 0)
    print(f"wrote {out}: {size:,} bytes, {len(entries)} pieces")
    # Check it at once: the patch file applied to the source gives every piece's result.
    read, _, _ = read_patch(out)
    results = apply_entries(read, source, log=lambda *a: None)
    for piece in pieces:
        if results[piece["name"]][0] != piece["result"]:
            sys.exit(f"{piece['name']}: the patch doesn't reproduce its result")
    print("checked: the patch file applied to the source gives every piece's result")


def log_font(piece, entry, target, log=print):
    """A font entry's pages: how many of their bytes the patch carries."""
    f = piece["font"]
    te, _ = afs_entries(piece["target"])
    o, n = te[f["entry"]]
    tex = xpr_textures(piece["target"][o:o + n])
    _, ttex = font_table(target.image(), target.image_base(), *f["target_table"])
    kinds = entry["kinds"]
    pages = sum(kinds[o + tex[t][0]:o + tex[t][0] + 0x100000].count(2) + kinds[o + tex[t][0]:o + tex[t][0] + 0x100000].count(3)
                for t in ttex)
    log(f"  font pages ({len(ttex)} of 1 MB): {f['cells']:,} glyph cells composed from the source's, {f['blank']:,} it "
        f"lacks; the patch's bytes in them {pages:,}")


def cmd_compare(opts):
    source, target = version(opts["source"]), version(opts["target"])
    pieces = make_pieces(opts, source, target)
    try:
        from compression import zstd
    except ImportError:
        zstd = None

    def zstd_patch(src, tgt):
        if not zstd or not tgt:
            return 0
        d = zstd.ZstdDict(src, is_raw=True)
        wlog = max(20, min(30, (len(src) + len(tgt)).bit_length()))
        options = {zstd.CompressionParameter.window_log: wlog,
                   zstd.CompressionParameter.enable_long_distance_matching: 1,
                   zstd.CompressionParameter.compression_level: 19}
        return len(zstd.compress(tgt, options=options, zstd_dict=d.as_prefix))

    cols = ["ops-lzma", "ops-lzms", "ops-raw", "ops-deflate", "msdelta", "zstd-patch", "lzma alone"]
    print(f"{'piece':26} " + " ".join(f"{c:>12}" for c in cols))
    totals = [0] * len(cols)
    for piece in pieces:
        src, ops = piece_ops(piece, log=lambda *a: None)
        control, diff, extra, kinds = encode(src, piece["result"], ops)
        raw = len(control) + len(diff) + len(extra)
        lm = sum(len(lzma_compress(s)) for s in (control, diff, extra))
        lz = sum(len(lzms_compress(s)) for s in (control, diff, extra))
        df = sum(len(zlib.compress(s, 9)) for s in (control, diff, extra))
        if piece.get("afs"):
            # msdelta and zstd entry by entry against the source's entry of the same index (or the composed pages),
            # the rest (tables) as they are.
            se, _ = afs_entries(piece["source"])
            te, tn = afs_entries(piece["result"])
            md = zs = 0
            same = {sha256(piece["source"][o:o + n]) for o, n in se}
            covered = 0
            for i, (o, n) in enumerate(te):
                tgt = piece["result"][o:o + n]
                covered += n
                if not n or sha256(tgt) in same:
                    continue
                so, sn = se[i] if i < len(se) else (0, 0)
                s = piece["source"][so:so + sn]
                if piece.get("font") and i == piece["font"]["entry"]:
                    s = s + piece["font"]["blob"]
                md += len(msdelta_create(s, tgt))
                zs += zstd_patch(s, tgt)
            tables = len(piece["result"]) - covered - tn[1]
            md += len(lzma_compress(piece["result"][:te[0][0]])) + len(lzma_compress(piece["result"][tn[0]:tn[0] + tn[1]]))
            zs += len(lzma_compress(piece["result"][:te[0][0]])) + len(lzma_compress(piece["result"][tn[0]:tn[0] + tn[1]]))
            whole = 0
        else:
            md = len(msdelta_create(piece["source"], piece["result"]))
            zs = zstd_patch(piece["source"], piece["result"])
            whole = len(lzma_compress(piece["result"]))
        row = [lm, lz, raw, df, md, zs, whole]
        totals = [a + b for a, b in zip(totals, row)]
        print(f"{piece['name']:26} " + " ".join(f"{v:>12,}" for v in row), flush=True)
    print(f"{'total':26} " + " ".join(f"{v:>12,}" for v in totals))


def cmd_apply(path, opts, out_dir):
    source = version(opts["source"])
    entries, size, xex_size = read_patch(path)
    if os.path.exists(out_dir) and os.listdir(out_dir):
        sys.exit(f"{out_dir} must be new or empty")
    os.makedirs(out_dir, exist_ok=True)
    print(f"{path}: {size:,} bytes, {len(entries)} pieces")
    results = apply_entries(entries, source)
    header, image = results["default.xex/header"][0], results["default.xex/image"][0]
    with open(os.path.join(out_dir, "default.pe"), "wb") as f:
        f.write(image)
    exact = all(e["result_sha"] == e["target_sha"] for e in entries if e["name"].startswith("default.xex/"))
    comp = struct.unpack_from(">HH", header, xex_opt(header, 0x3FF) + 4)[1]
    if exact and xex_size and comp == 1:
        # The target's own default.xex: the image compressed and encrypted as its header says.
        xex = xex_pack(header, image, xex_size)
        what = "the target's file, repacked"
    elif exact and comp == 0:
        xex = header + image
        what = "the target's header and image (uncompressed)"
    else:
        xex = header  # all the runtime reads of a development data directory's default.xex
        what = "the target's header alone (the image has unclaimed ranges)"
    with open(os.path.join(out_dir, "default.xex"), "wb") as f:
        f.write(xex)
    print(f"  default.xex: {len(xex):,} bytes, {what}, SHA-256 {hashlib.sha256(xex).hexdigest()}")
    for e in entries:
        if e["name"].startswith("default.xex/"):
            continue
        data, extents = results[e["name"]]
        out = os.path.join(out_dir, *e["name"].replace("\\", "/").split("/"))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as f:
            f.write(data)
        merged = []
        for t, n, s in extents:
            last = merged[-1] if merged else None
            if last and last[0] + last[1] == t and ((s is None and last[2] is None) or
                                                   (s is not None and s >= 0 and last[2] is not None and
                                                    last[2] >= 0 and last[2] + last[1] == s)):
                merged[-1] = (last[0], last[1] + n, last[2])
            else:
                merged.append((t, n, s))
        size = e["source_size"]
        from_source = sum(n for t, n, s in merged if s is not None and 0 <= s < size)
        composed = sum(n for t, n, s in merged if s is not None and s >= size)
        with open(out + ".extents.txt", "w", encoding="utf-8") as f:
            f.write(f"# {e['name']}: {len(data):,} bytes: {from_source:,} from the source's file, {composed:,} composed "
                    f"(font pages from the source's glyphs), {len(data) - from_source - composed:,} made with the patch's "
                    f"bytes. Target offset, length, and the source file's offset, 'composed' or 'patch'\n")
            for t, n, s in merged:
                where = ("patch" if s is None else "zero" if s < 0 else
                         f"composed +0x{s - size:X}" if s >= size else f"0x{s:09X}")
                f.write(f"0x{t:09X} 0x{n:09X} {where}\n")
        print(f"  {e['name']}: {len(data):,} bytes in {len(merged)} extents: {from_source:,} from the source's file, "
              f"{composed:,} composed, {len(data) - from_source - composed:,} made with the patch's bytes")


def cmd_verify(path, opts):
    """Applies the patch to the source version in memory and compares every byte of each result with the target
    version's: the bytes that differ must all lie in ranges the patch says differ (unclaimed: zero; kept: the
    source's entry; composed font pages), and outside them every byte must be the target's."""
    source, target = version(opts["source"]), version(opts["target"])
    entries, size, xex_size = read_patch(path)
    print(f"{path}: {size:,} bytes, {len(entries)} pieces")
    results = apply_entries(entries, source)
    ok = True
    for e in entries:
        data, _ = results[e["name"]]
        want = target.file(e["name"])
        if len(data) != len(want):
            print(f"  {e['name']}: {len(data):,} bytes, the target's {len(want):,}")
            ok = False
            continue
        # Where the result may differ, by why: 1 unclaimed, 2 kept, 3 composed font pages.
        why = bytearray(len(want))
        for a, b in e["unclaimed"]:
            why[a:b] = b"\1" * (b - a)
        for a, b in e["kept"]:
            why[a:b] = b"\2" * (b - a)
        if e["font"] and e["font"]["mode"] == 2:
            te, _ = afs_entries(want)
            o, n = te[e["font"]["entry"]]
            tex = xpr_textures(want[o:o + n])
            _, ttex = font_table(results["default.xex/image"][0], target.image_base(), *e["font"]["target_table"])
            for t in ttex:
                why[o + tex[t][0]:o + tex[t][0] + 0x100000] = b"\3" * 0x100000
        differ = [0, 0, 0, 0]
        if data != want:
            # Compare in blocks; only blocks that differ are walked byte by byte.
            for start in range(0, len(want), 1 << 16):
                a, b = data[start:start + (1 << 16)], want[start:start + (1 << 16)]
                if a != b:
                    for i, (x, y) in enumerate(zip(a, b)):
                        if x != y:
                            differ[why[start + i]] += 1
        allowed = [why.count(k) for k in range(4)]
        line = f"  {e['name']}: " + ("every byte is the target's" if not any(differ) else
                                     "every byte the patch claims is the target's" if not differ[0] else
                                     f"{differ[0]:,} bytes the patch claims DIFFER from the target's")
        notes = []
        if allowed[1]:
            notes.append(f"{allowed[1]:,} unclaimed (zero), {differ[1]:,} of them differ")
        if allowed[2]:
            notes.append(f"{allowed[2]:,} kept from the source, {differ[2]:,} of them differ")
        if allowed[3]:
            notes.append(f"{allowed[3]:,} in composed font pages, {differ[3]:,} of them differ (glyphs the source drew "
                         f"differently or lacks)")
        print(line + (f" ({'; '.join(notes)})" if notes else ""))
        ok = ok and not differ[0]
    if all(e["result_sha"] == e["target_sha"] for e in entries if e["name"].startswith("default.xex/")) and xex_size:
        header, image = results["default.xex/header"][0], results["default.xex/image"][0]
        if struct.unpack_from(">HH", header, xex_opt(header, 0x3FF) + 4)[1] == 1:
            xex = xex_pack(header, image, xex_size)
            same = xex == target.xex()
            print(f"  default.xex, repacked from them: {'the target file byte for byte' if same else 'DIFFERS'} "
                  f"(SHA-256 {hashlib.sha256(xex).hexdigest()})")
            ok = ok and same
    print("verified" if ok else "MISMATCH")
    if not ok:
        sys.exit(1)


def cmd_info(path):
    entries, size, xex_size = read_patch(path)
    print(f"{path}: {size:,} bytes, version {VERSION}, {len(entries)} pieces"
          + (f", the target default.xex {xex_size:,} bytes" if xex_size else ""))
    for e in entries:
        stored = sum(len(s) for _, s in e["streams"])
        raw = sum(n for n, _ in e["streams"])
        unclaimed = sum(b - a for a, b in e["unclaimed"])
        print(f"  {e['name']:22} {e['engine']:8} stored {stored:>10,} (streams {raw:,}); source {e['source_size']:,} "
              f"bytes {e['source_sha'].hex()[:16]}..., result {e['result_size']:,} {e['result_sha'].hex()[:16]}..."
              + (f", {unclaimed:,} unclaimed in {len(e['unclaimed'])} ranges" if unclaimed else "")
              + (f", {sum(b - a for a, b in e['kept']):,} kept from the source in {len(e['kept'])} ranges"
                 if e["kept"] else "")
              + (f", font entry {e['font']['entry']} ({'composed' if e['font']['mode'] == 2 else 'exact'})"
                 if e["font"] else ""))


def cmd_seeds(out_dir):
    """Made-up patches for the patch reader's fuzz harness (tools\\versionpatch_fuzz) to start from: pseudo-random
    sources and results made of them, with every operation, unclaimed and kept ranges, a font record and empty
    streams."""
    rng = random.Random(4)

    def noise(n):
        return bytes(rng.randrange(256) for _ in range(n))

    def piece(name, source, spec, kept=(), font=None):
        """A piece of `source` made by (operation, source offset, length) in result order."""
        result, unclaimed = bytearray(), []
        for op, at, n in spec:
            if op == OP_COPY:
                result += source[at:at + n]
            elif op == OP_ADD:
                result += bytes((b + (i % 7 == 0) * rng.randrange(1, 9)) & 0xFF for i, b in enumerate(source[at:at + n]))
            elif op == OP_INSERT:
                result += noise(n)
            else:
                unclaimed.append((len(result), len(result) + n))
                result += bytes(n)
        control, diff, extra, _ = encode(source, bytes(result), spec)
        return dict(name=name, source_size=len(source), source_sha=sha256(source), result_size=len(result),
                    result_sha=sha256(bytes(result)), target_sha=sha256(bytes(result)), unclaimed=unclaimed,
                    kept=list(kept), engine="ops-lzma", font=font,
                    streams=[(len(x), lzma_compress(x)) for x in (control, diff, extra)])

    source = noise(4096)
    seeds = {
        "one_piece": [piece("data/file.bin", source, [(OP_COPY, 100, 500), (OP_ADD, 700, 300), (OP_INSERT, 0, 64),
                                                      (OP_SKIP, 0, 128), (OP_COPY, 50, 200), (OP_ADD, 3000, 900)])],
        "executable": [piece("default.xex/header", source[:512], [(OP_ADD, 0, 512), (OP_INSERT, 0, 32)]),
                       piece("default.xex/image", source, [(OP_COPY, 0, 1024), (OP_SKIP, 0, 2048), (OP_ADD, 3072, 1024),
                                                          (OP_INSERT, 0, 100)])],
        "font": [piece("spr.afs", source, [(OP_COPY, 0, 2048), (OP_ADD, 2048, 1024), (OP_COPY, 3072, 1024)],
                       kept=[(0, 256)], font=dict(mode=2, entry=1, source_table=(0x82C5AE90, 4),
                                                  target_table=(0x82C6D8B8, 9)))],
        "copies": [piece("movie.sfd", source, [(OP_COPY, 0, 4096), (OP_COPY, 1000, 96)])],
    }
    os.makedirs(out_dir, exist_ok=True)
    for name, entries in seeds.items():
        write_patch(os.path.join(out_dir, f"seed_{name}.vpatch"), entries, 0)
    print(f"wrote {len(seeds)} seeds to {out_dir}")


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("build", "compare", "apply", "verify", "info", "seeds"):
        sys.exit(__doc__)
    cmd = sys.argv[1]
    opts, rest = parse_args(sys.argv[2:])
    if cmd == "build" and len(rest) == 1:
        cmd_build(rest[0], opts)
    elif cmd == "compare" and not rest:
        cmd_compare(opts)
    elif cmd == "apply" and len(rest) == 2:
        cmd_apply(rest[0], opts, rest[1])
    elif cmd == "verify" and len(rest) == 1:
        cmd_verify(rest[0], opts)
    elif cmd == "info" and len(rest) == 1:
        cmd_info(rest[0])
    elif cmd == "seeds" and len(rest) == 1:
        cmd_seeds(rest[0])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
