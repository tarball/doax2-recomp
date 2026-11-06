"""Writes the PE image of an uncompressed, unencrypted XEX (as tools\\patchxex writes one) and checks an image against
a XEX header's page descriptors.

Usage: python -I xexpe.py <in.xex> [<out.pe>]
       python -I xexpe.py --verify-pe <signed.xex> <image.pe>    (checks an image, e.g. tools\\xexunpack.ps1's, against
                                                                  a XEX's header; that XEX may be compressed)

The security info's image digest is the SHA-1 of the first descriptor's pages and the first descriptor, and each
descriptor's digest field is the SHA-1 of the next descriptor's pages and the next descriptor (the last one's covers
nothing in the image). So a match means the image is exactly the one the header was signed for.
"""
import hashlib
import struct
import sys


def be32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def opt(d, key):
    for i in range(be32(d, 20)):
        if be32(d, 24 + i * 8) == key:
            return be32(d, 28 + i * 8)
    return None


def verify(x, image):
    """(top digest matches, descriptor count, bytes covered, indices of descriptors whose digest doesn't match)."""
    s = be32(x, 16)
    page = 0x1000 if be32(x, s + 0x10C) & 0x10000000 else 0x10000
    count = be32(x, s + 0x180)
    descs = [x[s + 0x184 + i * 24:s + 0x184 + (i + 1) * 24] for i in range(count)]
    offsets, off = [], 0
    for desc in descs:
        offsets.append(off)
        off += (be32(desc, 0) >> 4) * page

    def data(i):
        return image[offsets[i]:offsets[i] + (be32(descs[i], 0) >> 4) * page]

    ok = bool(descs) and hashlib.sha1(data(0) + descs[0]).digest() == x[s + 0x114:s + 0x128]
    bad = [i for i in range(count - 1) if hashlib.sha1(data(i + 1) + descs[i + 1]).digest() != descs[i][4:24]]
    return ok, count, off, bad


def main():
    args = sys.argv[1:]
    if args[:1] == ["--verify-pe"] and len(args) == 3:
        x = open(args[1], "rb").read()
        image = open(args[2], "rb").read()
    elif len(args) in (1, 2) and not args[0].startswith("--"):
        x = open(args[0], "rb").read()
        ffi = opt(x, 0x3FF)
        enc, comp = struct.unpack_from(">HH", x, ffi + 4)
        if enc or comp:
            sys.exit("not an uncompressed, unencrypted XEX")
        header_size = be32(x, 8)
        image_size = be32(x, be32(x, 16) + 4)
        image = x[header_size:header_size + image_size]
        if len(args) == 2:
            with open(args[1], "wb") as f:
                f.write(image)
            print(f"wrote {len(image)} bytes (0x{len(image):X}), MZ: {image[:2] == b'MZ'}")
    else:
        sys.exit(__doc__)
    ok, count, covered, bad = verify(x, image)
    print(f"image digest matches the first pages: {ok}; {count} descriptors over 0x{covered:X} bytes; "
          f"descriptor digests that match the next pages: {count - 1 - len(bad)} of {count - 1}"
          + (f" (first bad: {bad[:8]})" if bad else ""))
    print(f"image sha256 {hashlib.sha256(image).hexdigest()}")


if __name__ == "__main__":
    main()
