#pragma once

// Version patches (tools\versionpatch.py; analysis/version_patches.md): what makes the supported version of a game's
// executable and files from another version's, out of that version's own bytes and the patch's, so that a disc of that
// version plays as the supported one. A patch file ("VPAT", little-endian) holds pieces, each a file of the result: the
// executable as two, its XEX header ("default.xex/header") and its image ("default.xex/image"), and disc files by their
// paths. Each is made by operations on its source, the other version's file: COPY (the source's bytes), ADD (the
// source's bytes plus a difference byte each, mod 256: an address that moved comes out as a few bytes), INSERT (the
// patch's own bytes) and SKIP (zeros: what the patch leaves out, such as the image's code), in three streams (the
// operations, the differences, the inserted bytes) compressed with LZMA, which the LZMA SDK's decoder (third_party/lzma)
// decompresses.
// A piece names its source's size and SHA-256 and its result's: the source is checked before, the result after. An
// archive's piece can compose font pages from the source's own glyph cells first (Font), which its operations then read
// as if they followed the source.
// Game-agnostic: which versions a game's discs come in, and their patches, are disc_image.cpp's.
#include "vfs/iso_device.h"

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace patch
{
    using Sha256 = std::array<uint8_t, 32>;

    // SHA-256 (BCrypt), at once or a part at a time.
    Sha256 Hash(const uint8_t* data, size_t size);
    std::string Hex(const Sha256& hash);
    class Hasher
    {
    public:
        Hasher();
        ~Hasher();
        Hasher(const Hasher&) = delete;
        Hasher& operator=(const Hasher&) = delete;
        void Update(const uint8_t* data, size_t size);
        // The hash, or all zeros if BCrypt failed.
        Sha256 Finish();

    private:
        void* m_algorithm = nullptr; // BCRYPT_ALG_HANDLE
        void* m_hash = nullptr;      // BCRYPT_HASH_HANDLE
        bool m_ok = false;
    };

    struct Range
    {
        uint64_t offset = 0, length = 0;
    };

    // A font composition: DOA4's kind of font, 1024x1024 8-bit tiled pages of 32x32 glyph cells in an XPR2 package (an
    // archive's entry), and a page table in each executable's image (16 bytes a page: the texture, the glyph count, the
    // size, the address of the glyph list, its code points in cell order). The result's pages are made of the source's
    // cells by code point; the piece's operations read them after the source's end.
    struct Font
    {
        uint32_t mode = 0;  // 0 none; 1 the composed pages patched into the target's; 2 the composed pages as the result
        uint32_t entry = 0; // the archive's (AFS) entry that holds the pages
        uint32_t sourceTable = 0, sourcePages = 0; // the page tables: their addresses in the source's and the result's images
        uint32_t targetTable = 0, targetPages = 0;
    };

    struct Piece
    {
        std::string name;
        uint64_t sourceSize = 0, resultSize = 0;
        Sha256 sourceSha{}, resultSha{}, targetSha{}; // the result is the target's, but for what it leaves out or keeps
        std::vector<Range> unclaimed, kept;
        Font font;
        std::vector<uint8_t> control, difference, insert; // the streams, decompressed
    };

    struct Patch
    {
        std::vector<Piece> pieces;
        Sha256 sha{}; // the file's
        const Piece* Find(std::string_view name) const;
    };

    // A patch's stream as tools\versionpatch.py stores it: nothing for no bytes, else LZMA's 5 property bytes and its
    // data, which must come out exactly `size` bytes and end with the stream's last byte. False if it doesn't (for tests:
    // Read decompresses a patch's streams).
    bool DecompressStream(const uint8_t* stored, size_t storedSize, uint64_t size, std::vector<uint8_t>& out);
    // What Read, Compose, Apply and ComposeFont say when memory runs out, which isn't the patch's fault.
    inline constexpr char kOutOfMemory[] = "it needs more memory than this PC has free";
    // Reads a patch file, every count, size and range bounded (each stream's size by its piece and by what its compressed
    // bytes can hold, before anything is allocated, and all of them together), and decompresses its streams. Empty, or
    // what's wrong.
    std::string Read(const std::vector<uint8_t>& file, Patch& patch);
    // Changes whenever the applier or the font composition would make other bytes from a patch, so that a composed file
    // that an earlier build checked is checked again (disc_image.h: what disc_checks.txt remembers).
    constexpr int kApplierVersion = 1;

    // Reads `length` bytes of a piece's source at `offset`: false if it can't.
    using SourceReader = std::function<bool(uint64_t offset, uint8_t* buffer, size_t length)>;
    // Applies a piece's operations to its source (piece.sourceSize bytes, then `appended`: a font composition's pages) as
    // a composed file: what comes from the source stays there (kDisc extents), the appended pages and what the patch makes
    // go in its memory. Checks the operations against the sizes and the streams, but not the hashes. Empty, or what's
    // wrong.
    std::string Compose(const Piece& piece, const SourceReader& source, std::vector<uint8_t> appended, vfs::ComposedFile& file);
    // Applies a piece to its source in memory: the source's size and SHA-256 are checked before, the result's after.
    std::string Apply(const Piece& piece, const std::vector<uint8_t>& source, std::vector<uint8_t>& result);

    // A font composition's pages (Font): the result's pages, in its page table's order, from the source's XPR2 package
    // (the archive's entry) and the two images (their base addresses: the XEX's). Glyphs the source lacks are blank.
    std::string ComposeFont(const Font& font, const std::vector<uint8_t>& package, const std::vector<uint8_t>& sourceImage, uint32_t sourceBase,
        const std::vector<uint8_t>& resultImage, uint32_t resultBase, std::vector<uint8_t>& pages);
    // A texel's byte offset in an 8-bit Xenos tiled 2D texture `width` texels wide.
    uint32_t TiledOffset(uint32_t x, uint32_t y, uint32_t width);
}
