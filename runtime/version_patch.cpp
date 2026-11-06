// Version patches (version_patch.h): the patch file's reader, its operations and its font composition, as
// tools\versionpatch.py's read_patch, decode and compose_font have them.
#include "version_patch.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <map>
#include <new>

#include <windows.h>
#include <bcrypt.h>

#include "LzmaDec.h"

namespace patch
{
    namespace
    {
        constexpr char kMagic[4] = { 'V', 'P', 'A', 'T' };
        constexpr uint32_t kFormat = 1;
        // ops-lzma: the only engine the game reads (the tool's ops-lzms, ops-raw and msdelta are for measuring).
        constexpr uint32_t kEngineLzma = 4;
        constexpr uint32_t kStreams = 3; // the operations, the differences, the inserted bytes
        enum Operation : uint8_t
        {
            kCopy = 0,
            kAdd = 1,
            kInsert = 2,
            kSkip = 3,
        };
        // u8 the operation, i64 its source's place from the previous source operation's end, u64 its length.
        constexpr size_t kOperationSize = 17;
        // What a patch file may ask for: a piece is a file of a disc (XDVDFS sizes are 32-bit), a patch a few of them, and
        // its streams decompressed take some memory, but not all of a PC's (DOA4's take 16 MB); a piece made in memory, not
        // much more (DOA4's image, 23 MB).
        constexpr uint32_t kMaxPieces = 64, kMaxName = 1024, kMaxRanges = 1 << 16, kMaxFontPages = 64;
        constexpr uint64_t kMaxSize = UINT32_MAX, kMaxOperations = 64ull << 20, kMaxStreams = 512ull << 20, kMaxInMemory = 512ull << 20;

        uint32_t Be32(const uint8_t* p)
        {
            return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
        }

        uint16_t Be16(const uint8_t* p)
        {
            return uint16_t(p[0] << 8 | p[1]);
        }

        // Little-endian values from the file, failing from the first read past its end on.
        class Reader
        {
        public:
            explicit Reader(const std::vector<uint8_t>& data) : m_data(data) {}

            bool Ok() const { return m_ok; }
            size_t Left() const { return m_data.size() - m_at; }

            const uint8_t* Take(uint64_t size)
            {
                if (!m_ok || size > Left())
                {
                    m_ok = false;
                    return nullptr;
                }
                const uint8_t* bytes = m_data.data() + m_at;
                m_at += size_t(size);
                return bytes;
            }

            template <typename T>
            T Get()
            {
                T value{};
                if (const uint8_t* bytes = Take(sizeof(T)))
                    memcpy(&value, bytes, sizeof(T));
                return value;
            }

            void Get(Sha256& hash)
            {
                if (const uint8_t* bytes = Take(hash.size()))
                    memcpy(hash.data(), bytes, hash.size());
            }

        private:
            const std::vector<uint8_t>& m_data;
            size_t m_at = 0;
            bool m_ok = true;
        };

        // The LZMA SDK's decoder (third_party/lzma) decompresses each stream in one call, into its buffer, which is its
        // dictionary too; its one allocation, the probabilities (16 KB with the tool's properties, 6 MB at most), is the
        // heap's.
        void* LzmaAlloc(ISzAllocPtr, size_t size)
        {
            return malloc(size);
        }

        void LzmaFree(ISzAllocPtr, void* address)
        {
            free(address);
        }

        const ISzAlloc kLzmaAlloc = { LzmaAlloc, LzmaFree };

        // How many times its size a stream of LZMA can decompress to, and a little more: about 7,100 at most (a match of
        // 273 bytes, the longest, takes 14 of the range coder's decisions, and a decision 0.022 bits at the least).
        constexpr uint64_t kMaxRatio = 8192;

        enum class Decompressed
        {
            kOk,
            kWrong,
            kOutOfMemory,
        };

        // A stream as tools\versionpatch.py stores it: nothing for no bytes, else LZMA's 5 property bytes and its data,
        // which must come out exactly `size` bytes and end with the stream's last byte (with an end marker or without). A
        // size more than the stream's bytes can hold is refused before a buffer that size is made.
        Decompressed DecompressLzma(const uint8_t* data, uint64_t stored, uint64_t size, std::vector<uint8_t>& out)
        {
            out.clear();
            if (size == 0)
                return stored == 0 ? Decompressed::kOk : Decompressed::kWrong;
            if (stored < LZMA_PROPS_SIZE || size > (stored - LZMA_PROPS_SIZE) * kMaxRatio)
                return Decompressed::kWrong;
            try
            {
                out.resize(size_t(size));
            }
            catch (const std::bad_alloc&)
            {
                return Decompressed::kOutOfMemory;
            }
            SizeT made = SizeT(size), taken = SizeT(stored - LZMA_PROPS_SIZE);
            ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
            const SRes result =
                LzmaDecode(out.data(), &made, data + LZMA_PROPS_SIZE, &taken, data, LZMA_PROPS_SIZE, LZMA_FINISH_END, &status, &kLzmaAlloc);
            if (result == SZ_OK && made == size && taken == stored - LZMA_PROPS_SIZE &&
                (status == LZMA_STATUS_FINISHED_WITH_MARK || status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK))
                return Decompressed::kOk;
            out = {};
            return result == SZ_ERROR_MEM ? Decompressed::kOutOfMemory : Decompressed::kWrong;
        }

        struct Glyph
        {
            uint32_t texture = 0, cell = 0;
            bool present = false;
        };

        // A font's page table (Font): each code point's first glyph, by code point (`where`) and in the table's order
        // (`order`), and each page's texture. False if the table or a glyph list lies outside the image.
        bool ReadFontTable(const std::vector<uint8_t>& image, uint32_t base, uint32_t address, uint32_t pages, std::vector<Glyph>& where,
            std::vector<std::pair<uint16_t, Glyph>>& order, std::vector<uint32_t>& textures)
        {
            where.assign(0x10000, Glyph{});
            if (pages == 0 || pages > kMaxFontPages || address < base || uint64_t(address - base) + uint64_t(pages) * 16 > image.size())
                return false;
            for (uint32_t page = 0; page < pages; page++)
            {
                const uint8_t* entry = image.data() + (address - base) + page * 16;
                const uint32_t texture = Be32(entry), count = Be32(entry + 4), list = Be32(entry + 12);
                if (count > 1024 || list < base || uint64_t(list - base) + uint64_t(count) * 2 > image.size())
                    return false;
                textures.push_back(texture);
                for (uint32_t i = 0; i < count; i++)
                {
                    const uint16_t code = Be16(image.data() + (list - base) + i * 2);
                    if (!where[code].present)
                    {
                        where[code] = Glyph{ texture, i, true };
                        order.emplace_back(code, where[code]);
                    }
                }
            }
            return true;
        }

        struct Texture
        {
            uint64_t data = 0; // in the package
            uint32_t width = 0, height = 0, format = 0;
        };

        // An XPR2 package's textures, by resource index (each resource's last 24 bytes are its texture's fetch constant).
        bool ReadTextures(const std::vector<uint8_t>& package, std::map<uint32_t, Texture>& textures)
        {
            if (package.size() < 16 || memcmp(package.data(), "XPR2", 4) != 0)
                return false;
            const uint32_t headerSize = Be32(&package[4]), count = Be32(&package[12]);
            for (uint32_t k = 0; k < count; k++)
            {
                const uint64_t entry = 16 + uint64_t(k) * 16;
                if (entry + 16 > package.size())
                    return false;
                const uint32_t offset = Be32(&package[size_t(entry) + 4]), size = Be32(&package[size_t(entry) + 8]);
                if (size < 24)
                    continue;
                const uint64_t fetch = 12 + uint64_t(offset) + size - 24;
                if (fetch + 24 > package.size())
                    return false;
                const uint32_t word1 = Be32(&package[size_t(fetch) + 4]), word2 = Be32(&package[size_t(fetch) + 8]);
                textures[k] = Texture{ 12 + uint64_t(headerSize) + (word1 & 0xFFFFF000u), (word2 & 0x1FFF) + 1, ((word2 >> 13) & 0x1FFF) + 1, word1 & 0x3F };
            }
            return true;
        }
    }

    Sha256 Hash(const uint8_t* data, size_t size)
    {
        Hasher hasher;
        hasher.Update(data, size);
        return hasher.Finish();
    }

    std::string Hex(const Sha256& hash)
    {
        static const char digits[] = "0123456789abcdef";
        std::string text;
        for (const uint8_t byte : hash)
        {
            text.push_back(digits[byte >> 4]);
            text.push_back(digits[byte & 15]);
        }
        return text;
    }

    Hasher::Hasher()
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        m_ok = BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) &&
            BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0));
        m_algorithm = algorithm;
        m_hash = hash;
    }

    Hasher::~Hasher()
    {
        if (m_hash)
            BCryptDestroyHash(m_hash);
        if (m_algorithm)
            BCryptCloseAlgorithmProvider(m_algorithm, 0);
    }

    void Hasher::Update(const uint8_t* data, size_t size)
    {
        while (m_ok && size)
        {
            const ULONG chunk = ULONG(std::min<size_t>(size, 1u << 30));
            m_ok = BCRYPT_SUCCESS(BCryptHashData(m_hash, const_cast<PUCHAR>(data), chunk, 0));
            data += chunk;
            size -= chunk;
        }
    }

    Sha256 Hasher::Finish()
    {
        Sha256 hash{};
        if (!m_ok || !BCRYPT_SUCCESS(BCryptFinishHash(m_hash, hash.data(), ULONG(hash.size()), 0)))
            hash = {};
        m_ok = false;
        return hash;
    }

    const Piece* Patch::Find(std::string_view name) const
    {
        for (const Piece& piece : pieces)
        {
            if (piece.name == name)
                return &piece;
        }
        return nullptr;
    }

    bool DecompressStream(const uint8_t* stored, size_t storedSize, uint64_t size, std::vector<uint8_t>& out)
    {
        return DecompressLzma(stored, storedSize, size, out) == Decompressed::kOk;
    }

    std::string Read(const std::vector<uint8_t>& file, Patch& patch)
    {
        patch = {};
        uint64_t decompressed = 0;
        Reader in(file);
        const uint8_t* magic = in.Take(sizeof(kMagic));
        if (!magic || memcmp(magic, kMagic, sizeof(kMagic)) != 0)
            return "it isn't a version patch";
        const uint32_t format = in.Get<uint32_t>(), count = in.Get<uint32_t>();
        in.Get<uint64_t>(); // the target's default.xex's size, which the tool repacks it to
        if (!in.Ok())
            return "it's cut short";
        if (format != kFormat)
            return "its format (" + std::to_string(format) + ") isn't the one this build reads (" + std::to_string(kFormat) + ")";
        if (count > kMaxPieces)
            return "it has too many pieces";
        for (uint32_t i = 0; i < count; i++)
        {
            Piece piece;
            const uint16_t nameLength = in.Get<uint16_t>();
            if (const uint8_t* name = in.Take(nameLength))
                piece.name.assign(reinterpret_cast<const char*>(name), nameLength);
            piece.sourceSize = in.Get<uint64_t>();
            in.Get(piece.sourceSha);
            piece.resultSize = in.Get<uint64_t>();
            in.Get(piece.resultSha);
            in.Get(piece.targetSha);
            if (!in.Ok())
                return "it's cut short";
            if (nameLength > kMaxName || piece.name.empty() || patch.Find(piece.name))
                return "a piece's name isn't right";
            if (piece.sourceSize > kMaxSize || piece.resultSize > kMaxSize)
                return piece.name + " is larger than a disc's file can be";
            for (std::vector<Range>* ranges : { &piece.unclaimed, &piece.kept })
            {
                const uint32_t ranged = in.Get<uint32_t>();
                if (ranged > kMaxRanges)
                    return piece.name + " has too many ranges";
                for (uint32_t k = 0; k < ranged && in.Ok(); k++)
                {
                    Range range;
                    range.offset = in.Get<uint64_t>();
                    range.length = in.Get<uint64_t>();
                    if (range.offset > piece.resultSize || range.length > piece.resultSize - range.offset)
                        return "a range of " + piece.name + " lies past its end";
                    ranges->push_back(range);
                }
            }
            const uint32_t engine = in.Get<uint32_t>();
            Font& font = piece.font;
            font.mode = in.Get<uint32_t>();
            font.entry = in.Get<uint32_t>();
            font.sourceTable = in.Get<uint32_t>();
            font.sourcePages = in.Get<uint32_t>();
            font.targetTable = in.Get<uint32_t>();
            font.targetPages = in.Get<uint32_t>();
            const uint32_t streams = in.Get<uint32_t>();
            if (!in.Ok())
                return "it's cut short";
            if (engine != kEngineLzma)
                return piece.name + "'s engine (" + std::to_string(engine) + ") isn't LZMA operations, the only one the game reads";
            if (font.mode > 2 || (font.mode && (font.sourcePages > kMaxFontPages || font.targetPages > kMaxFontPages)))
                return piece.name + "'s font composition isn't one the game knows";
            if (streams != kStreams)
                return piece.name + " doesn't have its three streams";
            for (std::vector<uint8_t>* stream : { &piece.control, &piece.difference, &piece.insert })
            {
                const uint64_t stored = in.Get<uint64_t>(), size = in.Get<uint64_t>();
                const uint8_t* bytes = in.Take(stored);
                if (!bytes)
                    return "it's cut short";
                // No stream is larger than its piece, but the operations (a few for each part), and all of them together
                // only so large.
                if (size > (stream == &piece.control ? kMaxOperations : piece.resultSize) || size > kMaxStreams - decompressed)
                    return "a stream of " + piece.name + " is larger than a patch allows";
                decompressed += size;
                const Decompressed result = DecompressLzma(bytes, stored, size, *stream);
                if (result == Decompressed::kOutOfMemory)
                    return kOutOfMemory;
                if (result != Decompressed::kOk)
                    return "a stream of " + piece.name + " doesn't decompress to its size";
            }
            patch.pieces.push_back(std::move(piece));
        }
        if (in.Left())
            return "it has bytes after its last piece";
        patch.sha = Hash(file.data(), file.size());
        return {};
    }

    std::string Compose(const Piece& piece, const SourceReader& source, std::vector<uint8_t> appended, vfs::ComposedFile& file)
    {
        using Extent = vfs::ComposedFile::Extent;
        file = {};
        file.size = piece.resultSize;
        if (piece.control.size() % kOperationSize)
            return "its operations aren't whole";
        // The source's bytes, then the appended ones, which go in memory first.
        const uint64_t sourceSize = piece.sourceSize, total = sourceSize + appended.size();
        file.memory = std::move(appended);
        try
        {
            file.memory.reserve(file.memory.size() + piece.difference.size() + piece.insert.size());
        }
        catch (const std::bad_alloc&)
        {
            file = {};
            return kOutOfMemory;
        }
        const auto add = [&](uint64_t offset, uint64_t length, Extent::From from, uint64_t at) {
            if (!length)
                return;
            if (!file.extents.empty())
            {
                Extent& last = file.extents.back();
                if (last.from == from && last.offset + last.length == offset && (from == Extent::From::kZero || last.at + last.length == at))
                {
                    last.length += length;
                    return;
                }
            }
            file.extents.push_back(Extent{ offset, length, from, at });
        };
        // The extents of source bytes [at, at + length) placed at `offset`: the source's own, then the appended ones.
        const auto fromSource = [&](uint64_t offset, uint64_t at, uint64_t length) {
            if (at < sourceSize)
            {
                const uint64_t part = std::min(length, sourceSize - at);
                add(offset, part, Extent::From::kDisc, at);
                offset += part, at += part, length -= part;
            }
            add(offset, length, Extent::From::kMemory, at - sourceSize);
        };
        const auto readSource = [&](uint64_t at, uint8_t* out, uint64_t length) {
            if (at < sourceSize)
            {
                const uint64_t part = std::min(length, sourceSize - at);
                if (!source(at, out, size_t(part)))
                    return false;
                at += part, out += part, length -= part;
            }
            if (length)
                memcpy(out, file.memory.data() + (at - sourceSize), size_t(length));
            return true;
        };

        uint64_t written = 0, sourceEnd = 0, differences = 0, inserted = 0;
        for (size_t i = 0; i < piece.control.size(); i += kOperationSize)
        {
            const uint8_t operation = piece.control[i];
            int64_t seek = 0;
            uint64_t length = 0;
            memcpy(&seek, &piece.control[i + 1], sizeof(seek));
            memcpy(&length, &piece.control[i + 9], sizeof(length));
            if (length > file.size - written)
                return "an operation writes past its end";
            switch (operation)
            {
            case kSkip:
                add(written, length, Extent::From::kZero, 0);
                break;
            case kInsert:
                if (length > piece.insert.size() - inserted)
                    return "its inserted bytes run out";
                add(written, length, Extent::From::kMemory, file.memory.size());
                file.memory.insert(file.memory.end(), piece.insert.begin() + ptrdiff_t(inserted), piece.insert.begin() + ptrdiff_t(inserted + length));
                inserted += length;
                break;
            case kCopy:
            case kAdd:
            {
                // The source's bytes from the previous source operation's end, moved by `seek`.
                if (seek < 0 ? uint64_t(0) - uint64_t(seek) > sourceEnd : uint64_t(seek) > total - sourceEnd)
                    return "an operation reads outside its source";
                const uint64_t at = sourceEnd + uint64_t(seek);
                if (length > total - at)
                    return "an operation reads outside its source";
                if (operation == kCopy)
                    fromSource(written, at, length);
                else
                {
                    if (length > piece.difference.size() - differences)
                        return "its differences run out";
                    const size_t made = file.memory.size();
                    file.memory.resize(made + size_t(length));
                    if (!readSource(at, file.memory.data() + made, length))
                        return "its source can't be read";
                    const uint8_t* difference = piece.difference.data() + differences;
                    for (size_t k = 0; k < length; k++)
                        file.memory[made + k] = uint8_t(file.memory[made + k] + difference[k]);
                    add(written, length, Extent::From::kMemory, made);
                    differences += length;
                }
                sourceEnd = at + length;
                break;
            }
            default:
                return "an operation of an unknown kind (" + std::to_string(operation) + ")";
            }
            written += length;
        }
        if (written != file.size || differences != piece.difference.size() || inserted != piece.insert.size())
            return "its streams don't add up to it";
        return {};
    }

    std::string Apply(const Piece& piece, const std::vector<uint8_t>& source, std::vector<uint8_t>& result)
    {
        using Extent = vfs::ComposedFile::Extent;
        result.clear();
        if (source.size() != piece.sourceSize || Hash(source.data(), source.size()) != piece.sourceSha)
            return "its source isn't the one the patch was made for";
        if (piece.resultSize > kMaxInMemory)
            return "its result is larger than a piece made in memory can be";
        vfs::ComposedFile file;
        const auto read = [&](uint64_t offset, uint8_t* buffer, size_t length) {
            memcpy(buffer, source.data() + offset, length);
            return true;
        };
        if (std::string problem = Compose(piece, read, {}, file); !problem.empty())
            return problem;
        try
        {
            result.resize(size_t(file.size));
        }
        catch (const std::bad_alloc&)
        {
            return kOutOfMemory;
        }
        for (const Extent& extent : file.extents)
        {
            uint8_t* out = result.data() + extent.offset;
            if (extent.from == Extent::From::kDisc)
                memcpy(out, source.data() + extent.at, size_t(extent.length));
            else if (extent.from == Extent::From::kMemory)
                memcpy(out, file.memory.data() + extent.at, size_t(extent.length));
            else
                memset(out, 0, size_t(extent.length));
        }
        if (Hash(result.data(), result.size()) != piece.resultSha)
        {
            result.clear();
            return "its result isn't the one the patch was made for";
        }
        return {};
    }

    uint32_t TiledOffset(uint32_t x, uint32_t y, uint32_t width)
    {
        const uint32_t aligned = (width + 31) & ~31u;
        const uint32_t macro = ((x >> 5) + (y >> 5) * (aligned >> 5)) << 7;
        const uint32_t micro = (x & 7) + ((y & 0xE) << 2);
        const uint32_t offset = macro + ((micro & ~0xFu) << 1) + (micro & 0xF) + ((y & 1) << 4);
        return ((offset & ~0x1FFu) << 3) + ((y & 16) << 7) + ((offset & 0x1C0) << 2) + (((((y & 8) >> 2) + (x >> 3)) & 3) << 6) + (offset & 0x3F);
    }

    std::string ComposeFont(const Font& font, const std::vector<uint8_t>& package, const std::vector<uint8_t>& sourceImage, uint32_t sourceBase,
        const std::vector<uint8_t>& resultImage, uint32_t resultBase, std::vector<uint8_t>& pages)
    {
        // A page is 1024x1024 texels of a byte, 32x32 cells of 32x32.
        constexpr uint32_t kSide = 1024, kPageBytes = kSide * kSide, kCellSide = 32, kCellTexels = kCellSide * kCellSide;
        pages.clear();
        std::vector<Glyph> sourceWhere, resultWhere;
        std::vector<std::pair<uint16_t, Glyph>> sourceOrder, resultOrder;
        std::vector<uint32_t> sourceTextures, resultTextures;
        if (!ReadFontTable(sourceImage, sourceBase, font.sourceTable, font.sourcePages, sourceWhere, sourceOrder, sourceTextures) ||
            !ReadFontTable(resultImage, resultBase, font.targetTable, font.targetPages, resultWhere, resultOrder, resultTextures))
            return "a font's page table isn't where the patch says";
        std::map<uint32_t, Texture> textures;
        if (!ReadTextures(package, textures))
            return "the font's archive entry isn't an XPR2 package";
        // Each cell's texels' offsets in a tiled page, row by row.
        static const std::vector<uint32_t> cells = [] {
            std::vector<uint32_t> offsets(size_t(kCellTexels) * kCellTexels);
            for (uint32_t cell = 0; cell < kCellTexels; cell++)
            {
                for (uint32_t y = 0; y < kCellSide; y++)
                {
                    for (uint32_t x = 0; x < kCellSide; x++)
                        offsets[(cell * kCellSide + y) * kCellSide + x] = TiledOffset((cell % kCellSide) * kCellSide + x, (cell / kCellSide) * kCellSide + y, kSide);
                }
            }
            return offsets;
        }();
        // A page for each texture the result's table names (blank where the source lacks a glyph).
        std::map<uint32_t, std::vector<uint8_t>> composed;
        try
        {
            for (const uint32_t texture : resultTextures)
                composed[texture].resize(kPageBytes);
            pages.reserve(resultTextures.size() * kPageBytes);
        }
        catch (const std::bad_alloc&)
        {
            return kOutOfMemory;
        }
        for (const auto& [code, glyph] : resultOrder)
        {
            const Glyph& from = sourceWhere[code];
            if (!from.present)
                continue;
            const auto texture = textures.find(from.texture);
            if (texture == textures.end() || texture->second.width != kSide || texture->second.height != kSide || texture->second.format != 2 ||
                texture->second.data > package.size() || package.size() - texture->second.data < kPageBytes)
                return "the font's package lacks a page its table names";
            const uint8_t* source = package.data() + texture->second.data;
            uint8_t* target = composed[glyph.texture].data();
            const uint32_t* read = &cells[size_t(from.cell) * kCellTexels];
            const uint32_t* write = &cells[size_t(glyph.cell) * kCellTexels];
            for (uint32_t k = 0; k < kCellTexels; k++)
                target[write[k]] = source[read[k]];
        }
        for (const uint32_t texture : resultTextures)
            pages.insert(pages.end(), composed[texture].begin(), composed[texture].end());
        return {};
    }
}
