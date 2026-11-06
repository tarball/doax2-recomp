#include "disc_image.h"

#include "log.h"
#include "version_patch.h"
#include "vfs/iso_device.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <new>
#include <tuple>

#include <windows.h>
#include <bcrypt.h>

namespace disc
{
    namespace
    {
        // The version config/DOAX2.toml describes is Dead or Alive Xtreme 2's Title Update 2 (title 544307D2, version
        // 0x203): the USA disc's default.xex with the update applied, which is on no disc, so every disc plays with a
        // version patch (analysis/tu2_plan.md).
        constexpr char kSupportedXex[] = "";
        // Its XEX header (as XenonUtils' patcher writes it: uncompressed), and its image as the game runs it (the code and
        // .pdata zero: ClearCode), which a version patch must make.
        constexpr char kSupportedHeader[] = "b25e5c5165a0aef1f12304e9de34b4abf84b1f53151e8e60ca087142865da1d5";
        constexpr char kSupportedImage[] = "ddf6b65327b4a57e7b5158a88a77b642f674b64146f6154be2cf6747c87aec53";
        // The game's other versions, whose discs a release plays with a version patch of its own (tools\versionpatch.py,
        // which tools\release.ps1 runs): the USA disc (version 3, media ID 21B9628E). The update changes no disc file, so
        // its patch makes the executable alone: TU2's header and image, without the code and .pdata.
        constexpr Version kOtherVersions[] = {
            { "c4a14853e1f7af951be34f380604113703638780b36d5e74e674fe7431992870", "USA", "the USA disc", GAME_EXECUTABLE "_tu2.vpatch", true },
        };

        // The XEX retail key, which decrypts each executable's session key.
        constexpr uint8_t kRetailKey[16] = { 0x20, 0xB1, 0x85, 0xA5, 0x9D, 0x28, 0xFD, 0xC3, 0x40, 0x58, 0x3F, 0xBB, 0x08, 0x96, 0xBF, 0x91 };
        constexpr uint32_t kFileFormatInfo = 0x3FF, kImageBaseAddress = 0x10201; // optional header keys
        constexpr uint16_t kEncrypted = 1, kNoCompression = 0, kBasicCompression = 1;

        // Whether a default.xex's SHA-256 is the supported version's: never when kSupportedXex is empty, the supported
        // version being on no disc (a title update's, which every disc plays with a version patch).
        bool IsSupportedXex(const std::string& hash)
        {
            return kSupportedXex[0] && hash == kSupportedXex;
        }

        // AES-128-CBC with a zero IV, in place, over whole blocks.
        bool Decrypt(const uint8_t key[16], uint8_t* data, size_t size)
        {
            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_KEY_HANDLE handle = nullptr;
            bool ok = BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0)) &&
                BCRYPT_SUCCESS(BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                    sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) &&
                BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(algorithm, &handle, nullptr, 0, const_cast<PUCHAR>(key), 16, 0));
            if (ok)
            {
                uint8_t iv[16] = {};
                ULONG written = 0;
                ok = BCRYPT_SUCCESS(BCryptDecrypt(handle, data, ULONG(size), nullptr, iv, sizeof(iv), data, ULONG(size), &written, 0)) &&
                    written == size;
            }
            if (handle)
                BCryptDestroyKey(handle);
            if (algorithm)
                BCryptCloseAlgorithmProvider(algorithm, 0);
            return ok;
        }

        uint32_t Be32(const std::vector<uint8_t>& data, size_t offset)
        {
            if (offset + 4 > data.size())
                return 0;
            return uint32_t(data[offset]) << 24 | uint32_t(data[offset + 1]) << 16 | uint32_t(data[offset + 2]) << 8 | data[offset + 3];
        }

        // An optional header's value in an XEX header, or `fallback`.
        uint32_t OptionalHeader(const std::vector<uint8_t>& xex, uint32_t key, uint32_t fallback)
        {
            const uint32_t count = Be32(xex, 20);
            for (uint32_t i = 0; i < count && 32 + size_t(i) * 8 <= xex.size(); i++)
            {
                if (Be32(xex, 24 + size_t(i) * 8) == key)
                    return Be32(xex, 28 + size_t(i) * 8);
            }
            return fallback;
        }

        // The XEX header: the file's first bytes, as many as it says.
        std::vector<uint8_t> Header(const std::vector<uint8_t>& xex)
        {
            const uint32_t size = Be32(xex, 8);
            return std::vector<uint8_t>(xex.begin(), xex.begin() + ptrdiff_t(std::min<size_t>(size, xex.size())));
        }

        bool ReadWholeFile(const std::filesystem::path& path, std::vector<uint8_t>& data)
        {
            std::ifstream file(path, std::ios::binary | std::ios::ate);
            if (!file)
                return false;
            data.resize(size_t(file.tellg()));
            file.seekg(0);
            file.read(reinterpret_cast<char*>(data.data()), std::streamsize(data.size()));
            return bool(file);
        }

        // A disc file's bytes, whole however a read splits them.
        bool ReadFully(vfs::File& file, uint64_t offset, uint8_t* buffer, size_t length)
        {
            while (length)
            {
                const uint32_t chunk = uint32_t(std::min<size_t>(length, 1u << 24));
                uint32_t transferred = 0;
                if (file.Read(buffer, chunk, offset, transferred) != 0 || transferred != chunk)
                    return false;
                buffer += chunk, offset += chunk, length -= chunk;
            }
            return true;
        }

        std::unique_ptr<vfs::File> OpenDiscFile(vfs::Device& device, const std::string& path)
        {
            vfs::OpenRequest request;
            request.path = path;
            request.nonDirectory = true;
            std::unique_ptr<vfs::File> file;
            vfs::OpenResult result;
            if (device.Open(request, file, result) != 0)
                return nullptr;
            return file;
        }

        // A version patch's piece name as a path on the disc, as ComposedFiles has it.
        std::string DiscPath(std::string name)
        {
            std::replace(name.begin(), name.end(), '/', '\\');
            name.erase(0, std::min(name.find_first_not_of('\\'), name.size()));
            std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return char(std::tolower(c)); });
            return name;
        }

        // An AFS archive's entry, read from it.
        bool ReadAfsEntry(vfs::File& archive, uint64_t archiveSize, uint32_t entry, std::vector<uint8_t>& bytes)
        {
            uint8_t header[8];
            if (entry > (1u << 20) || !ReadFully(archive, 0, header, sizeof(header)) || memcmp(header, "AFS\0", 4) != 0)
                return false;
            uint32_t count = 0, place[2] = {};
            memcpy(&count, header + 4, 4);
            if (entry >= count || !ReadFully(archive, 8 + uint64_t(entry) * 8, reinterpret_cast<uint8_t*>(place), sizeof(place)))
                return false;
            if (place[0] > archiveSize || place[1] > archiveSize - place[0])
                return false;
            bytes.resize(place[1]);
            return ReadFully(archive, place[0], bytes.data(), bytes.size());
        }

        // What makes a version patch's composed file what it is: its source on the disc read whole, as the patch says
        // (empty), and the result read whole through its extents, as the patch made it.
        std::string CheckComposed(vfs::File& source, const vfs::ComposedFile& composed, const patch::Piece& piece)
        {
            constexpr size_t kChunk = 8 << 20;
            std::vector<uint8_t> buffer(kChunk);
            patch::Hasher sourceHash;
            for (uint64_t at = 0; at < piece.sourceSize; at += kChunk)
            {
                const size_t length = size_t(std::min<uint64_t>(kChunk, piece.sourceSize - at));
                if (!ReadFully(source, at, buffer.data(), length))
                    return "source";
                sourceHash.Update(buffer.data(), length);
            }
            if (sourceHash.Finish() != piece.sourceSha)
                return "source";
            patch::Hasher resultHash;
            for (const vfs::ComposedFile::Extent& extent : composed.extents)
            {
                for (uint64_t done = 0; done < extent.length;)
                {
                    const size_t length = size_t(std::min<uint64_t>(kChunk, extent.length - done));
                    if (extent.from == vfs::ComposedFile::Extent::From::kMemory)
                        resultHash.Update(composed.memory.data() + extent.at + done, length);
                    else
                    {
                        if (extent.from == vfs::ComposedFile::Extent::From::kDisc)
                        {
                            if (!ReadFully(source, extent.at + done, buffer.data(), length))
                                return "source";
                        }
                        else
                            memset(buffer.data(), 0, length);
                        resultHash.Update(buffer.data(), length);
                    }
                    done += length;
                }
            }
            return resultHash.Finish() == piece.resultSha ? std::string() : "result";
        }

        // When memory runs out making the game with the patch, which isn't the patch's fault.
        std::string OutOfMemory(const Version& version)
        {
            return std::string("There isn't enough memory to apply the version patch ") + version.patch + ".";
        }

        // The other version's executable made into the supported version's with its patch, and its files composed.
        Check Patch(const std::string& isoPath, const Options& options, const Version& version, const std::vector<uint8_t>& xex, Game& game,
            std::string& problem)
        {
            const std::filesystem::path patchFile = options.patchDirectory.empty() ? std::filesystem::path(version.patch) : options.patchDirectory / version.patch;
            std::vector<uint8_t> bytes;
            if (!ReadWholeFile(patchFile, bytes))
            {
                // When the supported version is on no disc, every disc needs a patch: the release is missing its own.
                if (!kSupportedXex[0])
                {
                    problem = std::string("The version patch ") + version.patch + " is missing. Extract the release again.";
                    return Check::kBroken;
                }
                problem = std::string("Missing patch for ") + version.name + " disc (" + version.patch + ")";
                return Check::kOtherVersion;
            }
            // What's wrong with the patch (`where` in it, then why): it's damaged, unless memory ran out.
            const auto damaged = [&](const std::string& where, const std::string& why) {
                problem = why == patch::kOutOfMemory ? OutOfMemory(version)
                                                     : std::string("The version patch ") + version.patch + " is damaged: " + where + why + ". Extract the release again.";
                return Check::kBroken;
            };
            patch::Patch patch;
            if (const std::string why = patch::Read(bytes, patch); !why.empty())
                return damaged("", why);
            bytes = {};

            // The executable: the header and the image pieces applied to the disc's, which must give the supported version's.
            const patch::Piece* headerPiece = patch.Find("default.xex/header");
            const patch::Piece* imagePiece = patch.Find("default.xex/image");
            std::vector<uint8_t> sourceImage;
            if (!headerPiece || !imagePiece)
                return damaged("", "it has no executable");
            if (!Unpack(xex, sourceImage))
            {
                problem = "Can't unpack the game's executable from the disc image.";
                return Check::kDamaged;
            }
            const std::vector<uint8_t> sourceHeader = Header(xex);
            using Step = std::tuple<const patch::Piece*, const std::vector<uint8_t>*, std::vector<uint8_t>*>;
            for (const auto& [piece, source, result] : { Step(headerPiece, &sourceHeader, &game.xex), Step(imagePiece, &sourceImage, &game.image) })
            {
                if (const std::string why = patch::Apply(*piece, *source, *result); !why.empty())
                    return damaged(piece->name + ": ", why);
            }
            ClearCode(game.image);
            if (Sha256(game.xex.data(), game.xex.size()) != kSupportedHeader || !IsSupportedImage(game.image))
            {
                problem = "The patched game executable doesn't match the expected hash. Extract the release again.";
                return Check::kBroken;
            }

            // Its files: each other piece is a disc file, served composed. Checked once per disc image and patch.
            const std::unique_ptr<vfs::Device> device = vfs::OpenIsoDevice(isoPath);
            if (!device)
                return Check::kUnreadable;
            // Remembered with the applier's version: another applier checks again.
            const std::string checkedAs = patch::Hex(patch.sha) + ":" + std::to_string(patch::kApplierVersion);
            const bool checked = checkedAs == Remembered(options.dataDirectory, isoPath, "patched");
            for (const patch::Piece& piece : patch.pieces)
            {
                if (&piece == headerPiece || &piece == imagePiece)
                    continue;
                const std::string path = DiscPath(piece.name);
                const std::unique_ptr<vfs::File> source = OpenDiscFile(*device, path);
                const std::string wrong = "The disc image's " + piece.name + " isn't " + version.described + "'s: the disc image may be damaged.";
                if (!source || source->Info().size != piece.sourceSize)
                {
                    problem = wrong;
                    return Check::kDamaged;
                }
                const auto read = [&](uint64_t offset, uint8_t* buffer, size_t length) { return ReadFully(*source, offset, buffer, length); };
                std::vector<uint8_t> pages;
                if (piece.font.mode)
                {
                    std::vector<uint8_t> package;
                    if (!ReadAfsEntry(*source, piece.sourceSize, piece.font.entry, package))
                    {
                        problem = wrong;
                        return Check::kDamaged;
                    }
                    if (const std::string why = patch::ComposeFont(piece.font, package, sourceImage, OptionalHeader(sourceHeader, kImageBaseAddress, 0x82000000),
                            game.image, OptionalHeader(game.xex, kImageBaseAddress, 0x82000000), pages);
                        !why.empty())
                        return damaged(piece.name + ": ", why);
                }
                auto composed = std::make_shared<vfs::ComposedFile>();
                if (const std::string why = patch::Compose(piece, read, std::move(pages), *composed); !why.empty())
                    return damaged(piece.name + ": ", why);
                if (!checked)
                {
                    LOG_INFO("Checking the disc image's %s (%.0f MB) for the version patch %s, once", piece.name.c_str(), piece.sourceSize / 1e6, version.patch);
                    if (const std::string which = CheckComposed(*source, *composed, piece); !which.empty())
                    {
                        if (which == "source")
                        {
                            problem = wrong;
                            return Check::kDamaged;
                        }
                        return damaged("", piece.name + " doesn't come out as it should");
                    }
                }
                composed->sha = piece.resultSha;
                uint64_t fromDisc = 0;
                for (const vfs::ComposedFile::Extent& extent : composed->extents)
                    fromDisc += extent.from == vfs::ComposedFile::Extent::From::kDisc ? extent.length : 0;
                LOG_INFO("Version patch: the disc's %s is served as %s's (%llu bytes in %zu extents: %llu from the disc's file; %.1f MB of memory)",
                    piece.name.c_str(), GAME_DISC, (unsigned long long)composed->size, composed->extents.size(), (unsigned long long)fromDisc,
                    composed->memory.size() / 1e6);
                game.files[path] = std::move(composed);
            }
            // (A patch that composes nothing, one that makes the executable alone, has nothing to remember.)
            if (!checked && !game.files.empty())
                Remember(options.dataDirectory, isoPath, "patched", checkedAs);
            game.version = &version;
            return Check::kOk;
        }

        // A disc image's full path, size and modification time (a FILETIME), which disc_checks.txt keeps.
        bool Stamp(const std::string& isoPath, std::string& path, uint64_t& size, uint64_t& modified)
        {
            char full[MAX_PATH];
            const DWORD length = GetFullPathNameA(isoPath.c_str(), MAX_PATH, full, nullptr);
            WIN32_FILE_ATTRIBUTE_DATA attributes{};
            if (!length || length >= MAX_PATH || !GetFileAttributesExA(full, GetFileExInfoStandard, &attributes))
                return false;
            path = full;
            size = uint64_t(attributes.nFileSizeHigh) << 32 | attributes.nFileSizeLow;
            modified = uint64_t(attributes.ftLastWriteTime.dwHighDateTime) << 32 | attributes.ftLastWriteTime.dwLowDateTime;
            return true;
        }

        // disc_checks.txt's lines: "<size> <modification time> <what> <value> <path>". The ones that parse.
        struct Line
        {
            unsigned long long size = 0, modified = 0;
            std::string what, value, path, text;
        };
        std::vector<Line> ReadChecks(const std::string& dataDirectory)
        {
            std::vector<Line> lines;
            FILE* file = fopen((dataDirectory + "/disc_checks.txt").c_str(), "r");
            if (!file)
                return lines;
            char text[2048];
            while (fgets(text, sizeof(text), file))
            {
                Line line;
                char what[64] = "", value[128] = "";
                int consumed = 0;
                if (sscanf(text, "%llu %llu %63s %127s %n", &line.size, &line.modified, what, value, &consumed) < 4 || consumed <= 0)
                    continue;
                line.what = what;
                line.value = value;
                line.path = text + consumed;
                while (!line.path.empty() && (line.path.back() == '\n' || line.path.back() == '\r'))
                    line.path.pop_back();
                line.text = text;
                if (line.text.empty() || line.text.back() != '\n')
                    line.text += '\n';
                lines.push_back(std::move(line));
            }
            fclose(file);
            return lines;
        }
    }

    std::string Sha256(const uint8_t* data, size_t size)
    {
        return patch::Hex(patch::Hash(data, size));
    }

    bool IsSupported(const std::vector<uint8_t>& xex)
    {
        return IsSupportedXex(Sha256(xex.data(), xex.size()));
    }

    bool IsSupportedImage(const std::vector<uint8_t>& image)
    {
        return Sha256(image.data(), image.size()) == kSupportedImage;
    }

    Check ReadExecutable(const std::string& isoPath, std::vector<uint8_t>& xex, const Version** version)
    {
        xex.clear();
        if (version)
            *version = nullptr;
        const std::unique_ptr<vfs::Device> device = vfs::OpenIsoDevice(isoPath);
        if (!device)
            return Check::kUnreadable;
        const std::unique_ptr<vfs::File> file = OpenDiscFile(*device, "default.xex");
        if (!file)
            return Check::kUnreadable;
        const uint64_t size = file->Info().size;
        if (size == 0 || size > (256u << 20))
            return Check::kUnreadable;
        xex.resize(size_t(size));
        if (!ReadFully(*file, 0, xex.data(), xex.size()))
            return Check::kUnreadable;
        const std::string hash = Sha256(xex.data(), xex.size());
        if (IsSupportedXex(hash))
            return Check::kOk;
        for (const Version& other : kOtherVersions)
        {
            if (hash == other.xex)
            {
                if (version)
                    *version = &other;
                return Check::kOtherVersion;
            }
        }
        return Check::kOtherGame;
    }

    Check Prepare(const std::string& isoPath, const Options& options, Game& game, std::string& problem)
    {
        game = {};
        problem.clear();
        std::vector<uint8_t> xex;
        const Version* version = nullptr;
        const Check check = ReadExecutable(isoPath, xex, &version);
        // A development checkout's executable stands in for the disc's when the disc's files are the supported version's.
        const bool development = options.developmentXex && options.developmentImage &&
            (check == Check::kOk || (check == Check::kOtherVersion && version->executableOnly));
        if (check == Check::kOtherVersion && !development)
        {
            Check patched = Check::kBroken;
            try
            {
                patched = Patch(isoPath, options, *version, xex, game, problem);
            }
            catch (const std::bad_alloc&)
            {
                problem = OutOfMemory(*version);
            }
            if (patched != Check::kOk)
                game = {};
            return patched;
        }
        if (check != Check::kOk && !development)
            return check;
        if (development)
        {
            game.xex = *options.developmentXex;
            game.image = *options.developmentImage;
        }
        else
        {
            if (!Unpack(xex, game.image))
            {
                problem = "Can't unpack the game's executable from the disc image.";
                return Check::kDamaged;
            }
            game.xex = std::move(xex);
        }
        ClearCode(game.image);
        if (!IsSupportedImage(game.image))
        {
            if (!development)
            {
                problem = "The game's executable doesn't unpack into the image this build was made from.";
                return Check::kDamaged;
            }
            LOG_WARN("The data directory's default.pe, its code and .pdata cleared, isn't the image this build was made from (SHA-256 %s)",
                Sha256(game.image.data(), game.image.size()).c_str());
        }
        return Check::kOk;
    }

    bool Unpack(const std::vector<uint8_t>& xex, std::vector<uint8_t>& image)
    {
        const auto be32 = [&](size_t offset) { return Be32(xex, offset); };
        if (xex.size() < 24 || memcmp(xex.data(), "XEX2", 4) != 0)
            return false;
        const uint32_t headerSize = be32(8), security = be32(16), headers = be32(20);
        uint32_t info = 0; // the file format info
        for (uint32_t i = 0; i < headers && 32 + i * 8 <= headerSize; i++)
        {
            if (be32(24 + i * 8) == kFileFormatInfo)
                info = be32(28 + i * 8);
        }
        if (!info || headerSize > xex.size() || info + 8 > headerSize)
            return false;
        const uint32_t infoSize = be32(info);
        const uint16_t encryption = uint16_t(be32(info + 4) >> 16), compression = uint16_t(be32(info + 4));
        if ((compression != kBasicCompression && compression != kNoCompression) || infoSize < 8 || info + infoSize > headerSize)
        {
            LOG_ERROR("default.xex: compression %u isn't handled (only basic compression and none are)", compression);
            return false;
        }

        std::vector<uint8_t> payload(xex.begin() + headerSize, xex.end());
        if (encryption == kEncrypted)
        {
            uint8_t sessionKey[16];
            if (size_t(security) + 0x150 + 16 > xex.size())
                return false;
            memcpy(sessionKey, xex.data() + security + 0x150, 16);
            if (!Decrypt(kRetailKey, sessionKey, 16) || !Decrypt(sessionKey, payload.data(), payload.size() & ~size_t(15)))
                return false;
        }

        // The image is the size the security info gives. Without compression (a title update's executable as XenonUtils'
        // patcher writes it) the payload is the image.
        const uint32_t imageSize = be32(size_t(security) + 4);
        if (compression == kNoCompression)
        {
            if (payload.size() > imageSize)
                return false;
            image.assign(imageSize, 0);
            std::copy(payload.begin(), payload.end(), image.begin());
            return true;
        }
        // Basic compression: blocks of data, each followed by a run of zeros, which can cover less than the image (DOAX2's
        // last 0x8000 bytes are zeros they leave out).
        const uint32_t blocks = infoSize / 8 - 1;
        size_t total = 0;
        for (uint32_t i = 0; i < blocks; i++)
            total += size_t(be32(info + 8 + i * 8)) + be32(info + 12 + i * 8);
        if (total > imageSize)
            return false;
        image.assign(imageSize, 0);
        size_t source = 0, destination = 0;
        for (uint32_t i = 0; i < blocks; i++)
        {
            const uint32_t data = be32(info + 8 + i * 8), zeros = be32(info + 12 + i * 8);
            if (source + data > payload.size())
                return false;
            memcpy(image.data() + destination, payload.data() + source, data);
            source += data;
            destination += size_t(data) + zeros;
        }
        return true;
    }

    bool ClearCode(std::vector<uint8_t>& image)
    {
        const auto le = [&](size_t offset, size_t size) {
            uint32_t value = 0;
            memcpy(&value, image.data() + offset, size);
            return value;
        };
        if (image.size() < 0x40 || image[0] != 'M' || image[1] != 'Z')
            return false;
        const uint32_t pe = le(0x3C, 4);
        if (uint64_t(pe) + 24 > image.size() || memcmp(image.data() + pe, "PE\0\0", 4) != 0)
            return false;
        const uint32_t sections = le(pe + 6, 2), optional = le(pe + 20, 2);
        const uint64_t table = uint64_t(pe) + 24 + optional;
        if (table + uint64_t(sections) * 40 > image.size())
            return false;
        // The sections' ranges first, then cleared (one could hold the headers).
        constexpr uint32_t kCode = 0x00000020, kExecute = 0x20000000; // IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE
        std::vector<std::pair<size_t, size_t>> cleared;
        for (uint32_t i = 0; i < sections; i++)
        {
            const size_t entry = size_t(table) + i * 40;
            char name[9] = {};
            memcpy(name, image.data() + entry, 8);
            const uint32_t size = le(entry + 8, 4), address = le(entry + 12, 4), flags = le(entry + 36, 4);
            if ((flags & (kCode | kExecute)) || strcmp(name, ".pdata") == 0)
                cleared.emplace_back(address, size);
        }
        for (const auto& [address, size] : cleared)
        {
            if (address < image.size())
                memset(image.data() + address, 0, std::min(size, image.size() - address));
        }
        return true;
    }

    std::string Remembered(const std::string& dataDirectory, const std::string& isoPath, const std::string& what)
    {
        std::string path;
        uint64_t size = 0, modified = 0;
        if (dataDirectory.empty() || !Stamp(isoPath, path, size, modified))
            return {};
        std::string value;
        for (const Line& line : ReadChecks(dataDirectory))
        {
            if (line.size == size && line.modified == modified && line.what == what && _stricmp(line.path.c_str(), path.c_str()) == 0)
                value = line.value;
        }
        return value;
    }

    void Remember(const std::string& dataDirectory, const std::string& isoPath, const std::string& what, const std::string& value)
    {
        std::string path;
        uint64_t size = 0, modified = 0;
        if (dataDirectory.empty() || !Stamp(isoPath, path, size, modified))
            return;
        // The other lines as they were, this one new; written beside it first, so a reader never sees half of it.
        std::string text;
        for (const Line& line : ReadChecks(dataDirectory))
        {
            if (line.what != what || _stricmp(line.path.c_str(), path.c_str()) != 0)
                text += line.text;
        }
        char line[2048];
        snprintf(line, sizeof(line), "%llu %llu %s %s %s\n", (unsigned long long)size, (unsigned long long)modified, what.c_str(), value.c_str(), path.c_str());
        text += line;
        CreateDirectoryA(dataDirectory.c_str(), nullptr); // (the launcher's data folder, before it remembers the disc image)
        const std::string target = dataDirectory + "/disc_checks.txt", temporary = target + ".new";
        FILE* file = fopen(temporary.c_str(), "wb");
        if (!file)
            return;
        const bool written = fwrite(text.data(), 1, text.size(), file) == text.size();
        if (fclose(file) == 0 && written && MoveFileExA(temporary.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING))
            return;
        DeleteFileA(temporary.c_str());
    }
}
