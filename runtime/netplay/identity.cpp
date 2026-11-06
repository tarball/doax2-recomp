#include "netplay/identity.h"

#include "config.h"
#include "disc_image.h"
#include "log.h"
#include "netplay/game_state.h"
#include "vfs/vfs.h"

#define XXH_INLINE_ALL
#include <xxhash.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include <intrin.h>
#include <windows.h>

#ifndef GAME_BUILD_CONFIG
#define GAME_BUILD_CONFIG "unknown"
#endif

namespace netplay::identity
{
    namespace
    {
        bool ReadFileBytes(const wchar_t* path, std::vector<uint8_t>& data)
        {
            const HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return false;
            LARGE_INTEGER size{};
            bool ok = GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart < (1ll << 31);
            if (ok)
            {
                data.resize(size_t(size.QuadPart));
                DWORD read = 0;
                ok = ReadFile(file, data.data(), DWORD(data.size()), &read, nullptr) && read == data.size();
            }
            CloseHandle(file);
            return ok;
        }

        // The file offset of an RVA, through the section headers.
        std::optional<size_t> FileOffset(const IMAGE_NT_HEADERS64& nt, uint32_t rva)
        {
            const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(&nt);
            for (uint32_t i = 0; i < nt.FileHeader.NumberOfSections; i++, section++)
            {
                if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->SizeOfRawData)
                    return size_t(section->PointerToRawData) + (rva - section->VirtualAddress);
            }
            return std::nullopt;
        }

        // Blanks what differs between links of the same code (BuildId).
        void BlankLinkDetails(std::vector<uint8_t>& data)
        {
            if (data.size() < sizeof(IMAGE_DOS_HEADER))
                return;
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || size_t(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > data.size())
                return;
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(data.data() + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return;
            nt->FileHeader.TimeDateStamp = 0;
            nt->OptionalHeader.CheckSum = 0;
            const IMAGE_DATA_DIRECTORY debug = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            const std::optional<size_t> offset = FileOffset(*nt, debug.VirtualAddress);
            if (!debug.VirtualAddress || !offset || *offset + debug.Size > data.size())
                return;
            for (size_t entry = *offset; entry + sizeof(IMAGE_DEBUG_DIRECTORY) <= *offset + debug.Size; entry += sizeof(IMAGE_DEBUG_DIRECTORY))
            {
                const auto* directory = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(data.data() + entry);
                if (directory->PointerToRawData && size_t(directory->PointerToRawData) + directory->SizeOfData <= data.size())
                    memset(data.data() + directory->PointerToRawData, 0, directory->SizeOfData);
                memset(data.data() + entry, 0, sizeof(IMAGE_DEBUG_DIRECTORY));
            }
        }

        // The disc's identity: 0 not looked for yet, 1 being found, 2 known, 3 its files couldn't be read.
        std::atomic<int> g_discState{ 0 };
        std::atomic<uint64_t> g_discHash{ 0 };
        // The executable's hash, and the disc's files served composed (SetGame).
        uint64_t g_executableHash = 0;
        vfs::ComposedFiles g_composed;
        // How the files' hash is made: changed with HashFiles, so that a hash an earlier build kept isn't taken for one.
        constexpr char kFilesScheme[] = "files as served: path, size and XXH3, by path; 1";

        std::string Lower(std::string text)
        {
            std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return char(std::tolower(c)); });
            return text;
        }

        // Whether the identity leaves out a file or folder of the disc (lower case, '\'-separated): default.xex, which the
        // executable stands for, and the game's own list, in which a folder ends with '\'.
        bool LeftOut(const std::string& path, bool directory, const std::vector<std::string>& leaveOut)
        {
            if (path == "default.xex")
                return true;
            for (const std::string& item : leaveOut)
            {
                const std::string lower = Lower(item);
                if (lower.empty())
                    continue;
                if (path == lower || (directory && path + "\\" == lower) || (lower.back() == '\\' && path.rfind(lower, 0) == 0))
                    return true;
            }
            return false;
        }

        struct FileHash
        {
            std::string path; // lower case
            uint64_t size = 0, hash = 0;
        };

        // The files of a folder of the disc and of the folders in it, each hashed as the device serves it.
        bool HashFolder(vfs::Device& device, const std::string& folder, const std::vector<std::string>& leaveOut, std::vector<uint8_t>& buffer,
            std::vector<FileHash>& files)
        {
            vfs::OpenRequest request;
            request.path = folder;
            request.directory = true;
            std::unique_ptr<vfs::File> directory;
            vfs::OpenResult result;
            if (device.Open(request, directory, result) != 0 || !directory)
                return false;
            for (const vfs::EntryInfo& entry : directory->List())
            {
                const std::string path = Lower(folder.empty() ? entry.name : folder + "\\" + entry.name);
                if (LeftOut(path, entry.isDirectory, leaveOut))
                    continue;
                if (entry.isDirectory)
                {
                    if (!HashFolder(device, path, leaveOut, buffer, files))
                        return false;
                    continue;
                }
                request = {};
                request.path = path;
                request.nonDirectory = true;
                std::unique_ptr<vfs::File> file;
                if (device.Open(request, file, result) != 0 || !file)
                    return false;
                XXH3_state_t* state = XXH3_createState();
                bool ok = state && XXH3_64bits_reset(state) == XXH_OK;
                const uint64_t size = file->Info().size;
                for (uint64_t at = 0; ok && at < size;)
                {
                    const uint32_t length = uint32_t(std::min<uint64_t>(buffer.size(), size - at));
                    uint32_t read = 0;
                    ok = file->Read(buffer.data(), length, at, read) == 0 && read == length;
                    if (ok)
                        XXH3_64bits_update(state, buffer.data(), length);
                    at += length;
                }
                if (ok)
                    files.push_back(FileHash{ path, size, XXH3_64bits_digest(state) });
                if (state)
                    XXH3_freeState(state);
                if (!ok)
                    return false;
            }
            return true;
        }

        // The disc's files' hash, as the game's disc device serves them (another device on the same image, the same
        // composed files, so that its reads don't wait on the game's handle, or the game's on them): each file's path, size
        // and contents' hash, by path.
        std::optional<uint64_t> HashFiles(const std::string& image, const std::vector<std::string>& leaveOut)
        {
            const std::unique_ptr<vfs::Device> device = vfs::OpenIsoDevice(image, g_composed);
            std::vector<uint8_t> buffer(8 << 20);
            std::vector<FileHash> files;
            if (!device || !HashFolder(*device, "", leaveOut, buffer, files))
                return std::nullopt;
            std::sort(files.begin(), files.end(), [](const FileHash& a, const FileHash& b) { return a.path < b.path; });
            XXH3_state_t* state = XXH3_createState();
            if (!state || XXH3_64bits_reset(state) != XXH_OK)
            {
                if (state)
                    XXH3_freeState(state);
                return std::nullopt;
            }
            for (const FileHash& file : files)
            {
                XXH3_64bits_update(state, file.path.c_str(), file.path.size() + 1);
                XXH3_64bits_update(state, &file.size, sizeof(file.size));
                XXH3_64bits_update(state, &file.hash, sizeof(file.hash));
            }
            const uint64_t hash = XXH3_64bits_digest(state);
            XXH3_freeState(state);
            return hash;
        }

        // The disc's identity: its files' hash and the executable's.
        uint64_t Identity(uint64_t files)
        {
            const uint64_t parts[2] = { files, g_executableHash };
            return XXH3_64bits(parts, sizeof(parts));
        }

        // What the files' hash of a disc image comes from besides its bytes: how it's made, what it leaves out, and the
        // files served composed (their contents' SHA-256s). disc_checks.txt keeps a hash with this: one kept with other
        // inputs (an earlier release's, extracted over) isn't taken.
        uint64_t Inputs(const std::vector<std::string>& leaveOut)
        {
            std::string text = kFilesScheme;
            for (const std::string& item : leaveOut)
                text += '\0' + Lower(item);
            text += '\0';
            for (const auto& [path, file] : g_composed)
                text += '\0' + path + '\0' + std::string(file->sha.begin(), file->sha.end());
            return XXH3_64bits(text.data(), text.size());
        }
    }

    uint64_t BuildId()
    {
        static const uint64_t id = [] {
            wchar_t path[MAX_PATH];
            const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
            std::vector<uint8_t> data;
            if (!length || length >= MAX_PATH || !ReadFileBytes(path, data))
            {
                LOG_WARN("Netplay: can't read the game's executable to identify its build");
                return uint64_t(0);
            }
            BlankLinkDetails(data);
            uint64_t hash = XXH3_64bits(data.data(), data.size());
            // And the game's code module next to it (ANALYSIS.md, Phase 5, The game's code module), which every PC builds
            // from its own copy of the game, byte for byte the same file for the same build and disc. Without one (the
            // runtime's tests), the executable's alone.
            std::wstring module(path);
            module = module.substr(0, module.find_last_of(L"\\/") + 1) + L"" GAME_EXECUTABLE "_ppc.dll";
            if (std::vector<uint8_t> code; ReadFileBytes(module.c_str(), code))
            {
                BlankLinkDetails(code);
                hash = XXH3_64bits_withSeed(code.data(), code.size(), hash);
            }
            return hash;
        }();
        return id;
    }

    const char* BuildConfiguration()
    {
        return GAME_BUILD_CONFIG;
    }

    void SetGame(const std::vector<uint8_t>& xex, const std::vector<uint8_t>& image, const vfs::ComposedFiles& composed)
    {
        // The XEX header (the file's first bytes, as many as it says), then the image.
        size_t header = xex.size();
        if (xex.size() >= 12)
            header = std::min<size_t>(header, size_t(xex[8]) << 24 | size_t(xex[9]) << 16 | size_t(xex[10]) << 8 | xex[11]);
        g_executableHash = XXH3_64bits_withSeed(image.data(), image.size(), XXH3_64bits(xex.data(), header));
        g_composed = composed;
    }

    void StartDiscHash()
    {
        static std::once_flag once;
        std::call_once(once, [] {
            const std::string path = config::DiscImage();
            const GameState* game = GetGameState();
            const std::vector<std::string> leaveOut = game ? game->identityLeavesOut : std::vector<std::string>();
            // Kept as "<the inputs' hash>-<the files' hash>", but while a file is served from elsewhere (DEBUG_DISC_FILE).
            char inputs[17];
            snprintf(inputs, sizeof(inputs), "%016llX", (unsigned long long)Inputs(leaveOut));
            const char* overrides = std::getenv(GAME_PREFIX "_DEBUG_DISC_FILE");
            const bool keep = !overrides || !*overrides;
            if (const std::string remembered = keep ? disc::Remembered(config::DataDirectory(), path, "identity") : std::string();
                remembered.size() == 33 && remembered.compare(0, 16, inputs) == 0 && remembered[16] == '-')
            {
                const uint64_t files = strtoull(remembered.c_str() + 17, nullptr, 16);
                g_discHash = Identity(files);
                g_discState = 2;
                LOG_INFO("Netplay: the disc's identity is %016llX (its files' %016llX, from disc_checks.txt)", (unsigned long long)g_discHash.load(),
                    (unsigned long long)files);
                return;
            }
            g_discState = 1;
            LOG_INFO("Netplay: hashing the disc's files to identify them (%s)",
                keep ? "once for this disc image: disc_checks.txt keeps it" : "every time, DEBUG_DISC_FILE serving a file from elsewhere");
            std::thread([path, leaveOut, keep, inputs = std::string(inputs)] {
                // Below the game's threads, and with low memory priority, so that the file cache's pages it reads go before
                // the game's own.
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
                MEMORY_PRIORITY_INFORMATION memory{ MEMORY_PRIORITY_LOW };
                SetThreadInformation(GetCurrentThread(), ThreadMemoryPriority, &memory, sizeof(memory));
                const auto begin = std::chrono::steady_clock::now();
                const std::optional<uint64_t> files = HashFiles(path, leaveOut);
                const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - begin).count();
                if (files)
                {
                    char text[17];
                    snprintf(text, sizeof(text), "%016llX", (unsigned long long)*files);
                    if (keep)
                        disc::Remember(config::DataDirectory(), path, "identity", inputs + "-" + text);
                    g_discHash = Identity(*files);
                    LOG_INFO("Netplay: the disc's identity is %016llX (its files' %016llX, %.1f s)", (unsigned long long)g_discHash.load(),
                        (unsigned long long)*files, seconds);
                    g_discState = 2;
                }
                else
                {
                    LOG_ERROR("Netplay: can't read the disc's files to identify them (a file runs past the disc image's end?)");
                    g_discState = 3;
                }
            }).detach();
        });
    }

    std::optional<uint64_t> DiscHash()
    {
        if (g_discState.load() != 2)
            return std::nullopt;
        return g_discHash.load();
    }

    bool DiscHashFailed()
    {
        return g_discState.load() == 3;
    }

    std::string Machine()
    {
        int info[4] = {};
        char brand[49] = {};
        __cpuid(info, int(0x80000000));
        if (uint32_t(info[0]) >= 0x80000004)
        {
            for (int i = 0; i < 3; i++)
            {
                __cpuid(info, int(0x80000002 + i));
                memcpy(brand + 16 * i, info, 16);
            }
        }
        const char* name = brand;
        while (*name == ' ')
            name++;
        for (size_t end = strlen(brand); end > 0 && brand[end - 1] == ' '; end--)
            brand[end - 1] = 0;
        __cpuid(info, 1);
        const bool fma3 = info[2] & (1 << 12);
        using RtlGetVersionFunction = LONG(WINAPI*)(OSVERSIONINFOW*);
        OSVERSIONINFOW version{ sizeof(version) };
        if (const auto get = reinterpret_cast<RtlGetVersionFunction>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion")))
            get(&version);
        char text[160];
        snprintf(text, sizeof(text), "%s (FMA3 %s), Windows %lu.%lu.%lu", *name ? name : "unknown CPU", fma3 ? "yes" : "no",
            version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber);
        return text;
    }
}
