// XDVDFS disc image device. The directory tree is parsed once at mount; reads go straight to the image, but for composed
// files (a version patch's), whose extents read the image, memory or zeros.
#include "vfs/iso_device.h"

#include "kernel/status.h"
#include "log.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string_view>

#include <windows.h>

namespace vfs
{
    namespace
    {
        constexpr uint64_t kSectorSize = 2048;
        constexpr char kMagic[] = "MICROSOFT*XBOX*MEDIA";
        // Game partition offsets: plain XISO, XGD1, XGD2, XGD3.
        constexpr uint64_t kPartitionOffsets[] = { 0, 0x18300000, 0xFD90000, 0x2080000 };

        std::string Lower(std::string_view text)
        {
            std::string result(text);
            std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) { return char(std::tolower(c)); });
            return result;
        }

        struct Node
        {
            EntryInfo info;
            uint64_t offset = 0; // byte offset of the data in the image
            std::vector<std::string> children; // lower-case paths of direct children
        };

        class IsoImage
        {
        public:
            HANDLE file = INVALID_HANDLE_VALUE;
            uint64_t imageSize = 0;
            uint64_t partition = 0;
            uint64_t creationTime = 0;
            std::map<std::string, Node> nodes; // lower-case relative path -> node ("" is the root)
            ComposedFiles composed;            // the files served composed, by the same paths

            // A node's entry as served: a composed file's size instead of the disc's.
            EntryInfo Served(const std::string& key, const Node& node) const
            {
                EntryInfo info = node.info;
                if (const auto it = composed.find(key); it != composed.end() && !info.isDirectory)
                {
                    info.size = it->second->size;
                    info.allocationSize = (info.size + kSectorSize - 1) / kSectorSize * kSectorSize;
                }
                return info;
            }

            ~IsoImage()
            {
                if (file != INVALID_HANDLE_VALUE)
                    CloseHandle(file);
            }

            bool ReadAt(uint64_t offset, void* buffer, uint32_t length, uint32_t& transferred) const
            {
                OVERLAPPED overlapped{};
                overlapped.Offset = DWORD(offset);
                overlapped.OffsetHigh = DWORD(offset >> 32);
                DWORD read = 0;
                const BOOL ok = ReadFile(file, buffer, length, &read, &overlapped);
                transferred = read;
                return ok || GetLastError() == ERROR_HANDLE_EOF;
            }

            bool ReadExact(uint64_t offset, void* buffer, uint32_t length) const
            {
                uint32_t transferred = 0;
                return ReadAt(offset, buffer, length, transferred) && transferred == length;
            }

            // Parses a directory's binary tree of entries into `nodes`.
            bool ParseDirectory(const std::string& path, uint32_t sector, uint32_t size, int depth)
            {
                if (depth > 32 || size == 0)
                    return true;
                std::vector<uint8_t> table(size);
                if (!ReadExact(partition + sector * kSectorSize, table.data(), size))
                    return false;

                std::vector<uint32_t> stack{ 0 };
                std::vector<bool> seen(size / 4 + 1);
                while (!stack.empty())
                {
                    const uint32_t offset = stack.back();
                    stack.pop_back();
                    if (offset + 14 > size || seen[offset / 4])
                        continue;
                    seen[offset / 4] = true;

                    uint16_t left, right;
                    uint32_t entrySector, entrySize;
                    memcpy(&left, &table[offset], 2);
                    memcpy(&right, &table[offset + 2], 2);
                    memcpy(&entrySector, &table[offset + 4], 4);
                    memcpy(&entrySize, &table[offset + 8], 4);
                    const uint8_t attributes = table[offset + 12];
                    const uint8_t nameLength = table[offset + 13];
                    if (left == 0xFFFF) // padding
                        continue;
                    if (offset + 14 + nameLength > size)
                        continue;

                    const std::string name(reinterpret_cast<const char*>(&table[offset + 14]), nameLength);
                    const std::string childPath = path.empty() ? name : path + "\\" + name;
                    Node node;
                    node.info.name = name;
                    node.info.isDirectory = attributes & kAttributeDirectory;
                    node.info.size = node.info.isDirectory ? 0 : entrySize;
                    node.info.allocationSize = (uint64_t(entrySize) + kSectorSize - 1) / kSectorSize * kSectorSize;
                    node.info.attributes = (attributes & kAttributeDirectory) ? kAttributeDirectory : kAttributeReadOnly;
                    node.info.creationTime = node.info.accessTime = node.info.writeTime = creationTime;
                    node.offset = partition + uint64_t(entrySector) * kSectorSize;
                    nodes[Lower(path)].children.push_back(Lower(childPath));
                    const std::string key = Lower(childPath);
                    nodes[key] = node;

                    if (node.info.isDirectory && !ParseDirectory(childPath, entrySector, entrySize, depth + 1))
                        return false;
                    if (left)
                        stack.push_back(uint32_t(left) * 4);
                    if (right)
                        stack.push_back(uint32_t(right) * 4);
                }
                return true;
            }
        };

        class IsoFile : public File
        {
        public:
            IsoFile(std::shared_ptr<const IsoImage> image, const Node& node) : m_image(std::move(image)), m_node(node) {}

            const EntryInfo& Info() const override { return m_node.info; }

            uint32_t Read(void* buffer, uint32_t length, uint64_t offset, uint32_t& transferred) override
            {
                transferred = 0;
                if (m_node.info.isDirectory)
                    return status::kInvalidParameter;
                if (offset >= m_node.info.size)
                    return status::kEndOfFile;
                const uint32_t count = uint32_t(std::min<uint64_t>(length, m_node.info.size - offset));
                return m_image->ReadAt(m_node.offset + offset, buffer, count, transferred) ? status::kSuccess : status::kUnsuccessful;
            }

            uint32_t Write(const void*, uint32_t, uint64_t, uint32_t& transferred) override
            {
                transferred = 0;
                return status::kAccessDenied;
            }

            uint32_t SetSize(uint64_t) override { return status::kAccessDenied; }
            uint32_t SetDeleteOnClose() override { return status::kAccessDenied; }

            std::vector<EntryInfo> List() const override
            {
                std::vector<EntryInfo> entries;
                for (const std::string& child : m_node.children)
                    entries.push_back(m_image->Served(child, m_image->nodes.at(child)));
                return entries;
            }

        private:
            std::shared_ptr<const IsoImage> m_image;
            const Node& m_node;
        };

        // A composed file: its extents read the disc's file of the same path (`node`), memory or zeros.
        class ComposedIsoFile : public File
        {
        public:
            ComposedIsoFile(std::shared_ptr<const IsoImage> image, const Node& node, std::shared_ptr<const ComposedFile> composed, const EntryInfo& info)
                : m_image(std::move(image)), m_node(node), m_composed(std::move(composed)), m_info(info)
            {
            }

            const EntryInfo& Info() const override { return m_info; }

            uint32_t Read(void* buffer, uint32_t length, uint64_t offset, uint32_t& transferred) override
            {
                transferred = 0;
                const ComposedFile& file = *m_composed;
                if (offset >= file.size)
                    return status::kEndOfFile;
                const uint32_t count = uint32_t(std::min<uint64_t>(length, file.size - offset));
                // The extent holding `offset`, then on from there.
                auto extent = std::upper_bound(file.extents.begin(), file.extents.end(), offset,
                    [](uint64_t at, const ComposedFile::Extent& e) { return at < e.offset; });
                if (extent == file.extents.begin())
                    return status::kUnsuccessful;
                --extent;
                auto* out = static_cast<uint8_t*>(buffer);
                while (transferred < count && extent != file.extents.end())
                {
                    const uint64_t position = offset + transferred, within = position - extent->offset;
                    const uint32_t part = uint32_t(std::min<uint64_t>(count - transferred, extent->length - within));
                    switch (extent->from)
                    {
                    case ComposedFile::Extent::From::kDisc:
                        if (uint32_t read = 0; !m_image->ReadAt(m_node.offset + extent->at + within, out + transferred, part, read) || read != part)
                            return status::kUnsuccessful;
                        break;
                    case ComposedFile::Extent::From::kMemory:
                        memcpy(out + transferred, file.memory.data() + extent->at + within, part);
                        break;
                    case ComposedFile::Extent::From::kZero:
                        memset(out + transferred, 0, part);
                        break;
                    }
                    transferred += part;
                    ++extent;
                }
                return transferred == count ? status::kSuccess : status::kUnsuccessful;
            }

            uint32_t Write(const void*, uint32_t, uint64_t, uint32_t& transferred) override
            {
                transferred = 0;
                return status::kAccessDenied;
            }

            uint32_t SetSize(uint64_t) override { return status::kAccessDenied; }
            uint32_t SetDeleteOnClose() override { return status::kAccessDenied; }

        private:
            std::shared_ptr<const IsoImage> m_image;
            const Node& m_node;
            std::shared_ptr<const ComposedFile> m_composed;
            EntryInfo m_info;
        };

        // DEBUG_DISC_FILE=<path on the disc>=<host file>[;...] (development): a file of the disc image is served from a
        // host file instead, read-only, with that file's size, before a version patch's composed file; the disc must have
        // the file. How the version patches' files were first tried in the game (analysis/version_patches.md, test 2).
        const std::map<std::string, std::string>& DiscFileOverrides()
        {
            static const std::map<std::string, std::string> overrides = [] {
                std::map<std::string, std::string> result;
                const char* setting = std::getenv(GAME_PREFIX "_DEBUG_DISC_FILE");
                for (std::string_view rest = setting ? setting : ""; !rest.empty();)
                {
                    const size_t end = std::min(rest.find(';'), rest.size());
                    const std::string_view item = rest.substr(0, end);
                    rest.remove_prefix(std::min(end + 1, rest.size()));
                    const size_t equals = item.find('=');
                    if (equals == std::string_view::npos || equals + 1 == item.size())
                        continue;
                    std::string path = Lower(item.substr(0, equals));
                    std::replace(path.begin(), path.end(), '/', '\\');
                    path.erase(0, std::min(path.find_first_not_of('\\'), path.size()));
                    result[path] = std::string(item.substr(equals + 1));
                }
                return result;
            }();
            return overrides;
        }

        class OverrideFile : public File
        {
        public:
            OverrideFile(HANDLE file, const EntryInfo& info) : m_file(file), m_info(info) {}
            ~OverrideFile() override { CloseHandle(m_file); }

            const EntryInfo& Info() const override { return m_info; }

            uint32_t Read(void* buffer, uint32_t length, uint64_t offset, uint32_t& transferred) override
            {
                transferred = 0;
                if (offset >= m_info.size)
                    return status::kEndOfFile;
                OVERLAPPED overlapped{};
                overlapped.Offset = DWORD(offset);
                overlapped.OffsetHigh = DWORD(offset >> 32);
                DWORD read = 0;
                const BOOL ok = ReadFile(m_file, buffer, DWORD(std::min<uint64_t>(length, m_info.size - offset)), &read, &overlapped);
                transferred = read;
                return ok || GetLastError() == ERROR_HANDLE_EOF ? status::kSuccess : status::kUnsuccessful;
            }

            uint32_t Write(const void*, uint32_t, uint64_t, uint32_t& transferred) override
            {
                transferred = 0;
                return status::kAccessDenied;
            }

            uint32_t SetSize(uint64_t) override { return status::kAccessDenied; }
            uint32_t SetDeleteOnClose() override { return status::kAccessDenied; }

        private:
            HANDLE m_file;
            EntryInfo m_info;
        };

        // A disc file's entry as DEBUG_DISC_FILE serves it (the host file's size), and the host file opened if `handle`
        // isn't null. False if no override names the file; an override whose host file can't be opened is an error.
        bool Overridden(const std::string& key, const Node& node, EntryInfo& info, HANDLE* handle, uint32_t& code)
        {
            const auto it = DiscFileOverrides().find(key);
            if (it == DiscFileOverrides().end() || node.info.isDirectory)
                return false;
            const HANDLE file = CreateFileA(it->second.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, nullptr);
            LARGE_INTEGER size{};
            if (file == INVALID_HANDLE_VALUE || !GetFileSizeEx(file, &size))
            {
                if (file != INVALID_HANDLE_VALUE)
                    CloseHandle(file);
                LOG_ERROR("DEBUG_DISC_FILE: can't open %s for the disc's %s", it->second.c_str(), key.c_str());
                code = status::kObjectNameNotFound;
                return true;
            }
            info = node.info;
            info.size = uint64_t(size.QuadPart);
            info.allocationSize = (info.size + kSectorSize - 1) / kSectorSize * kSectorSize;
            if (handle)
            {
                *handle = file;
                LOG_INFO("DEBUG_DISC_FILE: the disc's %s is served from %s (%llu bytes)", key.c_str(), it->second.c_str(), (unsigned long long)info.size);
            }
            else
                CloseHandle(file);
            code = status::kSuccess;
            return true;
        }

        class IsoDevice : public Device
        {
        public:
            explicit IsoDevice(std::shared_ptr<IsoImage> image) : m_image(std::move(image)) {}

            const char* Name() const override { return "disc image"; }
            bool ReadOnly() const override { return true; }

            uint32_t Open(const OpenRequest& request, std::unique_ptr<File>& file, OpenResult& result) override
            {
                const auto it = m_image->nodes.find(Lower(request.path));
                if (it == m_image->nodes.end())
                {
                    // Distinguish a missing parent directory from a missing file, as the kernel does.
                    const size_t slash = request.path.rfind('\\');
                    const bool parentExists = slash == std::string::npos || m_image->nodes.count(Lower(request.path.substr(0, slash)));
                    if (request.disposition != Disposition::Open && request.disposition != Disposition::Overwrite)
                        return status::kAccessDenied; // can't create on a read-only disc
                    return parentExists ? status::kObjectNameNotFound : status::kObjectPathNotFound;
                }
                const Node& node = it->second;
                if (request.write || (request.disposition != Disposition::Open && request.disposition != Disposition::OpenIf))
                    return status::kAccessDenied;
                if (request.directory && !node.info.isDirectory)
                    return 0xC0000103; // STATUS_NOT_A_DIRECTORY
                if (request.nonDirectory && node.info.isDirectory)
                    return 0xC00000BA; // STATUS_FILE_IS_A_DIRECTORY
                EntryInfo info;
                HANDLE host = INVALID_HANDLE_VALUE;
                if (uint32_t code = 0; Overridden(it->first, node, info, &host, code))
                {
                    if (code != status::kSuccess)
                        return code;
                    file = std::make_unique<OverrideFile>(host, info);
                    result = OpenResult::Opened;
                    return status::kSuccess;
                }
                if (const auto composed = m_image->composed.find(it->first); composed != m_image->composed.end() && !node.info.isDirectory)
                    file = std::make_unique<ComposedIsoFile>(m_image, node, composed->second, m_image->Served(it->first, node));
                else
                    file = std::make_unique<IsoFile>(m_image, node);
                result = OpenResult::Opened;
                return status::kSuccess;
            }

            uint32_t Query(const std::string& path, EntryInfo& info) override
            {
                const auto it = m_image->nodes.find(Lower(path));
                if (it == m_image->nodes.end())
                    return status::kObjectNameNotFound;
                if (uint32_t code = 0; Overridden(it->first, it->second, info, nullptr, code))
                    return code;
                info = m_image->Served(it->first, it->second);
                return status::kSuccess;
            }

            uint64_t TotalBytes() const override { return m_image->imageSize - m_image->partition; }
            uint64_t FreeBytes() const override { return 0; }
            const char* FileSystemName() const override { return "GDFX"; }

        private:
            std::shared_ptr<IsoImage> m_image;
        };
    }

    std::unique_ptr<Device> OpenIsoDevice(const std::string& isoPath, ComposedFiles composed)
    {
        auto image = std::make_shared<IsoImage>();
        image->file = CreateFileA(isoPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, nullptr);
        if (image->file == INVALID_HANDLE_VALUE)
        {
            LOG_ERROR("Can't open disc image %s", isoPath.c_str());
            return nullptr;
        }

        LARGE_INTEGER size;
        GetFileSizeEx(image->file, &size);
        image->imageSize = uint64_t(size.QuadPart);
        FILETIME writeTime;
        GetFileTime(image->file, nullptr, nullptr, &writeTime);
        image->creationTime = (uint64_t(writeTime.dwHighDateTime) << 32) | writeTime.dwLowDateTime;

        bool found = false;
        uint8_t descriptor[0x800];
        for (uint64_t partition : kPartitionOffsets)
        {
            if (partition + 33 * kSectorSize <= image->imageSize && image->ReadExact(partition + 32 * kSectorSize, descriptor, sizeof(descriptor)) &&
                memcmp(descriptor, kMagic, sizeof(kMagic) - 1) == 0)
            {
                image->partition = partition;
                found = true;
                break;
            }
        }
        if (!found)
        {
            LOG_ERROR("%s isn't an Xbox disc image (no XDVDFS volume descriptor)", isoPath.c_str());
            return nullptr;
        }

        uint32_t rootSector, rootSize;
        memcpy(&rootSector, descriptor + 20, 4);
        memcpy(&rootSize, descriptor + 24, 4);
        // Files' times are the volume's, from when the disc was mastered (the image file's own time if it has none):
        // the same wherever the image is kept, which matters to a game comparing them with files it copied.
        uint64_t volumeTime;
        memcpy(&volumeTime, descriptor + 28, 8);
        if (volumeTime)
            image->creationTime = volumeTime;

        Node& root = image->nodes[""];
        root.info.isDirectory = true;
        root.info.attributes = kAttributeDirectory;
        root.info.creationTime = root.info.accessTime = root.info.writeTime = image->creationTime;
        if (!image->ParseDirectory("", rootSector, rootSize, 0))
        {
            LOG_ERROR("Failed to read the directory tree of %s", isoPath.c_str());
            return nullptr;
        }
        // A composed file's extents follow each other to its end, and those from the disc lie in the disc's file it stands
        // for.
        for (const auto& [path, file] : composed)
        {
            const auto node = image->nodes.find(path);
            if (node == image->nodes.end() || node->second.info.isDirectory)
            {
                LOG_ERROR("%s has no file %s to compose", isoPath.c_str(), path.c_str());
                return nullptr;
            }
            uint64_t end = 0;
            for (const ComposedFile::Extent& extent : file->extents)
            {
                const uint64_t limit = extent.from == ComposedFile::Extent::From::kDisc ? node->second.info.size
                    : extent.from == ComposedFile::Extent::From::kMemory                ? file->memory.size()
                                                                                        : UINT64_MAX;
                if (extent.offset != end || extent.length > file->size - end || extent.at > limit || extent.length > limit - extent.at)
                {
                    LOG_ERROR("%s: the composed %s's extents aren't in order, or lie outside its sources", isoPath.c_str(), path.c_str());
                    return nullptr;
                }
                end += extent.length;
            }
            if (end != file->size)
            {
                LOG_ERROR("%s: the composed %s's extents don't reach its end", isoPath.c_str(), path.c_str());
                return nullptr;
            }
        }
        image->composed = std::move(composed);

        LOG_INFO("Disc image %s: partition at 0x%llX, %zu entries%s", isoPath.c_str(), (unsigned long long)image->partition, image->nodes.size() - 1,
            image->composed.empty() ? "" : (", " + std::to_string(image->composed.size()) + " served composed").c_str());
        return std::make_unique<IsoDevice>(std::move(image));
    }
}
