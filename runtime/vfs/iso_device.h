#pragma once

#include "vfs/vfs.h"

#include <array>
#include <map>

namespace vfs
{
    // A disc file served as another version's (a version patch's result, version_patch.h): `size` bytes made of extents,
    // in order and without gaps, each from the disc's own file at an offset, from `memory`, or zeros.
    struct ComposedFile
    {
        struct Extent
        {
            enum class From : uint8_t
            {
                kDisc,
                kMemory,
                kZero,
            };
            uint64_t offset = 0; // in the file served
            uint64_t length = 0;
            From from = From::kZero;
            uint64_t at = 0; // in the disc's file, or in `memory`
        };
        uint64_t size = 0;
        std::vector<Extent> extents;
        std::vector<uint8_t> memory;
        // Its contents' SHA-256 as what made it records it (a version patch, which checks it once per disc image), for
        // what's kept about the disc's files as served (netplay's identity).
        std::array<uint8_t, 32> sha{};
    };
    // By path on the disc, in lower case, '\'-separated.
    using ComposedFiles = std::map<std::string, std::shared_ptr<const ComposedFile>>;

    // Read-only XDVDFS (Xbox game disc) file system read directly from a disc image; the files `composed` names are served
    // as composed instead (each one's extents from the disc read the disc's file of that path).
    std::unique_ptr<Device> OpenIsoDevice(const std::string& isoPath, ComposedFiles composed = {});

    // A writable device backed by a host directory (created if missing).
    std::unique_ptr<Device> OpenHostDevice(const std::string& name, const std::string& hostDirectory);

    // A hard disk partition: its file system is a host directory (none if `hostDirectory` is empty: Partition0, the whole
    // disk, has none), and opening the partition itself gives its raw sectors, kept in the sparse host file `rawStore`.
    // The partition's place on the disk (`offset`, `length`) is what the disk queries report. Formatting it as FATX
    // writes a superblock there, whose cluster size the file system then reports.
    struct PartitionLayout
    {
        uint64_t offset = 0;
        uint64_t length = 0;
    };
    std::unique_ptr<Device> OpenHardDiskPartition(const std::string& name, const std::string& hostDirectory, const std::string& rawStore,
        PartitionLayout layout);
}
