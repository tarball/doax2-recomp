// A harness around XenonUtils' XEX patcher (Xenia's, in the XenonRecomp checkout): applies a title update's delta
// patch (default.xexp) to the executable it was made for, and lists a patch's delta records.
//
//   patchxex check   <base.xex> <patch.xexp>             whether the patch applies to that base (the patcher's key check)
//   patchxex apply   <base.xex> <patch.xexp> <out.xex>   applies it; out.xex is uncompressed and unencrypted
//   patchxex records <base.xex> <patch.xexp>             lists the patch's delta records: the header's, then the image's
//
// A record copies, zeroes or LZX-decodes (with the old bytes as the reference) uncompressed-length bytes at its new
// address, from its old one. Built by build.cmd next to it, from XenonRecomp's sources.
#include "xex.h"
#include "xex_patcher.h"
#include "memory_mapped_file.h"

#include <aes.hpp>
#include <TinySHA1.hpp>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <vector>

static const char *ResultName(XexPatcher::Result r)
{
    switch (r)
    {
    case XexPatcher::Result::Success: return "success";
    case XexPatcher::Result::FileOpenFailed: return "file open failed";
    case XexPatcher::Result::FileWriteFailed: return "file write failed";
    case XexPatcher::Result::XexFileUnsupported: return "XEX unsupported";
    case XexPatcher::Result::XexFileInvalid: return "XEX invalid";
    case XexPatcher::Result::PatchFileInvalid: return "patch invalid";
    case XexPatcher::Result::PatchIncompatible: return "patch incompatible with this base";
    case XexPatcher::Result::PatchFailed: return "patch failed";
    case XexPatcher::Result::PatchUnsupported: return "patch unsupported";
    }
    return "?";
}

static void DecryptKey(const uint8_t *encrypted, const uint8_t *with, uint8_t *out)
{
    memcpy(out, encrypted, 16);
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, with, AESBlankIV);
    AES_CBC_decrypt_buffer(&ctx, out, 16);
}

// Walks a run of delta records as the patcher's lzxDeltaApplyPatch does (a record is 12 bytes, then its LZX data when
// its compressed length is above 1), printing each and counting them by kind.
static void PrintRecords(const uint8_t *p, size_t length, const char *where, size_t counts[3], size_t &newBytes,
    size_t &lzxBytes)
{
    const uint8_t *end = p + length;
    while (p + 12 <= end)
    {
        uint32_t oldAddress = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
        uint32_t newAddress = (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7];
        uint32_t uncompressed = (p[8] << 8) | p[9];
        uint32_t compressed = (p[10] << 8) | p[11];
        if (!oldAddress && !newAddress && !uncompressed && !compressed)
            break;
        const int kind = compressed == 0 ? 0 : compressed == 1 ? 1 : 2;
        static const char *kinds[] = { "zero", "copy", "lzx" };
        printf("%s %-4s new 0x%08X len 0x%04X old 0x%08X compressed 0x%04X\n", where, kinds[kind], newAddress,
            uncompressed, oldAddress, compressed);
        counts[kind]++;
        newBytes += uncompressed;
        if (kind == 2)
            lzxBytes += compressed;
        p += 12 + (kind == 2 ? compressed : 0);
    }
}

static int Records(const char *basePath, const char *patchPath)
{
    MemoryMappedFile baseFile(basePath), patchFile(patchPath);
    if (!baseFile.isOpen() || !patchFile.isOpen())
    {
        fprintf(stderr, "can't open the files\n");
        return 1;
    }
    // The patched header (the patch's header records applied) holds the new executable's key, which the patch's own
    // key is encrypted with.
    std::vector<uint8_t> patched;
    XexPatcher::Result r = XexPatcher::apply(baseFile.data(), baseFile.size(), patchFile.data(), patchFile.size(),
        patched, true);
    if (r != XexPatcher::Result::Success)
    {
        printf("%s\n", ResultName(r));
        return 2;
    }
    const std::vector<uint8_t> patch(patchFile.data(), patchFile.data() + patchFile.size());
    auto *patchedHeader = (const Xex2Header *)patched.data();
    auto *patchHeader = (const Xex2Header *)patch.data();
    auto *patchedSecurity = (const Xex2SecurityInfo *)&patched[patchedHeader->securityOffset];
    auto *patchSecurity = (const Xex2SecurityInfo *)&patch[patchHeader->securityOffset];
    auto *descriptor = (const Xex2OptDeltaPatchDescriptor *)getOptHeaderPtr(patch.data(), XEX_HEADER_DELTA_PATCH_DESCRIPTOR);
    auto *format = (const Xex2OptFileFormatInfo *)getOptHeaderPtr(patch.data(), XEX_HEADER_FILE_FORMAT_INFO);
    if (!descriptor || !format || patchHeader->headerSize > patch.size())
    {
        fprintf(stderr, "not a delta patch\n");
        return 1;
    }

    size_t counts[3] = {}, newBytes = 0, lzxBytes = 0;
    PrintRecords((const uint8_t *)&descriptor->info, descriptor->size - offsetof(Xex2OptDeltaPatchDescriptor, info),
        "header", counts, newBytes, lzxBytes);
    printf("header records %zu (zero %zu, copy %zu, lzx %zu), bytes written 0x%zX, LZX data 0x%zX\n",
        counts[0] + counts[1] + counts[2], counts[0], counts[1], counts[2], newBytes, lzxBytes);

    uint8_t newKey[16], patchKey[16];
    DecryptKey((const uint8_t *)patchedSecurity->aesKey, Xex2RetailKey, newKey);
    DecryptKey((const uint8_t *)patchSecurity->aesKey, newKey, patchKey);

    std::vector<uint8_t> data(patch.begin() + patchHeader->headerSize, patch.end());
    if (format->encryptionType == XEX_ENCRYPTION_NORMAL)
    {
        AES_ctx ctx;
        AES_init_ctx_iv(&ctx, patchKey, AESBlankIV);
        AES_CBC_decrypt_buffer(&ctx, data.data(), data.size() & ~size_t(15));
    }

    auto *normal = (const Xex2FileNormalCompressionInfo *)(format + 1);
    printf("window size 0x%X\n", (uint32_t)normal->windowSize);
    printf("image move: source 0x%X size 0x%X target 0x%X\n", (uint32_t)descriptor->deltaImageSourceOffset,
        (uint32_t)descriptor->deltaImageSourceSize, (uint32_t)descriptor->deltaImageTargetOffset);
    // Each block starts with the next block's size and SHA-1 (24 bytes), then its records; the block before (or the
    // file format info, for the first) gives its size and SHA-1.
    const Xex2CompressedBlockInfo *block = &normal->firstBlock;
    size_t offset = 0, blocks = 0, badHashes = 0;
    counts[0] = counts[1] = counts[2] = 0;
    newBytes = lzxBytes = 0;
    while (block->blockSize >= 24 && offset + block->blockSize <= data.size())
    {
        const auto *next = (const Xex2CompressedBlockInfo *)&data[offset];
        uint8_t digest[20];
        sha1::SHA1 sha1;
        sha1.processBytes(&data[offset], block->blockSize);
        sha1.finalize(digest);
        if (memcmp(digest, block->blockHash, sizeof(digest)) != 0)
            badHashes++;
        char where[32];
        snprintf(where, sizeof(where), "block%zu", blocks);
        PrintRecords(&data[offset + 24], block->blockSize - 24, where, counts, newBytes, lzxBytes);
        offset += block->blockSize;
        block = next;
        blocks++;
    }
    printf("image blocks %zu (SHA-1 wrong: %zu), records %zu (zero %zu, copy %zu, lzx %zu), bytes written 0x%zX, "
        "LZX data 0x%zX, patch data used 0x%zX of 0x%zX\n", blocks, badHashes, counts[0] + counts[1] + counts[2],
        counts[0], counts[1], counts[2], newBytes, lzxBytes, offset, data.size());
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 4 && !strcmp(argv[1], "check"))
    {
        MemoryMappedFile base(argv[2]), patch(argv[3]);
        if (!base.isOpen() || !patch.isOpen())
        {
            fprintf(stderr, "can't open the files\n");
            return 1;
        }
        std::vector<uint8_t> out;
        XexPatcher::Result r = XexPatcher::apply(base.data(), base.size(), patch.data(), patch.size(), out, true);
        printf("%s\n", ResultName(r));
        return r == XexPatcher::Result::Success ? 0 : 2;
    }
    if (argc == 5 && !strcmp(argv[1], "apply"))
    {
        XexPatcher::Result r = XexPatcher::apply(argv[2], argv[3], argv[4]);
        printf("%s\n", ResultName(r));
        return r == XexPatcher::Result::Success ? 0 : 2;
    }
    if (argc == 4 && !strcmp(argv[1], "records"))
        return Records(argv[2], argv[3]);
    fprintf(stderr, "usage: patchxex check <base.xex> <patch.xexp>\n"
                    "       patchxex apply <base.xex> <patch.xexp> <out.xex>\n"
                    "       patchxex records <base.xex> <patch.xexp>\n");
    return 1;
}
