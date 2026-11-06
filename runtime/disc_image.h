#pragma once

// The game's executable from its disc image: the supported version's default.xex, checked by its SHA-256, then decrypted
// and decompressed in memory into the image the recompiled code was generated from. Another version's disc (the game's
// others, disc_image.cpp) plays with a version patch beside the executable (version_patch.h): it makes the supported
// version's executable from the disc's, and the disc's files that differ are served as the supported version's
// (composed). The supported version can be on no disc at all (a title update's), and then every disc plays with a patch.
// Either way the image's code and .pdata are zero (ClearCode): the game's code module holds the code, and every player
// runs the same image. A release reads it all from the disc image every time it starts, so nothing from the game is
// written out; a development checkout can keep the supported version's default.xex and default.pe in private/ instead.
#include "vfs/iso_device.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace disc
{
    enum class Check
    {
        kOk,
        kUnreadable,   // not an Xbox 360 disc image, or no default.xex in it
        kOtherGame,    // a default.xex, but none of the game's versions'
        kOtherVersion, // another version of the game, whose version patch this build doesn't have (a build from source)
        kDamaged,      // the disc image's files aren't its version's (a damaged dump): another disc image may do
        kBroken,       // the release is: its version patch is damaged, or missing where every disc needs one (the
                       // supported version on no disc), or this PC can't apply it
    };

    // Another version of the game, whose discs a version patch plays as the supported version (disc_image.cpp's list).
    struct Version
    {
        const char* xex;       // its default.xex's SHA-256
        const char* name;      // "1.0"
        const char* described; // for the player: "the original 1.0 disc"
        const char* patch;     // the version patch's file, beside the executable
        // Whether its patch makes the executable alone: the disc's files are the supported version's as they are, so a
        // development checkout's executable plays the disc without the patch (Options).
        bool executableOnly;
    };

    // The game as the runtime runs it.
    struct Game
    {
        // The executable: the disc's default.xex, or a version patch's XEX header alone (all the runtime reads of it but the
        // image), and its image, the code and .pdata zero.
        std::vector<uint8_t> xex, image;
        const Version* version = nullptr; // the disc's version, when a version patch made the game from it
        vfs::ComposedFiles files;         // the disc's files the patch serves as the supported version's
    };

    struct Options
    {
        std::filesystem::path patchDirectory; // where version patches are: the executable's folder (empty: the working one)
        std::string dataDirectory;  // where checks are remembered (disc_checks.txt); empty: nowhere
        // A development checkout's default.xex and default.pe (the supported version's), used instead of the disc's
        // executable when the disc's files are the supported version's: its own disc's, or another version's whose patch
        // makes the executable alone (Version::executableOnly). Other versions' discs are made with their patches.
        const std::vector<uint8_t>* developmentXex = nullptr;
        const std::vector<uint8_t>* developmentImage = nullptr;
    };

    // Reads and checks a disc image's executable and makes the game from it: the supported version's unpacked, another
    // version's made with its version patch, whose result must be the supported version's executable, and whose composed
    // files are checked once per disc image and patch, by reading them whole (their source as the patch says, and the
    // result), which the data directory then remembers. For kOtherVersion, `problem` names the version patch that's
    // missing ("Missing patch for 1.0 disc (doa4_1.0.vpatch)"), which another disc does without; for kDamaged and kBroken,
    // what's wrong, as a sentence ("The version patch doax2_tu2.vpatch is missing. Extract the release again.", when the
    // supported version is on no disc).
    Check Prepare(const std::string& isoPath, const Options& options, Game& game, std::string& problem);

    // Reads default.xex from the disc image into `xex`, and checks it: kOk for the supported version's, kOtherVersion for
    // another version's (`version` set to it).
    Check ReadExecutable(const std::string& isoPath, std::vector<uint8_t>& xex, const Version** version = nullptr);
    // Whether `xex` is the supported version's default.xex (see disc_image.cpp): never, when that version is on no disc.
    bool IsSupported(const std::vector<uint8_t>& xex);
    // Decrypts (retail key) and decompresses (basic compression, or none) an XEX2 into its image. False if it can't.
    bool Unpack(const std::vector<uint8_t>& xex, std::vector<uint8_t>& image);
    // Zeroes the image's code (its executable sections) and .pdata (the code's exception tables, which only exception
    // dispatch reads, which the runtime doesn't do). False if it has no PE headers.
    bool ClearCode(std::vector<uint8_t>& image);
    // Whether an image, its code cleared, is the supported version's.
    bool IsSupportedImage(const std::vector<uint8_t>& image);
    // SHA-256 as 64 lowercase hex digits (empty if it can't be computed).
    std::string Sha256(const uint8_t* data, size_t size);

    // What was found about a disc image once, by reading much of it: kept in the data directory's disc_checks.txt by the
    // image's full path, size and modification time, under a name (`what`: a word). Empty if nothing is.
    std::string Remembered(const std::string& dataDirectory, const std::string& isoPath, const std::string& what);
    void Remember(const std::string& dataDirectory, const std::string& isoPath, const std::string& what, const std::string& value);
}
