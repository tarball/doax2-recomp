#pragma once

// What two machines must have alike to play a netplay session together (netplay/session.h, whose handshake compares
// them): the same build of the game's executable, the same game's files, and the same switches (netplay/frame.h); and
// for the log, what each machine is.
#include "vfs/iso_device.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace netplay::identity
{
    // A hash of the game's executable and its code module (the files, as built; ANALYSIS.md, Phase 5, The game's code
    // module), but for what differs between two links of the same code: the PE header's time stamp and checksum, and the
    // debug directory, which names the PDB. 0 if the executable can't be read. Computed once, from the files rather than
    // the images in memory, which the loader relocates wherever they go.
    uint64_t BuildId();
    // The build's configuration: RelWithDebInfo, Release or Debug.
    const char* BuildConfiguration();
    // The game as it runs (disc::Game): its executable (its XEX header and image, the code zero), which the disc's
    // identity covers in default.xex's place, and the disc's files a version patch serves composed. Set once, before a
    // session starts.
    void SetGame(const std::vector<uint8_t>& xex, const std::vector<uint8_t>& image, const vfs::ComposedFiles& composed);
    // Starts finding the disc's identity: a hash of its files as the runtime serves them (the mounted disc device's, a
    // version patch's composed files as composed), but default.xex, which the executable stands for, and the files the
    // game leaves out (GameState::identityLeavesOut: what doesn't change a fight), so that a disc of another version that
    // a patch plays as the supported one, and the supported version's disc in any dump format (a full XGD2 image, a plain
    // XISO), have one identity. The files' hash comes from the data directory's disc_checks.txt if it has the image's,
    // by its path, size and modification time, kept with what it comes from besides the bytes (how it's made, what it
    // leaves out, the composed files); or else from hashing them through a disc device of its own, on a thread of its
    // own, its file cache pages at low priority (a few seconds for DOA4's 3 GB on an SSD), which keeps it there (but
    // while DEBUG_DISC_FILE serves a file from elsewhere).
    void StartDiscHash();
    // The disc's identity, once known.
    std::optional<uint64_t> DiscHash();
    // Whether the disc's files couldn't be read to identify them (a damaged or cut disc image): no session then.
    bool DiscHashFailed();
    // The CPU (its brand string, and whether it has FMA3) and the Windows build, for the log.
    std::string Machine();
}
