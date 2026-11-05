#pragma once

// The wire format of netplay sessions (session.h, session.cpp): the packets two machines exchange over UDP, and the bounds
// a receiver holds every count, frame and index in them to. Internal to the runtime: session.cpp sends and receives them,
// and the runtime's tests and the fuzz harness (tools/netplay/fuzz) build malformed ones from the same definitions.
//
// Every datagram starts with a Header: the game's prefix, the protocol's version, the packet's type and the session's
// token. A Hello carries no token (the joining machine has none yet) but a nonce of its own, which the host's Welcome or
// Refuse echoes, so that the joining machine takes only answers to its own hello, from the host it addressed. The token
// the Welcome carries is the host's for that joining machine's address and port (SipHash-2-4 of them with a secret the
// host draws as it starts), and the host takes a machine as its peer only once a packet carrying that token comes back
// from that address: a hello with a spoofed source costs the host one answer and nothing else. From then on, each
// machine takes packets from the other's address and port only, and only with the token.
//
// Nothing here is encrypted or authenticated beyond that: a machine on the network path between the two sees the token
// and can forge packets, and anyone who can reach a waiting host's port can join it first, neither critical for casual
// play (analysis/netplay_security_review.md, Left open).
#include "netplay/session.h"

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace netplay::session::protocol
{
    constexpr uint16_t kVersion = 9;
    constexpr uint32_t kMaxPads = 64;       // pads a segment packet carries at most
    constexpr uint32_t kChecksumsSent = 8;  // the last checksums each segment packet carries
    constexpr uint32_t kMaxParts = 12;      // the parts of a fight's setup
    constexpr uint32_t kShownBytes = 24;    // a part's bytes travel as they are up to this many, else as a hash (frame.h)
    constexpr uint8_t kHashed = 0xFF;       // PartDigest::length: a hash
    constexpr uint32_t kSettingsSize = 32;  // a player's settings at most (GameState::kMaxPlayerSettings)
    // A segment's key: its number among the flow's segments the session played (the same on both machines), with
    // kFightKey for a fight.
    constexpr uint32_t kFightKey = 0x80000000;
    constexpr uint32_t kNoKey = 0xFFFFFFFF;      // no segment
    constexpr uint32_t kFrameWindow = 1u << 24;  // a segment's frames a packet may name (inputs, checksums)
    // A segment packet's `received` from a machine that has ended the segment: it needs nothing more of it, so the
    // other doesn't answer (two machines that had both ended it would otherwise answer each other forever).
    constexpr uint32_t kNothingNeeded = 0xFFFFFFFF;
    // The input delays' and the window's bounds (the host's travel in its welcome and its choices).
    constexpr uint32_t kMaxDelay = 30;
    constexpr uint32_t kMaxWindow = 16;
    constexpr int32_t kNoSlack = INT32_MIN;
    // How far past this machine's frame of a segment the other's inputs and checksums may reach: the other machine is at
    // most 2 * delay + window frames ahead of the last frame of ours it has (it sends inputs to its frame + delay, and its
    // frame is at most delay + window past the last frame of ours it has, which is at most our frame + delay), so
    // 2 * kMaxDelay + kMaxWindow = 76 at most; and for a segment this machine hasn't started, the other waits at its frame
    // `delay` for our input, so its inputs reach 2 * delay at most. Packets naming frames further ahead are dropped,
    // which bounds what a machine keeps of the other's.
    constexpr uint32_t kFramesAhead = 128;
    // The segments ahead of this machine's whose packets are kept (and whose delays), and those behind it still answered.
    constexpr uint32_t kEarlyKept = 64;
    constexpr uint32_t kEndedKept = 8;

    enum class Type : uint16_t
    {
        kHello = 1,    // joining -> host: the joining machine and a nonce for the answer
        kWelcome = 2,  // host -> joining: the session's token, its seed and input delays, the host's machine
        kAlive = 3,    // where the sender's game is, every 250 ms once connected
        kSegment = 4,  // a player's inputs, checksums and settings in a segment of the flow, and a fight's setup at first
        kBye = 5,      // the sender leaves the session
        kRefuse = 6,   // host -> joining: not the same build, disc or switches (with the host's machine)
    };

#pragma pack(push, 1)
    struct Header
    {
        char game[8];      // GAME_PREFIX: another game's packets are ignored
        uint16_t version;  // kVersion
        uint16_t type;     // Type
        uint64_t session;  // the session's token (0 in a Hello)
        uint32_t time;     // the sender's clock as it sent this, in microseconds (wrapping)
        uint32_t echo;     // the newest `time` the sender had from the receiver, plus how long it held it (0: none yet)
    };
    static_assert(sizeof(Header) == 28);
    // What both machines must have alike to play together (identity.h), and for the log, what the machine is.
    struct Identity
    {
        uint64_t build;         // identity::BuildId
        uint64_t disc;          // identity::DiscHash
        char configuration[16]; // the build's configuration
        char switches[160];     // the switches that change how the game runs (Switches)
        char machine[96];       // the CPU and Windows build, for the log
    };
    // A list of parts (a fight's setup: game_state.h), as compared between machines: each part's bytes, or a hash of
    // them if longer than kShownBytes. The parts' names are the same on both machines (the same build), so they aren't
    // sent.
    struct PartDigest
    {
        uint8_t length;               // the part's bytes, or kHashed: their hash in the first 8
        uint8_t bytes[kShownBytes];
    };
    struct Digests
    {
        uint8_t count;
        PartDigest parts[kMaxParts];
    };
    struct Hello
    {
        Header header;     // session 0
        uint64_t nonce;    // the joining machine's, for the answer (Welcome or Refuse)
        Identity identity;
        // Zeros: a hello is no shorter than its answer, so that the host, answering hellos whose source may be forged,
        // never sends a third party more than it was sent.
        uint8_t padding[16];
    };
    // The host's input delays: fixed by its variables (kFixedLockstep, kFixedRollback), or chosen for each segment of
    // the flow (Delays, in its packets). The window always applies.
    constexpr uint8_t kFixedLockstep = 1, kFixedRollback = 2;
    struct Welcome
    {
        Header header;       // session: the token the joining machine uses from now on
        uint64_t nonce;      // the hello's
        uint32_t seed;
        uint16_t delay;      // the lockstep segments' input delay, if fixed
        uint16_t fightDelay; // with rollback (session.h): the fights' input delay, if fixed
        uint16_t window;     // and the window
        uint8_t fixed;       // kFixedLockstep, kFixedRollback
        Identity identity;
    };
    // A machine's measures of its own pace, in its segment and alive packets: the host chooses the input delays from
    // both machines' (session.cpp: Choose), and each machine's log shows the other's. 0: not measured yet.
    struct Measures
    {
        // Its main thread's work a frame (netplay::LastFrameWork), mean, in the flow's menu screens and in its fights (the
        // frames run as the present).
        uint32_t menuWorkUs, fightWorkUs;
        uint32_t replayFrameUs; // in fights that roll back: a replayed frame's time, mean (a rollback's frames after its first)
        uint32_t replayFrames;  // and how many were measured
        uint32_t loadUs;        // a savestate's load, mean
        uint32_t drawWaitUs;    // and its wait for the command processor to draw the frames recorded, mean
    };
    // How a delay was chosen.
    enum class How : uint8_t
    {
        kDefault,   // nothing measured yet: a cautious default
        kChosen,    // from the round trip and the machines' measures
        kFixed,     // the host's variable (NETPLAY_DELAY, NETPLAY_FIGHT_DELAY)
    };
    // Where a machine's reckoning of the frames a rollback fits beside a frame came from (session.cpp: Fits).
    enum class FitsFrom : uint8_t
    {
        kDefault,   // nothing measured: a default
        kFrameWork, // its frames' work, as an estimate of a replayed frame's
        kReplays,   // its replayed frames
    };
    // The input delays of a segment of the flow, which the host chooses as it ends the segment before (the first
    // segment's as it starts it, once connected): the host's packets carry its latest choice, and the joining machine
    // plays the segment with them. A choice is final: both machines play the segment with it (session.h).
    struct Delays
    {
        uint32_t segment = kNoKey;  // the segment's number among the flow's
        uint8_t lockstep = 0;       // its delay if it runs in lockstep (a menu screen, or a fight without rollback)
        uint8_t rollback = 0;       // and if it's a fight that rolls back
        uint8_t lockstepHow = 0, rollbackHow = 0; // How
        // What they were chosen from: the delay 60 frames a second needs at the round trip in lockstep (without the
        // frame to spare); the frames after which the other's input comes; the frames a rollback fits beside a frame on
        // each machine, and where that came from (FitsFrom); the round trip (mean and 95th percentile) and the frames'
        // work (the larger machine's).
        uint8_t needed = 0, late = 0;
        uint8_t fitsHost = 0, fitsJoining = 0, fitsHostFrom = 0, fitsJoiningFrom = 0;
        uint32_t roundTripUs = 0, roundTripHighUs = 0, workUs = 0;
    };
    // What every segment and alive packet carries besides: the sender's measures, and from the host, its latest choice
    // of delays.
    struct Pace
    {
        Measures measures;
        Delays delays;
    };
    struct Refuse
    {
        Header header;
        uint64_t nonce;    // the hello's
        Identity identity;
    };
    // Where the sender's game is: in a segment of the flow (and waiting there for the receiver's input), between
    // the flow's segments, or on its own (outside the flow: its own menus and modes, booting), and the flow's segment
    // it's in or was last in, with its frame there (its last, once it has left it).
    enum class Where : uint8_t
    {
        kOwnTime,
        kBetween,
        kInSegment,
        kWaiting,
    };
    struct Alive
    {
        Header header;
        uint32_t key;    // the segment (SegmentPacket::key), or kNoKey
        uint32_t frame;  // its frame
        uint32_t screen; // a menu screen's identity
        uint8_t where;   // Where
        Pace pace;
    };
    // Why a machine leaves the session (Bye::reason).
    enum class Leaving : uint8_t
    {
        kLeaves,    // its player leaves (the window closes), or the session ended there otherwise
        kApart,     // the two games went separate ways in the flow
    };
    struct Bye
    {
        Header header;
        uint8_t reason; // Leaving
    };
    // Followed by `pads` pads (the segment's frames `first` on), `checksums` checksums, and with kSetupIncluded the
    // fight's setup at its first frame (Digests).
    constexpr uint8_t kSetupIncluded = 1, kSetupReceived = 2;
    struct SegmentPacket
    {
        Header header;
        uint32_t key;       // the segment: its number in the flow's (both machines'), with kFightKey for a fight
        uint32_t screen;    // which menu screen it is on the sender (GameState::MenuState), 0 in a fight
        uint32_t received;  // the sender has the receiver's inputs of the segment for every frame before this one
        uint32_t first;
        uint16_t pads;
        uint16_t checksums;
        int32_t slack;      // the sender's slack in a fight (session.cpp: LocalSlack), in microseconds, or kNoSlack
        uint8_t setup;      // kSetupIncluded: the sender's fight setup follows; kSetupReceived: the sender has the receiver's
        uint8_t delay;      // the input delay the sender plays the segment with
        // The sender's player's settings for the flow (GameState::PlayerSettings), as it entered the flow: `size`
        // bytes, 0 if none.
        uint8_t settingsSize;
        uint8_t settings[kSettingsSize];
        Pace pace;
    };
    struct Checksum
    {
        uint32_t frame;
        uint64_t checksum;
    };
#pragma pack(pop)
    // The sizes tools/netplay/protocol.py has (the tests' and the fuzz harness's packet builder).
    static_assert(sizeof(Pad) == 12 && sizeof(Checksum) == 12);
    static_assert(sizeof(Identity) == 288 && sizeof(Digests) == 301 && sizeof(Pace) == 50);
    static_assert(sizeof(Hello) == 340 && sizeof(Welcome) == 335 && sizeof(Refuse) == 324);
    static_assert(sizeof(Hello) >= sizeof(Welcome) && sizeof(Hello) >= sizeof(Refuse));
    static_assert(sizeof(Alive) == 91 && sizeof(Bye) == 29 && sizeof(SegmentPacket) == 137);
    // The longest packet: a segment packet with every pad, checksum and the setup.
    constexpr size_t kMaxPacket = sizeof(SegmentPacket) + kMaxPads * sizeof(Pad) + kChecksumsSent * sizeof(Checksum) + sizeof(Digests);
    // The receive buffer: a datagram longer than this is dropped by the socket.
    constexpr size_t kReceiveBuffer = 2048;
    static_assert(kMaxPacket <= kReceiveBuffer);

    // SipHash-2-4 (Aumasson and Bernstein): a 64-bit keyed hash of short messages, for the session's tokens. The
    // reference's test vector: with the key 00 01 .. 0F and the message 00 01 .. 0E, A129CA6149BE45E5.
    inline uint64_t SipHash24(const uint8_t key[16], const void* message, size_t length)
    {
        const auto rotate = [](uint64_t x, int b) { return (x << b) | (x >> (64 - b)); };
        const auto load = [](const uint8_t* p) {
            uint64_t v;
            memcpy(&v, p, 8);
            return v; // little-endian hosts
        };
        const uint64_t k0 = load(key), k1 = load(key + 8);
        uint64_t v0 = 0x736f6d6570736575ull ^ k0, v1 = 0x646f72616e646f6dull ^ k1, v2 = 0x6c7967656e657261ull ^ k0,
                 v3 = 0x7465646279746573ull ^ k1;
        const auto round = [&] {
            v0 += v1; v1 = rotate(v1, 13); v1 ^= v0; v0 = rotate(v0, 32);
            v2 += v3; v3 = rotate(v3, 16); v3 ^= v2;
            v0 += v3; v3 = rotate(v3, 21); v3 ^= v0;
            v2 += v1; v1 = rotate(v1, 17); v1 ^= v2; v2 = rotate(v2, 32);
        };
        const uint8_t* in = static_cast<const uint8_t*>(message);
        const uint8_t* end = in + (length & ~size_t(7));
        for (; in != end; in += 8)
        {
            const uint64_t m = load(in);
            v3 ^= m;
            round();
            round();
            v0 ^= m;
        }
        uint64_t last = uint64_t(length & 0xFF) << 56;
        for (size_t i = 0; i < (length & 7); i++)
            last |= uint64_t(in[i]) << (8 * i);
        v3 ^= last;
        round();
        round();
        v0 ^= last;
        v2 ^= 0xFF;
        round();
        round();
        round();
        round();
        return v0 ^ v1 ^ v2 ^ v3;
    }
}
