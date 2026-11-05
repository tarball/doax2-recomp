#pragma once

// Hooks into a netplay session for the runtime's tests and the fuzz harness (tools/netplay/fuzz): a session without a
// socket or threads, whose datagrams the caller feeds as the receiving thread would hand them over, and whose state the
// caller reads. Nothing here runs in the game; session.cpp implements it beside the session, on the session's own state.
#include <cstddef>
#include <cstdint>
#include <string>

namespace netplay::session::testing
{
    // An IPv4 address and port, in host byte order.
    struct Address
    {
        uint32_t ip = 0;
        uint16_t port = 0;
        bool operator==(const Address&) const = default;
    };
    enum class Role
    {
        kHost,
        kJoining,
    };
    enum class State
    {
        kOff,
        kConnecting,
        kConnected,
        kEnded,
    };

    // A fresh session as `role`, connecting, its identity known (this build's, with a disc hash of 0), a joining one
    // aimed at `peer`. No socket: what it would send is counted (Snapshot::sent), not sent. Its switches are the
    // defaults (the delays chosen; fights in lockstep).
    void Reset(Role role, Address peer = {});
    // Connects it to `peer` with `token`, as the handshake would.
    void Connect(Address peer, uint64_t token);
    // Starts a segment of the flow here, a fight or a menu screen, with `delay`, this machine at its frame `frame` (as
    // one that has run so many frames of it).
    void StartSegment(bool fight, uint32_t delay, uint32_t frame);
    // Runs a frame of the segment: the frame after, this machine's input for it + delay (at rest), and what's no longer
    // needed forgotten.
    void AdvanceFrame();
    // Feeds a datagram, as from `from`, at the current time.
    void Feed(const void* data, size_t length, Address from);
    // This machine's identity as its hello or welcome carries it (protocol::Identity's bytes; `size` must be its size),
    // for building hellos the host takes.
    void LocalIdentityBytes(void* identity, size_t size);
    // The host's token for a machine at `from` (what its welcome to that machine carries).
    uint64_t HostToken(Address from);
    struct Snapshot
    {
        State state = State::kOff;
        Address peer;
        uint64_t token = 0, nonce = 0;
        uint32_t seed = 0;
        bool peerWhereKnown = false;
        uint8_t peerWhere = 0;
        // What the session holds of the other machine's: the current segment's inputs and checksums, the segments ahead
        // and their inputs and checksums, the fights' setups and the delays.
        size_t remoteInputs = 0, remoteChecksums = 0, earlySegments = 0, earlyInputs = 0, earlyChecksums = 0, remoteSetups = 0, delays = 0;
        uint32_t peerReceived = 0;
        // This machine's frame of the segment, and its own inputs kept: how many, the first and the last frame.
        uint32_t frame = 0;
        size_t localInputs = 0;
        uint32_t localFirst = 0, localLast = 0;
        // The packets this session would have sent, and of them the welcomes and refusals.
        uint64_t sent = 0, welcomes = 0, refusals = 0;
        std::string endReason;
    };
    Snapshot Inspect();
}
