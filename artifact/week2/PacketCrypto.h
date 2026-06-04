#pragma once
/**
 * PacketCrypto.h — Week-2 helpers for building and parsing encrypted packets.
 *
 * This file extends the week-1 Packet/Builder/Parser layer with the encrypted
 * on-wire format defined in the Project Plan (§ "Packet format sau khi có crypto").
 *
 * On-wire format after handshake:
 * ┌─────────────────────────────────────────────────────┐
 * │  HEADER  (15 bytes, PLAINTEXT)                      │
 * │  magic[2] | version[1] | msg_type[1] | flags[1]    │
 * │  seq_num[4] | payload_length[4] | checksum_crc32[4] │
 * ├─────────────────────────────────────────────────────┤
 * │  IV      (16 bytes, PLAINTEXT)                      │
 * │  AES-GCM IV — random per message, prepended by AES  │
 * ├─────────────────────────────────────────────────────┤
 * │  ENCRYPTED PAYLOAD (variable)                       │
 * │  AES-256-GCM( plaintext_data )                      │
 * ├─────────────────────────────────────────────────────┤
 * │  GCM AUTH TAG (16 bytes)                            │
 * └─────────────────────────────────────────────────────┘
 *
 * Note: AES256GCM::encrypt() already prepends the IV and appends the tag
 * (i.e., output = [IV 16][ciphertext][TAG 16]).  So the Packet payload field
 * simply stores the AES output directly — no extra wrapping needed.
 *
 * Replay attack prevention (per ClientSession):
 *   - seq_num in header increases monotonically per session.
 *   - Incoming seq_num < expected → DROP (replay).
 *   - Incoming seq_num > expected + 100 → DROP (suspicious gap / injection).
 */

#include "Protocol.h"
#include <cstdint>
#include <vector>
#include <set>
#include <array>
#include <stdexcept>

namespace vcs {

// ── PacketFlags ────────────────────────────────────────────────────────────────

namespace PacketFlags {
    static constexpr uint8_t ENCRYPTED   = 0x01;
    static constexpr uint8_t COMPRESSED  = 0x02;
    static constexpr uint8_t FRAGMENTED  = 0x04;
}

// ── ReplayGuard ────────────────────────────────────────────────────────────────

/**
 * Per-session state for replay-attack prevention.
 * Attach one ReplayGuard to each ClientSession.
 */
class ReplayGuard {
public:
    static constexpr uint32_t NONCE_WINDOW  = 1000;
    static constexpr uint32_t MAX_SEQ_JUMP  = 100;

    ReplayGuard() : expected_seq_(1) {}

    /**
     * Check an incoming packet's sequence number.
     * @return true  → packet is acceptable (not a replay / not suspicious).
     *         false → packet should be silently dropped.
     */
    bool check(uint32_t seq_num, const std::array<uint8_t,16>& nonce) {
        // Replay: seq already behind what we expect
        if (seq_num < expected_seq_) return false;

        // Suspicious forward jump (possible injection)
        if (seq_num > expected_seq_ + MAX_SEQ_JUMP) return false;

        // Duplicate nonce check (sliding window)
        if (seen_nonces_.count(nonce)) return false;
        seen_nonces_.insert(nonce);

        // Keep window bounded
        if (seen_nonces_.size() > NONCE_WINDOW) {
            seen_nonces_.erase(seen_nonces_.begin());
        }

        expected_seq_ = seq_num + 1;
        return true;
    }

    uint32_t nextOutgoingSeq() { return out_seq_++; }

    void reset() {
        expected_seq_ = 1;
        out_seq_      = 1;
        seen_nonces_.clear();
    }

private:
    uint32_t                                   expected_seq_;
    uint32_t                                   out_seq_ = 1;
    std::set<std::array<uint8_t,16>>           seen_nonces_;
};

} // namespace vcs
