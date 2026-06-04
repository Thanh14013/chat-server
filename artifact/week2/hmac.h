#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace vcs::crypto {

/**
 * HMAC-SHA256 — used exclusively for signing JWT-style Session Tokens.
 *
 * NOTE: HMAC is NOT used for packet integrity in week-2+.
 *       Packets use AES-256-GCM's built-in AEAD auth tag instead.
 *
 * Security notes:
 *  - verify() uses constant-time comparison to prevent timing side-channels.
 *  - OpenSSL HMAC_CTX is created fresh per call — thread-safe.
 */
class HMACSHA256 {
public:
    static constexpr size_t DIGEST_LEN = 32; // SHA-256 output bytes

    /**
     * Compute HMAC-SHA256(data, key).
     * @return 32-byte MAC.
     * @throws std::runtime_error on OpenSSL failure.
     */
    static std::vector<uint8_t> compute(const std::vector<uint8_t>& data,
                                         const std::vector<uint8_t>& key);

    /** Convenience overload accepting strings (e.g. JWT header.payload). */
    static std::vector<uint8_t> compute(const std::string& data,
                                         const std::vector<uint8_t>& key);

    /**
     * Constant-time verification of HMAC.
     * Returns true iff HMAC(data, key) == expected.
     * NEVER compare MACs with memcmp() or == — susceptible to timing attacks.
     */
    static bool verify(const std::vector<uint8_t>& data,
                       const std::vector<uint8_t>& key,
                       const std::vector<uint8_t>& expected);

    static bool verify(const std::string&           data,
                       const std::vector<uint8_t>& key,
                       const std::vector<uint8_t>& expected);
};

} // namespace vcs::crypto
