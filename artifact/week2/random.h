#pragma once
#include <vector>
#include <array>
#include <cstdint>

namespace vcs::crypto {

/**
 * Cryptographically Secure Pseudo-Random Number Generator (singleton).
 *
 * Backed by OpenSSL RAND_bytes which reads from /dev/urandom on Linux.
 * NEVER use std::rand(), srand(), or mt19937 for any crypto purpose.
 */
class CSPRNG {
public:
    static CSPRNG& getInstance();

    // Non-copyable singleton
    CSPRNG(const CSPRNG&)            = delete;
    CSPRNG& operator=(const CSPRNG&) = delete;

    /**
     * Fill `buf` with `n` cryptographically random bytes.
     * @throws std::runtime_error if OpenSSL entropy source fails.
     */
    void getBytes(uint8_t* buf, size_t n) const;

    /** Return `n` random bytes as a vector. */
    std::vector<uint8_t> getBytes(size_t n) const;

    /** Return a cryptographically random unsigned 32-bit integer. */
    uint32_t getUInt32() const;

    /** Return a 16-byte nonce for replay-attack prevention. */
    std::array<uint8_t, 16> getNonce() const;

private:
    CSPRNG() = default;
};

} // namespace vcs::crypto
