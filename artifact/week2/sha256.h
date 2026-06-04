#pragma once
#include <string>
#include <vector>
#include <array>
#include <cstdint>

namespace vcs::crypto {

/**
 * SHA-256 hashing and PBKDF2-HMAC-SHA256 password derivation.
 *
 * Password hashing policy (NIST SP 800-132 / NIST 2023 guidance):
 *  - Algorithm : PBKDF2-HMAC-SHA256
 *  - Iterations: 100,000  (minimum recommended by NIST 2023)
 *  - Salt      : 16 random bytes per user, stored alongside the hash
 *  - NEVER store plaintext passwords or bare SHA-256 of a password.
 *  - ALWAYS call OPENSSL_cleanse on the password buffer after hashing.
 */
class SHA256Hash {
public:
    static constexpr size_t HASH_LEN = 32;  // SHA-256 output bytes
    static constexpr size_t SALT_LEN = 16;  // PBKDF2 salt bytes
    static constexpr int    PBKDF2_ITERATIONS = 100'000;

    using HashBytes = std::array<uint8_t, HASH_LEN>;
    using SaltBytes = std::array<uint8_t, SALT_LEN>;

    // ── General SHA-256 ───────────────────────────────────────────────────────

    /** Hash arbitrary bytes; return lowercase hex string. */
    static std::string hash(const std::vector<uint8_t>& data);

    /** Hash a string. */
    static std::string hash(const std::string& data);

    /** Hash a file by path; return lowercase hex string. */
    static std::string hashFile(const std::string& filepath);

    // ── PBKDF2 password hashing ───────────────────────────────────────────────

    /**
     * Derive a key from a password using PBKDF2-HMAC-SHA256.
     *
     * @param password    Raw password bytes. Caller MUST zero this buffer
     *                    with OPENSSL_cleanse() immediately after calling.
     * @param salt        16-byte random salt (unique per user).
     * @param iterations  Iteration count (default = 100,000).
     * @return            32-byte derived key as a hex string.
     * @throws            std::runtime_error on failure.
     */
    static std::string pbkdf2(std::vector<uint8_t>& password,
                               const SaltBytes&       salt,
                               int iterations = PBKDF2_ITERATIONS);

    /** Overload accepting std::string password (will be zeroed in place). */
    static std::string pbkdf2(std::string&     password,
                               const SaltBytes& salt,
                               int iterations = PBKDF2_ITERATIONS);

    /**
     * Generate a cryptographically random 16-byte salt.
     * Must be unique per user — generated at registration time and stored.
     */
    static SaltBytes generateSalt();

    // ── Encoding helpers ──────────────────────────────────────────────────────

    /** Convert raw bytes to lowercase hex string. */
    static std::string toHex(const uint8_t* data, size_t len);
    static std::string toHex(const std::vector<uint8_t>& data);

    /** Convert hex string back to bytes. */
    static std::vector<uint8_t> fromHex(const std::string& hex);
};

} // namespace vcs::crypto
