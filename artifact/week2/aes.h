#pragma once
#include <vector>
#include <array>
#include <stdexcept>
#include <cstdint>

namespace vcs::crypto {

/**
 * AES-256-GCM AEAD cipher wrapper (OpenSSL).
 *
 * - Key  : 32 bytes (256-bit)
 * - IV   : 16 bytes per message — MUST be unique, generated fresh each call
 * - Tag  : 16 bytes GCM authentication tag (Encrypt-then-MAC built-in)
 *
 * Wire layout of encrypt() output:
 *   [IV 16 bytes][ciphertext ...][auth_tag 16 bytes]
 *
 * Caller does NOT need to transmit IV/tag separately — they are embedded.
 * decrypt() expects the same layout.
 */
class AES256GCM {
public:
    static constexpr size_t KEY_LEN = 32;
    static constexpr size_t IV_LEN  = 16;
    static constexpr size_t TAG_LEN = 16;

    using KeyBytes = std::array<uint8_t, KEY_LEN>;
    using IVBytes  = std::array<uint8_t, IV_LEN>;

    /**
     * Construct with an existing 256-bit session key.
     * Each ClientSession owns one AES256GCM instance.
     */
    explicit AES256GCM(const KeyBytes& key);

    /**
     * Construct with raw key bytes (e.g. received from key exchange).
     * data must be exactly KEY_LEN bytes.
     */
    explicit AES256GCM(const std::vector<uint8_t>& key);

    ~AES256GCM();

    // Non-copyable (holds sensitive key material)
    AES256GCM(const AES256GCM&)            = delete;
    AES256GCM& operator=(const AES256GCM&) = delete;

    // Movable
    AES256GCM(AES256GCM&&) noexcept;
    AES256GCM& operator=(AES256GCM&&) noexcept;

    /**
     * Encrypt plaintext with optional Additional Authenticated Data (AAD).
     *
     * @param plaintext  Raw data to encrypt.
     * @param aad        Optional AAD bound to ciphertext (e.g. packet header).
     * @return           [IV(16)] [ciphertext] [GCM_TAG(16)]
     * @throws           std::runtime_error on OpenSSL failure.
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                 const std::vector<uint8_t>& aad = {}) const;

    /**
     * Decrypt and authenticate ciphertext produced by encrypt().
     *
     * @param ciphertext [IV(16)] [encrypted data] [GCM_TAG(16)]
     * @param aad        Must match the AAD used during encryption.
     * @return           Recovered plaintext.
     * @throws           std::runtime_error if auth tag fails (tamper detected).
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                 const std::vector<uint8_t>& aad = {}) const;

    // ── Static helpers ──────────────────────────────────────────────────────

    /** Generate a cryptographically random 256-bit key. */
    static KeyBytes generateKey();

    /** Generate a cryptographically random 128-bit IV. */
    static IVBytes  generateIV();

private:
    KeyBytes key_;
};

} // namespace vcs::crypto
