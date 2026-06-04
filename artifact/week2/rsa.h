#pragma once
#include <string>
<parameter name="file_text">#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

// Forward-declare OpenSSL type to avoid polluting headers
typedef struct evp_pkey_st EVP_PKEY;

namespace vcs::crypto {

/**
 * RSA-2048 key pair manager.
 *
 * Security notes:
 *  - Uses OAEP padding (PKCS#1 v1.5 is NOT used — vulnerable to Bleichenbacher).
 *  - Private key is NEVER written to disk in this implementation.
 *  - Server generates exactly ONE key pair at startup; all clients share it.
 *  - Key size 2048-bit balances security and handshake performance.
 */
class RSA2048 {
public:
    static constexpr int KEY_BITS = 2048;

    RSA2048();
    ~RSA2048();

    // Non-copyable (holds private key material)
    RSA2048(const RSA2048&)            = delete;
    RSA2048& operator=(const RSA2048&) = delete;

    // Movable
    RSA2048(RSA2048&&) noexcept;
    RSA2048& operator=(RSA2048&&) noexcept;

    // ── Server-side ──────────────────────────────────────────────────────────

    /**
     * Generate a new RSA-2048 key pair.
     * Call once at server startup.
     * @throws std::runtime_error on failure.
     */
    void generateKeyPair();

    /**
     * Export public key as PEM string to send to clients.
     * @throws std::runtime_error if no key pair has been generated.
     */
    std::string getPublicKeyPEM() const;

    /**
     * Decrypt data that was RSA-OAEP encrypted with the public key.
     * Used by server to unwrap the AES session key from the client.
     * @throws std::runtime_error on decryption failure.
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) const;

    // ── Client-side ──────────────────────────────────────────────────────────

    /**
     * Load a PEM-encoded public key received from the server.
     * @throws std::runtime_error if PEM is invalid.
     */
    void loadPublicKeyPEM(const std::string& pem);

    /**
     * Encrypt data with the loaded public key (OAEP padding).
     * Used by client to wrap the AES session key.
     * @throws std::runtime_error if no public key is loaded, or on failure.
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) const;

    // ── Utility ──────────────────────────────────────────────────────────────

    /** True if a key pair (private + public) has been generated. */
    bool hasPrivateKey() const;

    /** True if at least a public key is loaded. */
    bool hasPublicKey() const;

private:
    EVP_PKEY* pkey_ = nullptr;      // Full key pair (server) or public only (client)
    bool      has_private_ = false;
};

} // namespace vcs::crypto
