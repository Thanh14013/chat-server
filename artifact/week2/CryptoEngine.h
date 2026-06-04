#pragma once
#include "../../crypto/aes.h"
#include "../../crypto/rsa.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <memory>
#include <cstdint>

namespace vcs::security {

/**
 * CryptoEngine — singleton facade exposing all crypto operations to the server.
 *
 * Responsibilities:
 *  1. Generate the server RSA-2048 key pair on startup.
 *  2. Maintain a per-fd AES-256-GCM session key map (populated after handshake).
 *  3. Provide encrypt/decrypt helpers for packet payload.
 *
 * Thread safety:
 *  - session_keys_ is guarded by a shared_mutex.
 *  - Read operations (encryptPayload, decryptPayload) acquire a shared lock —
 *    many client threads can run concurrently.
 *  - Write operations (establishSession, removeSession) acquire an exclusive lock.
 *
 * Usage pattern:
 *   CryptoEngine& ce = CryptoEngine::getInstance();
 *   ce.initialize();   // call once at server start
 *   ce.getPublicKeyPEM(); // send to each client during handshake
 */
class CryptoEngine {
public:
    static CryptoEngine& getInstance();

    CryptoEngine(const CryptoEngine&)            = delete;
    CryptoEngine& operator=(const CryptoEngine&) = delete;

    /**
     * Must be called once before any other method.
     * Generates the RSA key pair and the JWT secret key.
     * @throws std::runtime_error on failure.
     */
    void initialize();

    /** True after initialize() completes. */
    bool isInitialised() const;

    // ── RSA / Handshake ───────────────────────────────────────────────────────

    /** Export server RSA public key as PEM (sent to client in KEY_OFFER). */
    std::string getPublicKeyPEM() const;

    /** Access the raw RSA key pair (used by KeyExchange). */
    vcs::crypto::RSA2048& getRSA();

    /**
     * Store the AES session key for a connected client.
     * Called by KeyExchange::session_key_cb_ after successful KEY_ACCEPT.
     *
     * @param fd          Socket file descriptor of the client.
     * @param aes_key     32-byte AES-256 key decrypted from KEY_ACCEPT.
     */
    void establishSession(int fd, const std::vector<uint8_t>& aes_key);

    /** Remove session on client disconnect. */
    void removeSession(int fd);

    /** True if fd has a live, established AES session. */
    bool hasSession(int fd) const;

    // ── Encrypt / Decrypt (per-client session) ────────────────────────────────

    /**
     * Encrypt plaintext payload for a specific client.
     * The returned bytes include [IV(16)][ciphertext][GCM_TAG(16)].
     *
     * @param fd         Client socket fd.
     * @param plaintext  Raw payload bytes.
     * @param aad        Optional additional authenticated data (e.g. packet header).
     * @throws std::runtime_error if fd has no session or on crypto failure.
     */
    std::vector<uint8_t> encryptPayload(int fd,
                                         const std::vector<uint8_t>& plaintext,
                                         const std::vector<uint8_t>& aad = {}) const;

    /**
     * Decrypt and verify an encrypted payload received from a client.
     * @throws std::runtime_error on auth tag mismatch (tamper) or missing session.
     */
    std::vector<uint8_t> decryptPayload(int fd,
                                         const std::vector<uint8_t>& ciphertext,
                                         const std::vector<uint8_t>& aad = {}) const;

    // ── JWT secret key (shared with SessionToken) ─────────────────────────────

    /** Return 32-byte server secret used to sign JWT-style tokens. */
    const std::vector<uint8_t>& getJWTSecret() const;

private:
    CryptoEngine() = default;

    bool                         initialised_ = false;
    vcs::crypto::RSA2048         rsa_;
    std::vector<uint8_t>         jwt_secret_;  // 32 random bytes

    mutable std::shared_mutex    sessions_mutex_;
    std::unordered_map<int, vcs::crypto::AES256GCM> session_keys_;
};

} // namespace vcs::security
