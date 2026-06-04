#pragma once
#include "../../crypto/aes.h"
#include "../../crypto/rsa.h"
#include "../../common/Protocol.h"

#include <vector>
#include <array>
#include <string>
#include <memory>
#include <cstdint>
#include <atomic>

namespace vcs::client {

/**
 * ClientCrypto — handles all cryptographic operations on the client side.
 *
 * Mirrors CryptoEngine on the server. One instance per connection.
 *
 * Handshake steps (called in order):
 *  1. startHandshake()    → send MSG_CRYPTO_HELLO
 *  2. processKeyOffer()   → receive server RSA pubkey + nonce,
 *                           generate AES session key, send MSG_CRYPTO_KEY_ACCEPT
 *  3. processHandshakeOk()→ mark as ready
 *
 * After step 3, use encryptPacket() / decryptPacket() for all traffic.
 *
 * Security notes:
 *  - AES session key is generated fresh every connection (32 CSPRNG bytes).
 *  - Session key is zeroed on disconnect().
 *  - Server public key is NOT cached between sessions.
 *  - Client nonce (16 bytes) is embedded in KEY_ACCEPT to bind this specific
 *    session and prevent the server from replaying a previous KEY_OFFER.
 */
class ClientCrypto {
public:
    ClientCrypto();
    ~ClientCrypto();

    // Non-copyable
    ClientCrypto(const ClientCrypto&)            = delete;
    ClientCrypto& operator=(const ClientCrypto&) = delete;

    /**
     * Step 1 — build and return the CRYPTO_HELLO packet.
     * Resets all internal state (safe to call on reconnect).
     */
    Packet startHandshake();

    /**
     * Step 2 — process KEY_OFFER from server.
     *
     * Parses server RSA public key + server_nonce, generates a fresh
     * 32-byte AES session key and a 16-byte client_nonce, then RSA-OAEP
     * encrypts (session_key || client_nonce) with the server's pubkey.
     *
     * @param packet  KEY_OFFER packet received from server.
     * @return        KEY_ACCEPT packet to send to server.
     * @throws        std::runtime_error on malformed packet or crypto failure.
     */
    Packet processKeyOffer(const Packet& packet);

    /**
     * Step 3 — confirm handshake is complete.
     * After this, isReady() returns true.
     */
    void processHandshakeOk(const Packet& packet);

    /**
     * Encrypt a plaintext packet payload for sending to the server.
     * Uses the established AES-256-GCM session key.
     * The packet header bytes are fed as AAD to bind the ciphertext to them.
     *
     * @throws std::runtime_error if !isReady().
     */
    std::vector<uint8_t> encryptPacket(const std::vector<uint8_t>& plaintext,
                                        const std::vector<uint8_t>& header_aad = {}) const;

    /**
     * Decrypt and authenticate an encrypted payload received from the server.
     * @throws std::runtime_error on auth failure or if !isReady().
     */
    std::vector<uint8_t> decryptPacket(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& header_aad = {}) const;

    /** True once processHandshakeOk() has been called successfully. */
    bool isReady() const;

    /**
     * Zero all key material and reset to initial state.
     * Call on disconnect or session end.
     */
    void disconnect();

    /** Return server nonce received in KEY_OFFER (for logging/debug). */
    const std::array<uint8_t, 16>& getServerNonce() const;

private:
    // AES session key (32 bytes) — generated at step 2
    std::vector<uint8_t>            aes_session_key_;
    std::unique_ptr<vcs::crypto::AES256GCM> aes_;

    // RSA public key loaded from server's KEY_OFFER
    vcs::crypto::RSA2048            server_rsa_;

    // Nonces
    std::array<uint8_t, 16>         server_nonce_ = {};
    std::array<uint8_t, 16>         client_nonce_ = {};

    std::atomic<bool>               handshake_done_{false};
};

} // namespace vcs::client
