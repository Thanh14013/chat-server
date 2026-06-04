#pragma once
#include "../../common/Protocol.h"
#include "../../common/ErrorCodes.h"

#include <array>
#include <unordered_map>
#include <shared_mutex>
#include <ctime>
#include <string>
#include <functional>
#include <memory>

namespace vcs::crypto { class RSA2048; class AES256GCM; }

namespace vcs::security {

/**
 * State machine managing the TLS-like key exchange handshake.
 *
 * Handshake flow (see Project Plan §Security Model):
 *   WAITING_HELLO
 *     → handleHello()     → sends KEY_OFFER (server RSA pubkey + server_nonce)
 *   SENT_KEY_OFFER
 *     → handleKeyAccept() → decrypts AES session key, transitions to ESTABLISHED
 *   ESTABLISHED
 *     → all subsequent packets are AES-256-GCM encrypted
 *   FAILED
 *     → connection dropped
 *
 * Security:
 *  - Handshake must complete within HANDSHAKE_TIMEOUT_SEC (30 s).
 *  - server_nonce prevents session replay across reconnects.
 *  - After 3 consecutive handshake failures from the same IP → 5-minute block.
 */
class KeyExchange {
public:
    static constexpr int HANDSHAKE_TIMEOUT_SEC = 30;
    static constexpr int MAX_HANDSHAKE_FAILURES = 3;
    static constexpr int IP_BLOCK_SECONDS       = 300; // 5 minutes

    enum class HandshakeState {
        WAITING_HELLO,
        SENT_KEY_OFFER,
        WAITING_KEY_ACCEPT,
        ESTABLISHED,
        FAILED
    };

    struct PerClientState {
        HandshakeState          state          = HandshakeState::WAITING_HELLO;
        std::array<uint8_t,16>  server_nonce   = {};
        std::array<uint8_t,16>  client_nonce   = {};
        time_t                  handshake_time = 0;   // time of CRYPTO_HELLO
        std::string             peer_ip;
    };

    /**
     * @param rsa     Server RSA key pair (already initialised).
     * @param session_key_cb  Callback invoked on successful key acceptance:
     *                        (fd, aes_key_bytes_32) — CryptoEngine stores them.
     */
    explicit KeyExchange(
        vcs::crypto::RSA2048& rsa,
        std::function<void(int fd, const std::vector<uint8_t>& aes_key)> session_key_cb
    );

    ~KeyExchange() = default;

    KeyExchange(const KeyExchange&)            = delete;
    KeyExchange& operator=(const KeyExchange&) = delete;

    /**
     * Register a new client connection.
     * Must be called before any handle*() methods.
     */
    void addClient(int fd, const std::string& peer_ip);

    /** Remove client state on disconnect. */
    void removeClient(int fd);

    /**
     * Process MSG_CRYPTO_HELLO from client.
     * @return Packet to send (KEY_OFFER) or empty packet on error.
     */
    Packet handleHello(int fd, const Packet& incoming);

    /**
     * Process MSG_CRYPTO_KEY_ACCEPT from client.
     * On success: triggers session_key_cb, transitions to ESTABLISHED.
     * @return HANDSHAKE_OK packet or error packet.
     */
    Packet handleKeyAccept(int fd, const Packet& incoming);

    /** True only if the client's handshake is in ESTABLISHED state. */
    bool isEstablished(int fd) const;

    /** True if the given IP is currently on the block list. */
    bool isBlocked(const std::string& ip) const;

    /** Drop any connections that have not completed handshake in time. */
    void reapTimedOutHandshakes(std::function<void(int fd)> disconnect_cb);

private:
    vcs::crypto::RSA2048&                          rsa_;
    std::function<void(int, const std::vector<uint8_t>&)> session_key_cb_;

    mutable std::shared_mutex                       clients_mutex_;
    std::unordered_map<int, PerClientState>         clients_;

    // IP → { failure_count, blocked_until }
    mutable std::shared_mutex                       block_mutex_;
    std::unordered_map<std::string, std::pair<int, time_t>> ip_failures_;

    // ── Helpers ───────────────────────────────────────────────────────────────
    void   recordFailure(const std::string& ip);
    Packet buildErrorPacket(ErrorCode code) const;
};

} // namespace vcs::security
