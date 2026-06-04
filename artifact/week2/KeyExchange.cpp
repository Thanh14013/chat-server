#include "KeyExchange.h"
#include "../../crypto/rsa.h"
#include "../../crypto/random.h"
#include "../../common/MessageTypes.h"
#include "../../server/protocol/Builder.h"

#include <cstring>
#include <stdexcept>
#include <ctime>

namespace vcs::security {

// ── Lifecycle ─────────────────────────────────────────────────────────────────

KeyExchange::KeyExchange(
    vcs::crypto::RSA2048& rsa,
    std::function<void(int, const std::vector<uint8_t>&)> session_key_cb)
    : rsa_(rsa), session_key_cb_(std::move(session_key_cb)) {}

// ── Client management ─────────────────────────────────────────────────────────

void KeyExchange::addClient(int fd, const std::string& peer_ip) {
    std::unique_lock<std::shared_mutex> lock(clients_mutex_);
    PerClientState state;
    state.state          = HandshakeState::WAITING_HELLO;
    state.handshake_time = std::time(nullptr);
    state.peer_ip        = peer_ip;
    clients_[fd]         = std::move(state);
}

void KeyExchange::removeClient(int fd) {
    std::unique_lock<std::shared_mutex> lock(clients_mutex_);
    clients_.erase(fd);
}

// ── handleHello ───────────────────────────────────────────────────────────────

Packet KeyExchange::handleHello(int fd, const Packet& /*incoming*/) {
    std::unique_lock<std::shared_mutex> lock(clients_mutex_);
    auto it = clients_.find(fd);
    if (it == clients_.end()) return buildErrorPacket(ErrorCode::ERR_CRYPTO_HANDSHAKE_FAIL);

    PerClientState& cs = it->second;
    if (cs.state != HandshakeState::WAITING_HELLO) {
        cs.state = HandshakeState::FAILED;
        return buildErrorPacket(ErrorCode::ERR_CRYPTO_HANDSHAKE_FAIL);
    }

    // Check IP block
    {
        std::shared_lock<std::shared_mutex> blk(block_mutex_);
        auto bit = ip_failures_.find(cs.peer_ip);
        if (bit != ip_failures_.end()) {
            auto [count, blocked_until] = bit->second;
            if (count >= MAX_HANDSHAKE_FAILURES && std::time(nullptr) < blocked_until) {
                cs.state = HandshakeState::FAILED;
                return buildErrorPacket(ErrorCode::ERR_CRYPTO_HANDSHAKE_FAIL);
            }
        }
    }

    // Generate server_nonce
    cs.server_nonce = vcs::crypto::CSPRNG::getInstance().getNonce();
    cs.state        = HandshakeState::SENT_KEY_OFFER;
    cs.handshake_time = std::time(nullptr);

    // Build KEY_OFFER payload:
    //   [4 bytes: pem_len][pem_len bytes: public key PEM][16 bytes: server_nonce]
    std::string pem = rsa_.getPublicKeyPEM();
    uint32_t pem_len = static_cast<uint32_t>(pem.size());

    std::vector<uint8_t> payload;
    payload.reserve(4 + pem_len + 16);

    // PEM length (big-endian)
    payload.push_back((pem_len >> 24) & 0xFF);
    payload.push_back((pem_len >> 16) & 0xFF);
    payload.push_back((pem_len >>  8) & 0xFF);
    payload.push_back((pem_len >>  0) & 0xFF);

    payload.insert(payload.end(), pem.begin(), pem.end());
    payload.insert(payload.end(), cs.server_nonce.begin(), cs.server_nonce.end());

    return Builder::build(MessageType::MSG_CRYPTO_KEY_OFFER, payload);
}

// ── handleKeyAccept ───────────────────────────────────────────────────────────

Packet KeyExchange::handleKeyAccept(int fd, const Packet& incoming) {
    std::unique_lock<std::shared_mutex> lock(clients_mutex_);
    auto it = clients_.find(fd);
    if (it == clients_.end()) return buildErrorPacket(ErrorCode::ERR_CRYPTO_HANDSHAKE_FAIL);

    PerClientState& cs = it->second;
    if (cs.state != HandshakeState::SENT_KEY_OFFER) {
        cs.state = HandshakeState::FAILED;
        recordFailure(cs.peer_ip);
        return buildErrorPacket(ErrorCode::ERR_CRYPTO_HANDSHAKE_FAIL);
    }

    // KEY_ACCEPT payload layout:
    //   [4 bytes: rsa_blob_len][rsa_blob: RSA_OAEP(session_key_32 || client_nonce_16)]
    const auto& payload = incoming.payload;
    if (payload.size() < 4) {
        cs.state = HandshakeState::FAILED;
        recordFailure(cs.peer_ip);
        return buildErrorPacket(ErrorCode::ERR_CRYPTO_HANDSHAKE_FAIL);
    }

    uint32_t blob_len = (static_cast<uint32_t>(payload[0]) << 24) |
                        (static_cast<uint32_t>(payload[1]) << 16) |
                        (static_cast<uint32_t>(payload[2]) <<  8) |
                        (static_cast<uint32_t>(payload[3]) <<  0);

    if (payload.size() < 4 + blob_len) {
        cs.state = HandshakeState::FAILED;
        recordFailure(cs.peer_ip);
        return buildErrorPacket(ErrorCode::ERR_CRYPTO_HANDSHAKE_FAIL);
    }

    std::vector<uint8_t> rsa_blob(payload.begin() + 4, payload.begin() + 4 + blob_len);

    // Decrypt RSA-OAEP blob → [session_key_32 || client_nonce_16]
    std::vector<uint8_t> decrypted;
    try {
        decrypted = rsa_.decrypt(rsa_blob);
    } catch (const std::exception&) {
        cs.state = HandshakeState::FAILED;
        recordFailure(cs.peer_ip);
        return buildErrorPacket(ErrorCode::ERR_CRYPTO_HANDSHAKE_FAIL);
    }

    // Validate decrypted size: exactly 32 (AES key) + 16 (client nonce) bytes
    if (decrypted.size() != 48) {
        cs.state = HandshakeState::FAILED;
        recordFailure(cs.peer_ip);
        return buildErrorPacket(ErrorCode::ERR_CRYPTO_HANDSHAKE_FAIL);
    }

    // Extract AES session key (first 32 bytes)
    std::vector<uint8_t> aes_key(decrypted.begin(), decrypted.begin() + 32);

    // Extract client nonce (last 16 bytes)
    std::copy(decrypted.begin() + 32, decrypted.end(), cs.client_nonce.begin());

    // Scrub the decrypted buffer (it contained raw key material)
    OPENSSL_cleanse(decrypted.data(), decrypted.size());

    // Transition to ESTABLISHED
    cs.state = HandshakeState::ESTABLISHED;

    // Notify CryptoEngine to store the AES session key for this fd
    // Call BEFORE releasing the lock to avoid race where client sends data immediately
    lock.unlock();
    session_key_cb_(fd, aes_key);
    OPENSSL_cleanse(aes_key.data(), aes_key.size());

    return Builder::build(MessageType::MSG_CRYPTO_HANDSHAKE_OK, {});
}

// ── isEstablished ─────────────────────────────────────────────────────────────

bool KeyExchange::isEstablished(int fd) const {
    std::shared_lock<std::shared_mutex> lock(clients_mutex_);
    auto it = clients_.find(fd);
    if (it == clients_.end()) return false;
    return it->second.state == HandshakeState::ESTABLISHED;
}

// ── isBlocked ─────────────────────────────────────────────────────────────────

bool KeyExchange::isBlocked(const std::string& ip) const {
    std::shared_lock<std::shared_mutex> lock(block_mutex_);
    auto it = ip_failures_.find(ip);
    if (it == ip_failures_.end()) return false;
    return (it->second.first >= MAX_HANDSHAKE_FAILURES &&
            std::time(nullptr) < it->second.second);
}

// ── reapTimedOutHandshakes ────────────────────────────────────────────────────

void KeyExchange::reapTimedOutHandshakes(std::function<void(int)> disconnect_cb) {
    std::vector<int> to_disconnect;
    {
        std::shared_lock<std::shared_mutex> lock(clients_mutex_);
        time_t now = std::time(nullptr);
        for (auto& [fd, cs] : clients_) {
            if (cs.state != HandshakeState::ESTABLISHED &&
                cs.state != HandshakeState::FAILED &&
                (now - cs.handshake_time) > HANDSHAKE_TIMEOUT_SEC) {
                to_disconnect.push_back(fd);
            }
        }
    }
    for (int fd : to_disconnect) {
        disconnect_cb(fd);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

void KeyExchange::recordFailure(const std::string& ip) {
    std::unique_lock<std::shared_mutex> lock(block_mutex_);
    auto& [count, blocked_until] = ip_failures_[ip];
    ++count;
    if (count >= MAX_HANDSHAKE_FAILURES) {
        blocked_until = std::time(nullptr) + IP_BLOCK_SECONDS;
    }
}

Packet KeyExchange::buildErrorPacket(ErrorCode code) const {
    std::vector<uint8_t> payload = { static_cast<uint8_t>(code) };
    return Builder::build(MessageType::MSG_ERROR, payload);
}

} // namespace vcs::security
