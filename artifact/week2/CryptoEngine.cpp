#include "CryptoEngine.h"
#include "../../crypto/random.h"

#include <stdexcept>

namespace vcs::security {

// ── Singleton ─────────────────────────────────────────────────────────────────

CryptoEngine& CryptoEngine::getInstance() {
    static CryptoEngine instance;
    return instance;
}

// ── initialize ────────────────────────────────────────────────────────────────

void CryptoEngine::initialize() {
    if (initialised_) return;

    // Generate server RSA-2048 key pair (blocking — takes ~100-200ms)
    rsa_.generateKeyPair();

    // Generate 32-byte JWT signing secret
    jwt_secret_ = vcs::crypto::CSPRNG::getInstance().getBytes(32);

    initialised_ = true;
}

bool CryptoEngine::isInitialised() const {
    return initialised_;
}

// ── RSA / Handshake ───────────────────────────────────────────────────────────

std::string CryptoEngine::getPublicKeyPEM() const {
    if (!initialised_) throw std::runtime_error("CryptoEngine: not initialised");
    return rsa_.getPublicKeyPEM();
}

vcs::crypto::RSA2048& CryptoEngine::getRSA() {
    if (!initialised_) throw std::runtime_error("CryptoEngine: not initialised");
    return rsa_;
}

void CryptoEngine::establishSession(int fd, const std::vector<uint8_t>& aes_key) {
    if (aes_key.size() != vcs::crypto::AES256GCM::KEY_LEN) {
        throw std::runtime_error("CryptoEngine::establishSession: invalid key size");
    }
    std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
    // Emplace in-place to avoid copying key material
    session_keys_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(fd),
        std::forward_as_tuple(aes_key)
    );
}

void CryptoEngine::removeSession(int fd) {
    std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
    session_keys_.erase(fd);
}

bool CryptoEngine::hasSession(int fd) const {
    std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
    return session_keys_.count(fd) > 0;
}

// ── encryptPayload ────────────────────────────────────────────────────────────

std::vector<uint8_t> CryptoEngine::encryptPayload(int fd,
                                                    const std::vector<uint8_t>& plaintext,
                                                    const std::vector<uint8_t>& aad) const {
    std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
    auto it = session_keys_.find(fd);
    if (it == session_keys_.end()) {
        throw std::runtime_error("CryptoEngine::encryptPayload: no session for fd=" +
                                 std::to_string(fd));
    }
    return it->second.encrypt(plaintext, aad);
}

// ── decryptPayload ────────────────────────────────────────────────────────────

std::vector<uint8_t> CryptoEngine::decryptPayload(int fd,
                                                    const std::vector<uint8_t>& ciphertext,
                                                    const std::vector<uint8_t>& aad) const {
    std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
    auto it = session_keys_.find(fd);
    if (it == session_keys_.end()) {
        throw std::runtime_error("CryptoEngine::decryptPayload: no session for fd=" +
                                 std::to_string(fd));
    }
    return it->second.decrypt(ciphertext, aad);
}

// ── JWT secret ────────────────────────────────────────────────────────────────

const std::vector<uint8_t>& CryptoEngine::getJWTSecret() const {
    if (!initialised_) throw std::runtime_error("CryptoEngine: not initialised");
    return jwt_secret_;
}

} // namespace vcs::security
