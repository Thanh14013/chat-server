#pragma once
#include "../../crypto/aes.h"
#include "../../crypto/rsa.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <memory>
#include <cstdint>

namespace vcs::security{
    class CryptoEngine{
        public:
        static CryptoEngine& getInstance();
        CryptoEngine(const CryptoEngine&)            = delete;
        CryptoEngine& operator=(const CryptoEngine&) = delete;

        void initialize();

        bool isInitialised() const;

        std::string getPublicKeyPEM() const;

        vcs::crypto::RSA2048& getRSA();

        void establishSession(int fd, const std::vector<uint8_t>& aes_key);

        void removeSession(int fd);

        bool hasSession(int fd) const;

        std::vector<uint8_t> encryptPayload(int fd, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad = {}) const;

        std::vector<uint8_t> decryptPayload(int fd, const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& aad = {}) const;

        const std::vector<uint8_t>& getJWTSecret() const;

        private:
            CryptoEngine() = default;

            bool initialised_ = false;
            vcs::crypto::RSA2048 rsa_;
            std::vector<uint8_t> jwt_secret_; //32 random bytes

            mutable std::shared_mutex sessions_mutex_;
            std::unordered_map<int, vcs::crypto::AES256GCM> session_keys_;
    };
}