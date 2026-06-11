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

namespace vcs::client
{
    class ClientCrypto
    {
    public:
        ClientCrypto();
        ~ClientCrypto();

        ClientCrypto(const ClientCrypto &) = delete;
        ClientCrypto &operator=(const ClientCrypto &) = delete;

        Packet startHandshake();

        Packet processKeyOffer(const Packet& packet);

        void processHandshakeOk(const Packet& packet);

        std::vector<uint8_t> encryptPacket(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& header_aad = {}) const;
        
        std::vector<uint8_t> decryptPacket(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& header_aad = {}) const;

        bool isReady() const;

        void disconnect();

        const std::array<uint8_t, 16>& getServerNonce() const;

    private:
        std::vector<uint8_t> aes_session_key_;
        std::unique_ptr<vcs::crypto::AES256GCM> aes_;

        vcs::crypto::RSA2048 server_rsa_;

        std::array<uint8_t, 16> server_nonce_ = {};
        std::array<uint8_t, 16> client_nonce_ = {};

        std::atomic<bool> handshake_done_{false};
    };
}