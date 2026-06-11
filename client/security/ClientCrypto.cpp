#include "ClientCrypto.h"
#include "../../crypto/random.h"
#include "../../common/MessageTypes.h"
#include "../../common/Protocol.h"
#include <openssl/crypto.h>
#include <stdexcept>
#include <cstring>

namespace vcs::client
{
    ClientCrypto::ClientCrypto() = default;

    ClientCrypto::~ClientCrypto()
    {
        disconnect();
    }

    void ClientCrypto::disconnect()
    {
        handshake_done_.store(false);

        if (!aes_session_key_.empty())
        {
            OPENSSL_cleanse(aes_session_key_.data(), aes_session_key_.size());
            aes_session_key_.clear();
        }
        aes_.reset();
        OPENSSL_cleanse(server_nonce_.data(), server_nonce_.size());
        OPENSSL_cleanse(client_nonce_.data(), client_nonce_.size());
    }

    Packet ClientCrypto::startHandshake()
    {
        disconnect();
        return Packet(MessageType::MSG_CRYPTO_HELLO, {});
    }

    Packet ClientCrypto::processKeyOffer(const Packet &packet)
    {
        if (packet.header.msg_type != static_cast<uint8_t>(MessageType::MSG_CRYPTO_KEY_OFFER))
        {
            throw std::runtime_error("ClientCrypto::processKeyOffer: unexpected packet type");
        }

        const auto &payload = packet.payload;
        if (payload.size() < 4 + 16)
        {
            throw std::runtime_error("ClientCrypto::processKeyOffer: payload too short");
        }

        uint32_t pem_len = (static_cast<uint32_t>(payload[0]) << 24) |
                           (static_cast<uint32_t>(payload[1]) << 16) |
                           (static_cast<uint32_t>(payload[2]) << 8) |
                           (static_cast<uint32_t>(payload[3]) << 0);

        if (payload.size() < 4 + pem_len + 16)
        {
            throw std::runtime_error("ClientCrypto::processKeyOffer: truncated PEM or nonce");
        }

        std::string pem(payload.begin() + 4, payload.begin() + 4 + pem_len);
        server_rsa_.loadPublicKeyPEM(pem);

        std::copy(payload.begin() + 4 + pem_len, payload.begin() + 4 + pem_len + 16, server_nonce_.begin());

        aes_session_key_ = vcs::crypto::CSPRNG::getInstance().getBytes(32);

        client_nonce_ = vcs::crypto::CSPRNG::getInstance().getNonce();

        std::vector<uint8_t> blob;
        blob.reserve(48);
        blob.insert(blob.end(), aes_session_key_.begin(), aes_session_key_.end());
        blob.insert(blob.end(), client_nonce_.begin(), client_nonce_.end());

        std::vector<uint8_t> rsa_blob;
        try
        {
            rsa_blob = server_rsa_.encrypt(blob);
        }
        catch (...)
        {
            OPENSSL_cleanse(blob.data(), blob.size());
            throw;
        }
        OPENSSL_cleanse(blob.data(), blob.size());

        aes_ = std::make_unique<vcs::crypto::AES256GCM>(aes_session_key_);

        uint32_t blob_len = static_cast<uint32_t>(rsa_blob.size());
        std::vector<uint8_t> accept_payload;
        accept_payload.reserve(4 + rsa_blob.size());
        accept_payload.push_back((blob_len >> 24) & 0xFF);
        accept_payload.push_back((blob_len >> 16) & 0xFF);
        accept_payload.push_back((blob_len >> 8) & 0xFF);
        accept_payload.push_back((blob_len >> 0) & 0xFF);
        accept_payload.insert(accept_payload.end(), rsa_blob.begin(), rsa_blob.end());

        return Packet(MessageType::MSG_CRYPTO_KEY_ACCEPT, accept_payload);
    }

    void ClientCrypto::processHandshakeOk(const Packet &packet)
    {
        if (packet.header.msg_type != static_cast<uint8_t>(MessageType::MSG_CRYPTO_HANDSHAKE_OK))
        {
            throw std::runtime_error("ClientCrypto::processHandshakeOk: expected HANDSHAKE_OK");
        }
        if (!aes_)
        {
            throw std::runtime_error("ClientCrypto::processHandshakeOk: AES not initialised");
        }
        handshake_done_.store(true);
    }

    std::vector<uint8_t> ClientCrypto::encryptPacket(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &header_aad) const
    {
        if (!handshake_done_.load())
        {
            throw std::runtime_error("ClientCrypto::encryptPacket: handshake not complete");
        }
        return aes_->encrypt(plaintext, header_aad);
    }

    std::vector<uint8_t> ClientCrypto::decryptPacket(const std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &header_aad) const
    {
        if (!handshake_done_.load())
        {
            throw std::runtime_error("ClientCrypto::decryptPacket: handshake not complete");
        }
        return aes_->decrypt(ciphertext, header_aad);
    }

    bool ClientCrypto::isReady() const {
        return handshake_done_.load();
    }
    const std::array<uint8_t, 16>& ClientCrypto::getServerNonce() const{
        return server_nonce_;
    }
}