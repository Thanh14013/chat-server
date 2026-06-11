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

namespace vcs::security{
    class KeyExchange{
        public:
            static constexpr int HANDSHAKE_TIMEOUT_SEC = 30;
            static constexpr int MAX_HANDSHAKE_FAILURES = 3;
            static constexpr int IP_BLOCK_SECONDS       = 300;

            enum class HandshakeState{
                WAITING_HELLO,
                SENT_KEY_OFFER,
                WAITING_KEY_ACCEPT,
                ESTABLISHED,
                FAILED
            };

            struct PerClientState {
                HandshakeState state = HandshakeState::WAITING_HELLO;
                std::array<uint8_t, 16> server_nonce = {};
                std::array<uint8_t, 16> client_nonce = {};
                time_t handshake_time = 0;
                std::string peer_ip;
            };

            explicit KeyExchange(vcs::crypto::RSA2048& rsa, std::function<void(int fd, const std::vector<uint8_t>& aes_key)> session_key_cb);

            ~KeyExchange() = default;

            KeyExchange(const KeyExchange&)            = delete;
            KeyExchange& operator=(const KeyExchange&) = delete;
            
            void addClient(int fd, const std::string& peer_ip);

            void removeClient(int fd);

            Packet handleHello(int fd, const Packet& incoming);

            Packet handleKeyAccept(int fd, const Packet& incoming);

            bool isEstablished(int fd) const;

            bool isBlocked(const std::string& ip) const;

            void reapTimedOutHandshakes(std::function<void(int fd)> disconnect_cb);
        private:
            vcs::crypto::RSA2048& rsa_;
            std::function<void(int, const std::vector<uint8_t>&)> session_key_cb_;

            mutable std::shared_mutex clients_mutex_;
            std::unordered_map<int, PerClientState> clients_;

            mutable std::shared_mutex block_mutex_;
            std::unordered_map<std::string, std::pair<int, time_t>> ip_failures_;

            void recordFailure(const std::string& ip);
            Packet buildErrorPacket(ErrorCode code) const;
    };
}