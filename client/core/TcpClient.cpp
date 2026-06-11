#include "TcpClient.h"
#include "../security/CertVerifier.h"
#include "../../common/MessageTypes.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <chrono>

TcpClient::TcpClient() : m_fd(-1), m_connected(false) {}

TcpClient::~TcpClient()
{
    disconnect();
}

bool TcpClient::tryConnect(const std::string &host, uint16_t port)
{
    m_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (m_fd < 0)
        return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0)
    {
        ::close(m_fd);
        m_fd = -1;
        return false;
    }

    if (::connect(m_fd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        ::close(m_fd);
        m_fd = -1;
        return false;
    }
    return true;
}

bool TcpClient::connectToServer(const std::string &host, uint16_t port)
{
    m_host = host;
    m_port = port;
    int delays[] = {0, 2, 4, 8};
    for (int attempt = 0; attempt < 4; attempt++)
    {
        if (delays[attempt] > 0)
        {
            std::cout << "Retrying in " << delays[attempt] << "s...\n";
            std::this_thread::sleep_for(std::chrono::seconds(delays[attempt]));
        }
        if (tryConnect(host, port))
        {
            m_connected = true;
            m_recvThread = std::thread(&TcpClient::receiveThread, this);
            
            // start handshake immediately
            Packet hello = m_crypto.startHandshake();
            sendPacket(hello);
            
            return true;
        }
        std::cout << "Connection attempt " << (attempt + 1) << " failed.\n";
    }
    return false;
}

void TcpClient::disconnect()
{
    if (!m_connected.exchange(false))
        return;
    
    m_crypto.disconnect();

    if (m_fd >= 0)
    {
        ::shutdown(m_fd, SHUT_RDWR);
        ::close(m_fd);
        m_fd = -1;
    }
    if (m_recvThread.joinable()) {
        if (std::this_thread::get_id() != m_recvThread.get_id()) {
            m_recvThread.join();
        } else {
            m_recvThread.detach();
        }
    }
}

bool TcpClient::isReady() const {
    return m_crypto.isReady();
}

bool TcpClient::sendPacket(const Packet &pkt)
{
    std::lock_guard<std::mutex> lock(m_sendMutex);
    if (!m_connected || m_fd < 0)
        return false;

    Packet to_send = pkt;
    if (to_send.header.msg_type != static_cast<uint8_t>(MessageType::MSG_CRYPTO_HELLO) &&
        to_send.header.msg_type != static_cast<uint8_t>(MessageType::MSG_CRYPTO_KEY_OFFER) &&
        to_send.header.msg_type != static_cast<uint8_t>(MessageType::MSG_CRYPTO_KEY_ACCEPT) &&
        to_send.header.msg_type != static_cast<uint8_t>(MessageType::MSG_CRYPTO_HANDSHAKE_OK)) {
        
        if (m_crypto.isReady()) {
            try {
                to_send.payload = m_crypto.encryptPacket(to_send.payload);
                to_send.header.payload_length = static_cast<uint32_t>(to_send.payload.size());
                to_send.header.checksum = computeCRC32(to_send.payload);
            } catch (const std::exception& e) {
                std::cerr << "[!] Encryption failed.\n";
                return false;
            }
        }
    }

    auto bytes = packetToBytes(to_send);
    ssize_t total = 0;
    ssize_t len = static_cast<ssize_t>(bytes.size());
    while (total < len)
    {
        ssize_t n = ::send(m_fd, bytes.data() + total, len - total, MSG_NOSIGNAL);
        if (n <= 0)
            return false;
        total += n;
    }
    return true;
}

void TcpClient::receiveThread()
{
    while (m_connected)
    {
        Packet pkt;
        if (!readPacketFromFd(m_fd, pkt))
        {
            if (m_connected)
            {
                m_connected = false;
                if (m_onDisconnect)
                    m_onDisconnect();
            }
            break;
        }

        if (pkt.header.msg_type == static_cast<uint8_t>(MessageType::MSG_CRYPTO_KEY_OFFER) ||
            pkt.header.msg_type == static_cast<uint8_t>(MessageType::MSG_CRYPTO_HANDSHAKE_OK)) {
            handleHandshakePacket(pkt);
        } else {
            if (m_crypto.isReady()) {
                try {
                    pkt.payload = m_crypto.decryptPacket(pkt.payload);
                } catch (const std::exception& e) {
                    std::cerr << "[!] Decryption failed.\n";
                    disconnect();
                    if (m_onDisconnect) m_onDisconnect();
                    break;
                }
            } else {
                std::cerr << "[!] Unencrypted packet received before handshake.\n";
                disconnect();
                if (m_onDisconnect) m_onDisconnect();
                break;
            }

            if (m_onPacket)
                m_onPacket(pkt);
        }
    }
}

void TcpClient::handleHandshakePacket(const Packet &pkt) {
    if (pkt.header.msg_type == static_cast<uint8_t>(MessageType::MSG_CRYPTO_KEY_OFFER)) {
        if (pkt.payload.size() >= 4) {
            uint32_t pem_len = (pkt.payload[0] << 24) | (pkt.payload[1] << 16) | (pkt.payload[2] << 8) | pkt.payload[3];
            if (pkt.payload.size() >= 4 + pem_len) {
                std::string pem(pkt.payload.begin() + 4, pkt.payload.begin() + 4 + pem_len);
                auto status = vcs::client::CertVerifier::getInstance().verifyServerKey(m_host, m_port, pem);
                if (status == vcs::client::CertVerifier::TrustStatus::CHANGED) {
                    std::string old_fp = vcs::client::CertVerifier::getInstance().getFingerprint(m_host, m_port);
                    std::string new_fp = vcs::client::CertVerifier::fingerprintOf(pem);
                    bool trust = vcs::client::CertVerifier::promptUserOnChange(m_host, m_port, old_fp, new_fp);
                    if (!trust) {
                        disconnect();
                        if (m_onHandshakeDone) m_onHandshakeDone(false);
                        return;
                    } else {
                        vcs::client::CertVerifier::getInstance().saveServerKey(m_host, m_port, pem);
                    }
                } else if (status == vcs::client::CertVerifier::TrustStatus::NEW) {
                    vcs::client::CertVerifier::getInstance().saveServerKey(m_host, m_port, pem);
                }
            }
        }

        try {
            Packet accept_pkt = m_crypto.processKeyOffer(pkt);
            sendPacket(accept_pkt);
        } catch (const std::exception& e) {
            std::cerr << "[!] Key offer processing failed: " << e.what() << "\n";
            disconnect();
            if (m_onHandshakeDone) m_onHandshakeDone(false);
        }
    } else if (pkt.header.msg_type == static_cast<uint8_t>(MessageType::MSG_CRYPTO_HANDSHAKE_OK)) {
        try {
            m_crypto.processHandshakeOk(pkt);
            if (m_onHandshakeDone) m_onHandshakeDone(true);
        } catch (const std::exception& e) {
            std::cerr << "[!] Handshake confirmation failed.\n";
            disconnect();
            if (m_onHandshakeDone) m_onHandshakeDone(false);
        }
    }
}
