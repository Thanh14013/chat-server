#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include "../../common/Protocol.h"
#include "../../server/protocol/Packet.h"
#include "../security/ClientCrypto.h"

class TcpClient
{
public:
    using PacketCallback = std::function<void(const Packet &)>;
    using DisconnectCallback = std::function<void()>;
    using HandshakeDoneCallback = std::function<void(bool success)>;

    TcpClient();
    ~TcpClient();

    bool connectToServer(const std::string &host, uint16_t port);
    void disconnect();

    bool sendPacket(const Packet &pkt);

    void setOnPacketReceived(PacketCallback cb) { m_onPacket = cb; }
    void setOnDisconnected(DisconnectCallback cb) { m_onDisconnect = cb; }
    void setOnHandshakeDone(HandshakeDoneCallback cb) { m_onHandshakeDone = cb; }

    bool isReady() const;

private:
    void receiveThread();
    bool tryConnect(const std::string &host, uint16_t port);
    void handleHandshakePacket(const Packet &pkt);

    int m_fd;
    std::string m_host;
    uint16_t m_port;
    std::atomic<bool> m_connected;
    std::thread m_recvThread;
    std::mutex m_sendMutex;

    vcs::client::ClientCrypto m_crypto;

    PacketCallback m_onPacket;
    DisconnectCallback m_onDisconnect;
    HandshakeDoneCallback m_onHandshakeDone;
};
