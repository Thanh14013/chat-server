#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include "../../common/Protocol.h"
#include "../../server/protocol/Packet.h"

class TcpClient {
public:
    using PacketCallback     = std::function<void(const Packet&)>;
    using DisconnectCallback = std::function<void()>;

    TcpClient();
    ~TcpClient();

    bool connectToServer(const std::string& host, uint16_t port);
    void disconnect();

    bool sendPacket(const Packet& pkt);

    void setOnPacketReceived(PacketCallback cb)      { m_onPacket = cb; }
    void setOnDisconnected(DisconnectCallback cb)    { m_onDisconnect = cb; }

    bool isConnected() const { return m_connected; }

private:
    void receiveThread();
    bool tryConnect(const std::string& host, uint16_t port);

    int               m_fd;
    std::atomic<bool> m_connected;
    std::thread       m_recvThread;
    std::mutex        m_sendMutex;

    PacketCallback     m_onPacket;
    DisconnectCallback m_onDisconnect;
};
