#include "TcpClient.h"
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
    if (m_fd >= 0)
    {
        ::shutdown(m_fd, SHUT_RDWR);
        ::close(m_fd);
        m_fd = -1;
    }
    if (m_recvThread.joinable())
        m_recvThread.join();
}

bool TcpClient::sendPacket(const Packet &pkt)
{
    std::lock_guard<std::mutex> lock(m_sendMutex);
    if (!m_connected || m_fd < 0)
        return false;
    auto bytes = packetToBytes(pkt);
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
        if (m_onPacket)
            m_onPacket(pkt);
    }
}
