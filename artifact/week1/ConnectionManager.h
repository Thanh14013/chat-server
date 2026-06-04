#pragma once
#include <string>
#include <atomic>
#include <thread>
#include "TcpClient.h"
#include "MessageQueue.h"
#include "../commands/CommandHandler.h"

class ConnectionManager {
public:
    ConnectionManager();
    ~ConnectionManager();

    bool start(const std::string& host, uint16_t port);
    void stop();

private:
    void inputThread();
    void displayPacket(const Packet& pkt);
    void printTimestamp();
    bool sendChatMessage(const std::string& msg);

    TcpClient       m_client;
    MessageQueue    m_queue;
    CommandHandler  m_cmdHandler;
    std::thread     m_inputThread;
    std::atomic<bool> m_running;
    std::string     m_nickname;
    std::string     m_currentRoom;
};
