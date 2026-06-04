#pragma once
#include <thread>
#include <atomic>

class TcpServer;

class EventLoop {
public:
    explicit EventLoop(TcpServer* server);
    ~EventLoop();

    void start();
    void stop();

private:
    void loop();

    TcpServer*        m_server;
    std::thread       m_thread;
    std::atomic<bool> m_running;
};
