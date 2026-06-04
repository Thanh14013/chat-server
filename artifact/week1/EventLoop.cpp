#include "EventLoop.h"
#include "TcpServer.h"
#include "ClientSession.h"
#include "../protocol/Builder.h"
#include "../utils/Logger.h"
#include "../../common/Constants.h"
#include <chrono>
#include <vector>

EventLoop::EventLoop(TcpServer* server)
    : m_server(server), m_running(false) {}

EventLoop::~EventLoop() {
    stop();
}

void EventLoop::start() {
    m_running = true;
    m_thread  = std::thread(&EventLoop::loop, this);
}

void EventLoop::stop() {
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
}

void EventLoop::loop() {
    int ticker = 0;

    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ticker++;

        if (ticker % Constants::PING_INTERVAL_SEC == 0) {
            auto sessions = m_server->getSessionsInRoom("");
            std::vector<int> deadFds;

            std::vector<ClientSession*> all;
            for (auto& room : m_server->getRoomList()) {
                for (auto* s : m_server->getSessionsInRoom(room)) {
                    all.push_back(s);
                }
            }

            for (auto* sess : all) {
                if (!sess->isAuthenticated()) continue;
                if (!sess->m_pongReceived) {
                    LOG_WARN("Client timeout (no pong): " + sess->nickname());
                    deadFds.push_back(sess->fd());
                } else {
                    sess->m_pongReceived = false;
                    sess->sendPacket(Builder::makePing());
                }
            }

            for (int fd : deadFds) {
                m_server->onClientDisconnected(fd);
            }
        }

        if (ticker % 60 == 0) {
            std::vector<int> timedOut;
            for (auto& room : m_server->getRoomList()) {
                for (auto* s : m_server->getSessionsInRoom(room)) {
                    if (s->isTimedOut()) timedOut.push_back(s->fd());
                }
            }
            for (int fd : timedOut) {
                LOG_INFO("Session timed out, disconnecting fd=" + std::to_string(fd));
                m_server->onClientDisconnected(fd);
            }
        }

        if (ticker >= 3600) ticker = 0;
    }
}
