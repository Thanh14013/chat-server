#include "EventLoop.h"
#include "TcpServer.h"
#include "ClientSession.h"
#include "../protocol/Builder.h"
#include "../utils/Logger.h"
#include "../security/IntrusionDetector.h"
#include "../security/AuditLogger.h"
#include "../features/FileTransfer.h"
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

void EventLoop::loop(){
    int ticker = 0;

    while (m_running){
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ticker++;

        if (ticker % 5 == 0){
            std::vector<int> deadFds;
            time_t now = std::time(nullptr);

            for (auto& room : m_server->getRoomList()){
                for (auto sess : m_server->getSessionsInRoom(room)){
                    if (!sess->isAuthenticated()) continue;
                    if (now - sess->lastPingTime() > 40) {
                        LOG_WARN("Client timeout (no ping): " + sess->nickname());
                        deadFds.push_back(sess->fd());
                    }
                }
            }

            for (int fd : deadFds) {
                m_server->onClientDisconnected(fd);
            }
        }

        FileTransfer::instance().cleanupExpired();

        if (ticker % 60 == 0){
            std::vector<int> timedOut;
            for (auto& room : m_server->getRoomList()){
                for (auto s : m_server->getSessionsInRoom(room)){
                    if (s->isTimedOut()) timedOut.push_back(s->fd());
                }
            }
            for (int fd : timedOut) {
                LOG_INFO("Session timed out, disconnecting fd=" + std::to_string(fd));
                m_server->onClientDisconnected(fd);
            }
        }

        if (ticker % 600 == 0) {
            IntrusionDetector::instance().decayScores();
            AuditLogger::instance().flush();
            LOG_INFO("IDS decay + audit flush done.");
        }
        
        if (ticker >= 3600) ticker = 0;
    }
}