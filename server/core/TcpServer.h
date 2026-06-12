#pragma once
#include <string>
#include <unordered_map>
#include <set>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <memory>
#include "ThreadPool.h"
#include "ClientSession.h"
#include "../../common/Protocol.h"
#include "../security/KeyExchange.h"
#include "../security/AuthManager.h"
#include "../security/SessionToken.h"
#include <sys/epoll.h>

class TcpServer {
    public:
        TcpServer();
        ~TcpServer();

        bool start(u_int16_t port, int maxClients, int threadPoolSize);
        void stop();

        void onPacketReceived(int fd, const Packet& pkt);
        void onClientDisconnected(int fd);

        void broadcastToRoom(const std::string& room, const Packet& pkt, int excludeFd = -1);
        void broadcastToAll(const Packet& pkt, int excludeFd = -1);

        ClientSession* getSession(int fd);
        int getFdByNickname(const std::string& nick);
        std::vector<ClientSession*> getSessionsInRoom(const std::string& room);
        std::vector<std::string> getUsersInRoom(const std::string& room);
        std::vector<std::string> getRoomList();

        static TcpServer* s_instance;

    private:
        void epollLoop();
        bool setNonBlocking(int fd);
        void handlePacket(int fd, const Packet& pkt);

        void handleConnectRequest(int fd, const Packet& pkt);
        void handleReconnectRequest(int fd, const Packet& pkt);
        void handleChatSend(int fd, const Packet& pkt);
        void handleChatPrivate(int fd, const Packet& pkt);
        void handleDisconnect(int fd, const Packet& pkt);
        void handlePing(int fd);
        void handlePong(int fd);
        void handleUserListRequest(int fd);
        void handleRoomListRequest(int fd);
        void handleRoomJoin(int fd, const Packet& pkt);
        void handleRoomCreate(int fd, const Packet& pkt);
        void handleRoomLeave(int fd);

        bool isNicknameTaken(const std::string& nick);
        bool isNicknameValid(const std::string& nick);
        void removeSession(int fd);

        int m_listenFd;
        int m_epollFd;
        int m_maxClients;
        std::atomic<bool> m_running;

        std::unordered_map<int, std::shared_ptr<ClientSession>> m_sessions;
        std::unordered_map<std::string, int> m_nicknames; // nickname -> fd
        std::map<std::string, std::set<int>> m_rooms;
        mutable std::shared_mutex m_sessionsMutex;
        mutable std::shared_mutex m_roomsMutex;

        std::unique_ptr<ThreadPool> m_threadPool;
        std::unique_ptr<vcs::security::KeyExchange> m_keyExchange;
        std::shared_ptr<vcs::security::SessionToken> m_sessionToken;
        std::unique_ptr<vcs::security::AuthManager> m_authManager;
        
};