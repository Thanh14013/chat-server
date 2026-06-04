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
        std::vector<ClientSession*> getSessionInRoom(const std::string& room);
        std::vector<std::string> getUsersInRoom(const std::string& room);
        std::vector<std::string> getRoomList();

        static TcpServer* s_instance;

    private:
        void acceptLoop();
        void handlePacket(int fd, const Packet& pkt);

        void handleConnectRequest(int fd, const Packet& pkt);
        void handleChatSend(int fd, const Packet& pkt);
        void handleChatPrivate(int fd, const Packet& pkt);
        void handleDisconnect(int fd, const Packet& pkt);
        void handlePing(int fd);
        void handlePong(int fd);
        void handleUserListRequest(int fd);
        void handleUserRoomRequest(int fd);
        void handleRoomJoin(int fd, const Packet& pkt);
        void handleRoomCreate(int fd, const Packet& pkt);
        void handleRoomLeave(int fd);

        bool isNicknameTaken(const std::string& nick);
        bool isNicknameValid(const std::string& nick);
        void removeSession(int fd);

        int m_listenFd;
        int m_maxClients;
        std::atomic<bool> m_running;

        std::unordered_map<int, std::shared_ptr<ClientSession>> m_sessions;
        std::map<std::string, std::set<int>> m_rooms;
        mutable std::shared_mutex m_sessionsMutex;
        mutable std::shared_mutex m_roomsMutex;

        std::unique_ptr<ThreadPool> m_threadPool;
        
};