#pragma once
#include <string>
#include <map>
#include <memory>
#include <vector>
#include <shared_mutex>
#include "Room.h"
#include "ChatHistory.h"
#include "../../common/ErrorCodes.h"
#include "../../common/Protocol.h"

struct RoomInfo
{
    std::string name;
    std::string topic;
    std::string creator;
    int member_count;
    bool is_private;
};

class TcpServer;

class RoomManager
{
public:
    static RoomManager &instance();

    void initialize(TcpServer *server, const std::string &defaultRoom);

    void initialize(TcpServer *server, const std::string &defaultRoom);

    ErrorCode createRoom(const std::string &name, const std::string &creator);
    ErrorCode deleteRoom(const std::string &name, const std::string &requester, bool isOwner);

    ErrorCode joinRoom(int fd, const std::string &nickname, const std::string &roomName);
    void leaveRoom(int fd, const std::string &nickname, const std::string &roomName);
    void removeUser(int fd);

    void broadcastToRoom(const std::string& room, const Packet& pkt, int excludeFd = -1);

    std::vector<RoomInfo>    getRoomList();
    std::string              getUserRoom(int fd);
    std::vector<std::string> getUsersInRoom(const std::string& room);

    Room*        getRoom(const std::string& name);
    ChatHistory* getOrCreateHistory(const std::string& room);

    void appendHistory(const std::string& room, const HistoryEntry& entry);
    void sendHistoryToClient(int fd, const std::string& room, int n = 50);
    
private:
    RoomManager() : m_server(nullptr) {}

    std::string nickFromFd(int fd);

    TcpServer* m_server;
    std::string m_defaultRoom;
    std::map<std::string, std::unique_ptr<Room>>       m_rooms;
    std::map<std::string, std::unique_ptr<ChatHistory>>m_histories;
    std::map<int, std::string>                         m_fdToRoom;
    mutable std::shared_mutex                          m_mutex;
};