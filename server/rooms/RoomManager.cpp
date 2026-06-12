#include "RoomManager.h"
#include "../core/TcpServer.h"
#include "../core/ClientSession.h"
#include "../protocol/Builder.h"
#include "../utils/Logger.h"
#include "../../common/Constants.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

RoomManager &RoomManager::instance()
{
    static RoomManager inst;
    return inst;
}

void RoomManager::initialize(TcpServer *server, const std::string &defaultRoom)
{
    m_server = server;
    m_defaultRoom = defaultRoom;

    std::unique_lock<std::shared_mutex> lk(m_mutex);
    m_rooms[defaultRoom] = std::make_unique<Room>(defaultRoom, "system");
    m_histories[defaultRoom] = std::make_unique<ChatHistory>(defaultRoom);
    LOG_INFO("RoomManager initialized. Default room: #" + defaultRoom);
}

std::string RoomManager::nickFromFd(int fd)
{
    if (!m_server)
        return "";
    ClientSession *s = m_server->getSession(fd);
    return s ? s->nickname() : "";
}

ErrorCode RoomManager::createRoom(const std::string &name, const std::string &creator)
{
    std::unique_lock<std::shared_mutex> lk(m_mutex);
    if (m_rooms.count(name))
        return ErrorCode::ERR_INTERNAL;
    if ((int)m_rooms.size() >= Constants::MAX_ROOMS)
        return ErrorCode::ERR_INTERNAL;

    m_rooms[name] = std::make_unique<Room>(name, creator);
    m_histories[name] = std::make_unique<ChatHistory>(name);
    LOG_INFO("Room created: #" + name + " by " + creator);
    return ErrorCode::ERR_OK;
}

ErrorCode RoomManager::deleteRoom(const std::string &name,
                                  const std::string &requester, bool isOwner)
{
    std::unique_lock<std::shared_mutex> lk(m_mutex);
    auto it = m_rooms.find(name);
    if (it == m_rooms.end())
        return ErrorCode::ERR_ROOM_NOT_FOUND;
    if (name == m_defaultRoom)
        return ErrorCode::ERR_PERMISSION_DENIED;
    if (!isOwner && it->second->creator() != requester)
        return ErrorCode::ERR_PERMISSION_DENIED;

    m_rooms.erase(it);
    m_histories.erase(name);
    LOG_INFO("Room deleted: #" + name);
    return ErrorCode::ERR_OK;
}

ErrorCode RoomManager::joinRoom(int fd, const std::string &nickname, const std::string &roomName)
{
    std::string oldRoom;
    {
        std::shared_lock<std::shared_mutex> lk(m_mutex);
        auto it = m_fdToRoom.find(fd);
        if (it != m_fdToRoom.end())
            oldRoom = it->second;
    }

    {
        std::unique_lock<std::shared_mutex> lk(m_mutex);
        auto it = m_rooms.find(roomName);
        if (it == m_rooms.end())
        {
            m_rooms[roomName] = std::make_unique<Room>(roomName, nickname);
            m_histories[roomName] = std::make_unique<ChatHistory>(roomName);
            LOG_INFO("Auto-created room #" + roomName + " by " + nickname);
        }

        Room *room = m_rooms[roomName].get();
        if (room->isFull())
            return ErrorCode::ERR_ROOM_FULL;

        if (!oldRoom.empty() && m_rooms.count(oldRoom))
        {
            m_rooms[oldRoom]->removeMember(fd);
        }

        room->addMember(fd);
        m_fdToRoom[fd] = roomName;
    }

    if (!oldRoom.empty() && oldRoom != roomName)
    {
        broadcastToRoom(oldRoom,
                        Builder::makeSystemNotify(nickname + " left #" + oldRoom), fd);
    }

    broadcastToRoom(roomName,
                    Builder::makeSystemNotify(nickname + " joined #" + roomName), fd);

    sendHistoryToClient(fd, roomName, 50);

    if (m_server)
    {
        ClientSession *sess = m_server->getSession(fd);
        if (sess)
            sess->setRoom(roomName);
    }

    return ErrorCode::ERR_OK;
}

void RoomManager::leaveRoom(int fd, const std::string& nickname, const std::string& roomName) {
    bool roomEmpty = false;

    {
        std::unique_lock<std::shared_mutex> lk(m_mutex);
        auto it = m_rooms.find(roomName);
        if (it == m_rooms.end()) return;

        it->second->removeMember(fd);
        m_fdToRoom[fd] = m_defaultRoom;

        if (roomName != m_defaultRoom)
            m_rooms[m_defaultRoom]->addMember(fd);

        roomEmpty = (it->second->getMemberCount() == 0 && roomName != m_defaultRoom);
        if (roomEmpty) {
            m_rooms.erase(it);
            m_histories.erase(roomName);
            LOG_INFO("Auto-deleted empty room: #" + roomName);
        }
    }

    broadcastToRoom(roomName,
        Builder::makeSystemNotify(nickname + " left #" + roomName), fd);

    if (roomName != m_defaultRoom) {
        broadcastToRoom(m_defaultRoom,
            Builder::makeSystemNotify(nickname + " joined #" + m_defaultRoom), fd);
    }

    if (m_server) {
        ClientSession* sess = m_server->getSession(fd);
        if (sess) sess->setRoom(m_defaultRoom);
    }
}

void RoomManager::removeUser(int fd) {
    std::string room;
    {
        std::unique_lock<std::shared_mutex> lk(m_mutex);
        auto it = m_fdToRoom.find(fd);
        if (it != m_fdToRoom.end()) {
            room = it->second;
            m_fdToRoom.erase(it);
        }
        for (auto& [rname, rptr] : m_rooms) rptr->removeMember(fd);
    }
    (void)room;
}

void RoomManager::broadcastToRoom(const std::string& room, const Packet& pkt,
                                   int excludeFd) {
    std::set<int> members;
    {
        std::shared_lock<std::shared_mutex> lk(m_mutex);
        auto it = m_rooms.find(room);
        if (it == m_rooms.end()) return;
        members = it->second->getMembers();
    }
    if (!m_server) return;
    for (int fd : members) {
        if (fd == excludeFd) continue;
        ClientSession* sess = m_server->getSession(fd);
        if (sess) sess->sendPacket(pkt);
    }
}

std::vector<RoomInfo> RoomManager::getRoomList() {
    std::shared_lock<std::shared_mutex> lk(m_mutex);
    std::vector<RoomInfo> result;
    for (auto& [name, rptr] : m_rooms) {
        RoomInfo info;
        info.name         = name;
        info.topic        = rptr->topic();
        info.creator      = rptr->creator();
        info.member_count = rptr->getMemberCount();
        info.is_private   = rptr->isPrivate();
        result.push_back(info);
    }
    return result;
}

std::string RoomManager::getUserRoom(int fd) {
    std::shared_lock<std::shared_mutex> lk(m_mutex);
    auto it = m_fdToRoom.find(fd);
    return it != m_fdToRoom.end() ? it->second : m_defaultRoom;
}

std::vector<std::string> RoomManager::getUsersInRoom(const std::string& room) {
    std::shared_lock<std::shared_mutex> lk(m_mutex);
    auto it = m_rooms.find(room);
    if (it == m_rooms.end()) return {};
    return it->second->getMemberNicknames([this](int fd) {
        return nickFromFd(fd);
    });
}


Room* RoomManager::getRoom(const std::string& name) {
    std::shared_lock<std::shared_mutex> lk(m_mutex);
    auto it = m_rooms.find(name);
    return it != m_rooms.end() ? it->second.get() : nullptr;
}

ChatHistory* RoomManager::getOrCreateHistory(const std::string& room) {
    std::unique_lock<std::shared_mutex> lk(m_mutex);
    if (!m_histories.count(room))
        m_histories[room] = std::make_unique<ChatHistory>(room);
    return m_histories[room].get();
}

void RoomManager::appendHistory(const std::string& room, const HistoryEntry& entry) {
    ChatHistory* h = getOrCreateHistory(room);
    if (h) h->append(entry);
}

void RoomManager::sendHistoryToClient(int fd, const std::string& room, int n) {
    ChatHistory* h = getOrCreateHistory(room);
    if (!h || !m_server) return;

    auto entries = h->getRecent(n);
    if (entries.empty()) return;

    ClientSession* sess = m_server->getSession(fd);
    if (!sess) return;

    Packet histPkt = h->serializeForClient(entries);
    sess->sendPacket(Builder::makeSystemNotify("--- Chat history for #" + room + " ---"));
    sess->sendPacket(histPkt);
    sess->sendPacket(Builder::makeSystemNotify("--- End of history ---"));
}