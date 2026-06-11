#include "TcpServer.h"
#include "../utils/Logger.h"
#include "../utils/Config.h"
#include "../protocol/Builder.h"
#include "../protocol/Parser.h"
#include "../../common/Constants.h"
#include "../../common/MessageTypes.h"
#include "../../common/ErrorCodes.h"
#include "../security/CryptoEngine.h"
#include "../utils/Database.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <regex>
#include <nlohmann/json.hpp>
#include <fcntl.h>
#include <sys/epoll.h>

using json = nlohmann::json;

TcpServer *TcpServer::s_instance = nullptr;

TcpServer::TcpServer() : m_listenFd(-1), m_maxClients(256), m_running(false)
{
    s_instance = this;
}

TcpServer::~TcpServer()
{
    stop();
}

bool TcpServer::setNonBlocking(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool TcpServer::start(uint16_t port, int maxClients, int threadPoolSize)
{
    m_maxClients = maxClients;
    m_threadPool = std::make_unique<ThreadPool>(threadPoolSize);
    m_sessionToken = std::make_shared<vcs::security::SessionToken>(vcs::security::CryptoEngine::getInstance().getJWTSecret());
    m_authManager = std::make_unique<vcs::security::AuthManager>(Database::instance().handle(), m_sessionToken);
    m_keyExchange = std::make_unique<vcs::security::KeyExchange>(vcs::security::CryptoEngine::getInstance().getRSA(),
        [](int fd, const std::vector<uint8_t>& key){
            vcs::security::CryptoEngine::getInstance().establishSession(fd, key);
        }
    );

    m_listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (m_listenFd < 0)
    {
        LOG_CRITICAL("Failed to create socket.");
        return false;
    }

    int opt = 1;
    setsockopt(m_listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (::bind(m_listenFd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        LOG_CRITICAL("Bind failed on port " + std::to_string(port));
        return false;
    }

    if (::listen(m_listenFd, 128) < 0)
    {
        LOG_CRITICAL("Listen failed.");
        return false;
    }

    
    m_epollFd = epoll_create1(0);
    if (m_epollFd < 0){
        LOG_CRITICAL("Failed to create epoll instance.");
        return false;
    }
    
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = m_listenFd;
    if (epoll_ctl(m_epollFd, EPOLL_CTL_ADD, m_listenFd, &ev) < 0){
        LOG_CRITICAL("Failed to add listen fd to epoll.");
        return false;
    }
    
    m_running = true;
    const auto &cfg = Config::instance().get();
    m_rooms[cfg.default_room] = {};

    LOG_INFO("Server starting...");
    LOG_INFO("Listening on 0.0.0.0:" + std::to_string(port));
    LOG_INFO("Max clients: " + std::to_string(maxClients));
    LOG_INFO("Press Ctrl+C to stop");

    epollLoop();
    return true;
}

void TcpServer::stop()
{
    if (!m_running.exchange(false))
        return;
    broadcastToAll(Builder::makeSystemNotify("Server is shutting down."));

    if (m_listenFd >= 0)
    {
        ::close(m_listenFd);
        m_listenFd = -1;
    }
    {
        std::unique_lock<std::shared_mutex> lock(m_sessionsMutex);
        for (auto &[fd, sess] : m_sessions)
        {
            sess->stop();
        }
        m_sessions.clear();
    }

    if (m_threadPool)
        m_threadPool->shutdown();
    LOG_INFO("Server stopped.");
}

void TcpServer::epollLoop() {
   constexpr int MAX_EVENTS = 64;
   epoll_event events[MAX_EVENTS];

   while (m_running){
    int nfds = epoll_wait(m_epollFd, events, MAX_EVENTS, 100);
    if (nfds < 0){
        if (m_running && errno != EINTR) LOG_WARN("epoll_wait failed.");
            continue;
    }

    for (int i = 0; i <nfds; i++){
        int fd = events[i].data.fd;

        if (fd == m_listenFd){
            sockaddr_in clientAddr{};
            socklen_t addrLen = sizeof(clientAddr);
            int clientFd = ::accept(m_listenFd, (sockaddr*)&clientAddr, &addrLen);
            if (clientFd < 0) continue;
            std::string ip = inet_ntoa(clientAddr.sin_addr);

            {
                std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
                if ((int)m_sessions.size() >= m_maxClients){
                    Packet rej = Builder::makeConnectReject(ErrorCode::ERR_SERVER_FULL, "Server full");
                    auto bytes = packetToBytes(rej);
                    ::send(clientFd, bytes.data(), bytes.size(), MSG_NOSIGNAL);
                    ::close(clientFd);
                    continue;
                }
            }

            setNonBlocking(clientFd);
            epoll_event evClient{};
            evClient.events = EPOLLIN | EPOLLRDHUP;
            evClient.data.fd = clientFd;
            epoll_ctl(m_epollFd, EPOLL_CTL_ADD, clientFd, &evClient);

            auto session = std::make_shared<ClientSession>(clientFd, ip, this);
            m_keyExchange->addClient(clientFd, ip);
            {
                std::unique_lock<std::shared_mutex> lock(m_sessionsMutex);
                m_sessions[clientFd] = session;
            }
            session->start(); // Giải phóng ngay lập tức, không chiếm thread
            LOG_INFO("New non-blocking connection: " + ip + " fd=" + std::to_string(clientFd));
        }
        else{
            if (events[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)){
                epoll_ctl(m_epollFd, EPOLL_CTL_DEL, fd, nullptr);
                onClientDisconnected(fd);
                continue;
            }

            if (events[i].events & EPOLLIN){
                uint8_t buffer[2048];
                ssize_t n = ::recv(fd, buffer, sizeof(buffer), 0);

                if (n <= 0){
                    epoll_ctl(m_epollFd, EPOLL_CTL_DEL, fd, nullptr);
                    onClientDisconnected(fd);
                }else{
                    std::shared_ptr<ClientSession> sess;
                    {
                        std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
                        auto it = m_sessions.find(fd);
                        if (it != m_sessions.end()) {
                            sess = it->second;
                        }
                    }
                    if (sess){
                        sess->appendAndParseBytes(buffer, n);
                    }
                }
            }
        }
    }
   }
}

void TcpServer::onPacketReceived(int fd, const Packet& pkt){
    m_threadPool->submit([this, fd, pkt]() {
        handlePacket(fd, pkt);
    });
}

void TcpServer::handlePacket(int fd, const Packet& pkt){
    auto type = static_cast<MessageType>(pkt.header.msg_type);
    switch (type) {
        case MessageType::MSG_CRYPTO_HELLO: {
            Packet resp = m_keyExchange->handleHello(fd, pkt);
            if (ClientSession* sess = getSession(fd)) {
                sess->sendPacket(resp);
                if (resp.header.msg_type == static_cast<uint8_t>(MessageType::MSG_ERROR)) onClientDisconnected(fd);
            }
            break;
        }
        case MessageType::MSG_CRYPTO_KEY_ACCEPT: {
            Packet resp = m_keyExchange->handleKeyAccept(fd, pkt);
            if (ClientSession* sess = getSession(fd)) {
                sess->sendPacket(resp);
                if (resp.header.msg_type == static_cast<uint8_t>(MessageType::MSG_ERROR)) onClientDisconnected(fd);
            }
            break;
        }
        case MessageType::MSG_CONNECT_REQUEST:   handleConnectRequest(fd, pkt); break;
        case MessageType::MSG_RECONNECT_REQUEST: handleReconnectRequest(fd, pkt); break;
        case MessageType::MSG_CHAT_SEND:         handleChatSend(fd, pkt);       break;
        case MessageType::MSG_CHAT_PRIVATE:      handleChatPrivate(fd, pkt);    break;
        case MessageType::MSG_DISCONNECT:        handleDisconnect(fd, pkt);     break;
        case MessageType::MSG_PING:              handlePing(fd);                break;
        case MessageType::MSG_PONG:              handlePong(fd);                break;
        case MessageType::MSG_USER_LIST_REQUEST: handleUserListRequest(fd);     break;
        case MessageType::MSG_ROOM_LIST_REQUEST: handleRoomListRequest(fd);     break;
        case MessageType::MSG_ROOM_JOIN:         handleRoomJoin(fd, pkt);       break;
        case MessageType::MSG_ROOM_CREATE:       handleRoomCreate(fd, pkt);     break;
        case MessageType::MSG_ROOM_LEAVE:        handleRoomLeave(fd);           break;
        default:
            LOG_WARN("Unknown packet type: " + std::to_string(pkt.header.msg_type));
            break;
    }
}

void TcpServer::handleConnectRequest(int fd, const Packet& pkt){
    auto parsed = Parser::parseConnectRequest(pkt);
    ClientSession* sess = getSession(fd);
    if (!sess) return;

    if (!isNicknameValid(parsed.nickname)) {
        sess->sendPacket(Builder::makeConnectReject(ErrorCode::ERR_NICKNAME_INVALID, "Invalid nickname"));
        onClientDisconnected(fd);
        return;
    }

    if (isNicknameTaken(parsed.nickname)) {
        sess->sendPacket(Builder::makeConnectReject(ErrorCode::ERR_NICKNAME_TAKEN, "User already online"));
        onClientDisconnected(fd);
        return;
    }

    if (!m_authManager->isNicknameTaken(parsed.nickname)) {
        ErrorCode err = m_authManager->registerUser(parsed.nickname, parsed.password);
        if (err != ErrorCode::ERR_OK) {
            sess->sendPacket(Builder::makeConnectReject(err, "Registration failed"));
            onClientDisconnected(fd);
            return;
        }
    }

    std::string token;
    ErrorCode err = m_authManager->authenticate(parsed.nickname, parsed.password, fd, token);
    if (err != ErrorCode::ERR_OK) {
        sess->sendPacket(Builder::makeConnectReject(err, "Authentication failed"));
        onClientDisconnected(fd);
        return;
    }

    const auto& cfg = Config::instance().get();
    sess->setNickname(parsed.nickname);
    sess->setRoom(cfg.default_room);
    sess->setAuthenticated(true);

    {
        std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
        m_rooms[cfg.default_room].insert(fd);
    }

    sess->sendPacket(Builder::makeConnectAccept(token, cfg.default_room));

    std::string notify = parsed.nickname + " joined #" + cfg.default_room;
    broadcastToRoom(cfg.default_room, Builder::makeSystemNotify(notify), fd);

    LOG_INFO("Client authenticated: " + parsed.nickname + " from " + sess->ip());
}

void TcpServer::handleReconnectRequest(int fd, const Packet& pkt) {
    std::string token = Parser::parseReconnectRequest(pkt);
    ClientSession* sess = getSession(fd);
    if (!sess) return;

    if (token.empty()) {
        sess->sendPacket(Builder::makeConnectReject(ErrorCode::ERR_AUTH_FAILED, "Missing token"));
        onClientDisconnected(fd);
        return;
    }

    std::string nickname;
    ErrorCode err = m_authManager->reconnectWithToken(token, fd, nickname);
    if (err != ErrorCode::ERR_OK) {
        sess->sendPacket(Builder::makeConnectReject(err, "Invalid or expired token"));
        onClientDisconnected(fd);
        return;
    }

    const auto& cfg = Config::instance().get();
    sess->setNickname(nickname);
    sess->setRoom(cfg.default_room);
    sess->setAuthenticated(true);

    {
        std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
        m_rooms[cfg.default_room].insert(fd);
    }

    sess->sendPacket(Builder::makeConnectAccept(token, cfg.default_room));

    std::string notify = nickname + " reconnected to #" + cfg.default_room;
    broadcastToRoom(cfg.default_room, Builder::makeSystemNotify(notify), fd);

    LOG_INFO("Client reconnected: " + nickname + " from " + sess->ip());
}

void TcpServer::handleChatSend(int fd, const Packet& pkt){
    ClientSession* sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    if (sess->isMuted()){
        sess->sendPacket(Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED,"You are muted"));
        return;
    }

    auto parsed = Parser::parseChatSend(pkt);
    if (parsed.message.empty()) return;
    if ((int)parsed.message.size() > Constants::MAX_MESSAGE_LEN) {
        sess->sendPacket(Builder::makeError(ErrorCode::ERR_MESSAGE_TOO_LONG, "Message too long"));
        return;
    }

    sess->incrementMsgCount();
    std::string room = sess->currentRoom();
    auto broadcast = Builder::makeChatBroadcast(sess->nickname(),  room, parsed.message);
    broadcastToRoom(room, broadcast, -1);
}

void TcpServer::handleChatPrivate(int fd, const Packet& pkt){
    ClientSession* sender = getSession(fd);
    if (!sender || !sender->isAuthenticated()) return;

    auto parsed = Parser::parseChatPrivate(pkt);
    if (parsed.to.empty() || parsed.message.empty()) return;

    std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
    for (auto& [ofd, sess] : m_sessions){
        if (sess->nickname() == parsed.to && sess->isAuthenticated()) {
            json j;
            j["from"]    = sender->nickname();
            j["to"]      = parsed.to;
            j["message"] = parsed.message;
            std::string s = j.dump();
            std::vector<uint8_t> payload(s.begin(), s.end());
            Packet p(MessageType::MSG_CHAT_PRIVATE, payload);
            sess->sendPacket(p);
            sender->sendPacket(p);
            return;
        }
    }
    sender->sendPacket(Builder::makeError(ErrorCode::ERR_ROOM_NOT_FOUND, "User not found"));
}

void TcpServer::handleDisconnect(int fd, const Packet&) {
    onClientDisconnected(fd);
}

void TcpServer::handlePing(int fd) {
    ClientSession* sess = getSession(fd);
    if (sess) sess->sendPacket(Builder::makePong());
}

void TcpServer::handlePong(int fd) {
    ClientSession* sess = getSession(fd);
    if (sess) sess->m_pongReceived = true;
}

void TcpServer::handleUserListRequest(int fd) {
    ClientSession* sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    auto users = getUsersInRoom(sess->currentRoom());
    json j = users;
    sess->sendPacket(Builder::makeUserListResponse(j.dump()));
}

void TcpServer::handleRoomListRequest(int fd) {
    ClientSession* sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    auto rooms = getRoomList();
    json j = rooms;
    sess->sendPacket(Builder::makeRoomListResponse(j.dump()));
}

void TcpServer::handleRoomJoin(int fd, const Packet& pkt){
    ClientSession* sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    auto parsed = Parser::parseRoomJoin(pkt);
    std::string newRoom = parsed.room_name;
    if (newRoom.empty()) return;

    std::string oldRoom = sess->currentRoom();

    {
        std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
        if (m_rooms.count(oldRoom)) m_rooms[oldRoom].erase(fd);
        m_rooms[newRoom].insert(fd);
    }

    sess->setRoom(newRoom);

    broadcastToRoom(oldRoom, Builder::makeSystemNotify(sess->nickname() + " left #" + oldRoom), fd);
    broadcastToRoom(newRoom, Builder::makeSystemNotify(sess->nickname() + " joined #" + newRoom), fd);
    sess->sendPacket(Builder::makeSystemNotify("You joined #" + newRoom));   
}

void TcpServer::handleRoomCreate(int fd, const Packet& pkt){
    ClientSession* sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    auto parsed = Parser::parseRoomCreate(pkt);
    std::string roomName = parsed.room_name;
    if (roomName.empty()) return;

    {
        std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
        if (m_rooms.count(roomName)) {
            sess->sendPacket(Builder::makeError(ErrorCode::ERR_INTERNAL, "Room already exists"));
            return;
        }
        if ((int)m_rooms.size() >= Constants::MAX_ROOMS) {
            sess->sendPacket(Builder::makeError(ErrorCode::ERR_INTERNAL, "Max rooms reached"));
            return;
        }
        m_rooms[roomName] = {};
    }

    sess->sendPacket(Builder::makeSystemNotify("Room #" + roomName + " created"));
    LOG_INFO("Room created: #" + roomName + " by " + sess->nickname());
}

void TcpServer::handleRoomLeave(int fd){
    ClientSession* sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    const auto& cfg    = Config::instance().get();
    std::string oldRoom = sess->currentRoom();
    std::string defRoom = cfg.default_room;

    if (oldRoom == defRoom) {
        sess->sendPacket(Builder::makeError(ErrorCode::ERR_INTERNAL, "Cannot leave default room"));
        return;
    }

    {
        std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
        m_rooms[oldRoom].erase(fd);
        m_rooms[defRoom].insert(fd);
    }

    sess->setRoom(defRoom);
    broadcastToRoom(oldRoom, Builder::makeSystemNotify(sess->nickname() + " left #" + oldRoom), fd);
    broadcastToRoom(defRoom, Builder::makeSystemNotify(sess->nickname() + " joined #" + defRoom), fd);
    sess->sendPacket(Builder::makeSystemNotify("You are now in #" + defRoom));
}

void TcpServer::onClientDisconnected(int fd) {
    ClientSession* sess = getSession(fd);
    std::string nick, room;
    if (sess) {
        nick = sess->nickname();
        room = sess->currentRoom();
    }

    removeSession(fd);

    if (!nick.empty() && !room.empty()) {
        broadcastToRoom(room, Builder::makeSystemNotify(nick + " has left the chat"), -1);
        LOG_INFO("Client left: " + nick);
    }
}

void TcpServer::removeSession(int fd) {
    if (m_keyExchange) m_keyExchange->removeClient(fd);
    if (m_authManager) m_authManager->removeSessionByFd(fd);
    vcs::security::CryptoEngine::getInstance().removeSession(fd);

    {
        std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
        for (auto& [rname, members] : m_rooms) {
            members.erase(fd);
        }
    }
    std::unique_lock<std::shared_mutex> lock(m_sessionsMutex);
    auto it = m_sessions.find(fd);
    if (it != m_sessions.end()) {
        it->second->stop();
        m_sessions.erase(it);
    }
}

void TcpServer::broadcastToRoom(const std::string& room, const Packet& pkt, int excludeFd) {
    std::set<int> members;
    {
        std::shared_lock<std::shared_mutex> lock(m_roomsMutex);
        auto it = m_rooms.find(room);
        if (it == m_rooms.end()) return;
        members = it->second;
    }
    std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
    for (int fd : members) {
        if (fd == excludeFd) continue;
        auto it = m_sessions.find(fd);
        if (it != m_sessions.end()) {
            it->second->sendPacket(pkt);
        }
    }
}

void TcpServer::broadcastToAll(const Packet& pkt, int excludeFd) {
    std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
    for (auto& [fd, sess] : m_sessions) {
        if (fd == excludeFd) continue;
        sess->sendPacket(pkt);
    }
}

ClientSession* TcpServer::getSession(int fd) {
    std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
    auto it = m_sessions.find(fd);
    if (it == m_sessions.end()) return nullptr;
    return it->second.get();
}

std::vector<ClientSession*> TcpServer::getSessionsInRoom(const std::string& room) {
    std::set<int> members;
    {
        std::shared_lock<std::shared_mutex> lock(m_roomsMutex);
        auto it = m_rooms.find(room);
        if (it != m_rooms.end()) members = it->second;
    }
    std::vector<ClientSession*> result;
    std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
    for (int fd : members) {
        auto it = m_sessions.find(fd);
        if (it != m_sessions.end()) result.push_back(it->second.get());
    }
    return result;
}

std::vector<std::string> TcpServer::getUsersInRoom(const std::string& room) {
    auto sessions = getSessionsInRoom(room);
    std::vector<std::string> names;
    for (auto* s : sessions) {
        if (s->isAuthenticated()) names.push_back(s->nickname());
    }
    return names;
}

std::vector<std::string> TcpServer::getRoomList() {
    std::shared_lock<std::shared_mutex> lock(m_roomsMutex);
    std::vector<std::string> rooms;
    for (auto& [name, _] : m_rooms) rooms.push_back(name);
    return rooms;
}

bool TcpServer::isNicknameTaken(const std::string& nick) {
    std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
    for (auto& [fd, sess] : m_sessions) {
        if (sess->nickname() == nick && sess->isAuthenticated()) return true;
    }
    return false;
}

bool TcpServer::isNicknameValid(const std::string& nick) {
    if (nick.empty() || (int)nick.size() > Constants::MAX_NICKNAME_LEN) return false;
    static const std::regex valid("^[a-zA-Z0-9_]{3,32}$");
    return std::regex_match(nick, valid);
}