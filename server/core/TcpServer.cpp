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
#include "../features/AdminCommands.h"
#include "../features/FileTransfer.h"
#include "../features/MessageFilter.h"
#include "../security/RateLimiter.h"
#include "../rooms/RoomManager.h"
#include "../rooms/ChatHistory.h"
#include "../security/IntrusionDetector.h"
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
    auto rooms_db = m_authManager->loadAllRoomsFromDb();
    for (const auto& r : rooms_db) {
        RoomInfo info;
        info.creator_nick = r.creator;
        info.has_password = r.has_password;
        auto banned = m_authManager->getBannedUsersForRoomDb(r.name);
        for(const auto& b : banned) info.banned_nicks.insert(b);
        m_rooms[r.name] = info;
    }
    if (m_rooms.find(cfg.default_room) == m_rooms.end()) {
        m_rooms[cfg.default_room] = {"system", {}, {}, false};
    }

    AdminCommands::instance().initialize(this);
    FileTransfer::instance().initialize(this);
    RoomManager::instance().initialize(this, cfg.default_room);
    IntrusionDetector::instance().loadBanList();
    IntrusionDetector::instance().addWhitelist("127.0.0.1");

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

            IPStatus ipStatus = IntrusionDetector::instance().checkIP(ip);
            if (ipStatus == IPStatus::BLOCKED) {
                ::close(clientFd);
                continue;
            }

            if (RateLimiter::instance().checkLimit("ip_" + ip, RateLimitType::CONNECT) == RateCheckResult::RATE_LIMITED) {
                ::close(clientFd);
                continue;
            }

            LOG_INFO("New connection accepted: fd=" + std::to_string(clientFd) + " IP=" + ip);

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

void TcpServer::handlePacket(int fd, const Packet& raw_pkt){
    Packet pkt = raw_pkt;
    if (pkt.header.msg_type != static_cast<uint8_t>(MessageType::MSG_CRYPTO_HELLO) &&
        pkt.header.msg_type != static_cast<uint8_t>(MessageType::MSG_CRYPTO_KEY_ACCEPT)) {
        if (vcs::security::CryptoEngine::getInstance().hasSession(fd)) {
            try {
                pkt.payload = vcs::security::CryptoEngine::getInstance().decryptPayload(fd, pkt.payload);
            } catch (const std::exception& e) {
                LOG_ERROR("Decryption failed for fd=" + std::to_string(fd) + ": " + e.what());
                auto sess = getSession(fd);
                if (sess) {
                    IntrusionDetector::instance().reportViolation(sess->ip(), ViolationType::HMAC_FAILURE);
                    sess->disconnect();
                }
                return;
            }
        } else {
            if (Config::instance().get().enable_encryption) {
                LOG_ERROR("Unencrypted packet received before handshake for fd=" + std::to_string(fd));
                auto sess = getSession(fd);
                if (sess) sess->disconnect();
                return;
            }
        }
    }

    auto type = static_cast<MessageType>(pkt.header.msg_type);
    std::string payload(pkt.payload.begin(), pkt.payload.end());
    switch (type) {
        case MessageType::MSG_CRYPTO_HELLO: {
            Packet resp = m_keyExchange->handleHello(fd, pkt);
            if (auto sess = getSession(fd)) {
                sess->sendPacket(resp);
                if (resp.header.msg_type == static_cast<uint8_t>(MessageType::MSG_ERROR)) onClientDisconnected(fd);
            }
            break;
        }
        case MessageType::MSG_CRYPTO_KEY_ACCEPT: {
            Packet resp = m_keyExchange->handleKeyAccept(fd, pkt);
            if (auto sess = getSession(fd)) {
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
        case MessageType::MSG_ROOM_DELETE:       handleRoomDelete(fd, pkt);     break;
        case MessageType::MSG_ROOM_LEAVE:        handleRoomLeave(fd);           break;
        case MessageType::MSG_ADMIN_ROOM_INFO_REQUEST: handleAdminRoomInfo(fd); break;
        case MessageType::MSG_WHOIS_REQUEST: {
            auto j = nlohmann::json::parse(payload, nullptr, false);
            std::string target = j.value("target", "");
            json resp;
            int tFd = getFdByNickname(target);
            if (tFd == -1) {
                resp["error"] = "User not found";
            } else {
                auto tSess = getSession(tFd);
                if (tSess && tSess->isAuthenticated()) {
                    resp["nickname"] = tSess->nickname();
                    resp["ip"]       = tSess->ip();
                    resp["room"]     = tSess->currentRoom();
                    resp["is_muted"] = tSess->isMuted();
                } else {
                    resp["error"] = "User not found";
                }
            }
            std::string str = resp.dump();
            if (auto sess = getSession(fd)) {
                sess->sendPacket(Packet(MessageType::MSG_WHOIS_RESPONSE, std::vector<uint8_t>(str.begin(), str.end())));
            }
            break;
        }
        
        // Admin Commands
        case MessageType::MSG_ADMIN_KICK: {
            auto j = nlohmann::json::parse(payload, nullptr, false);
            if (!j.is_discarded()) AdminCommands::instance().kick(fd, j.value("target",""), j.value("reason",""));
            break;
        }
        case MessageType::MSG_ADMIN_MUTE: {
            auto j = nlohmann::json::parse(payload, nullptr, false);
            if (!j.is_discarded()) {
                int dur = j.value("duration", -1);
                if (dur == 0) AdminCommands::instance().unmute(fd, j.value("target",""));
                else          AdminCommands::instance().mute(fd, j.value("target",""), dur);
            }
            break;
        }
        case MessageType::MSG_ADMIN_BAN: {
            auto j = nlohmann::json::parse(payload, nullptr, false);
            if (!j.is_discarded()) {
                if (j.value("unban", false)) AdminCommands::instance().unban(fd, j.value("target",""));
                else AdminCommands::instance().ban(fd, j.value("target",""), j.value("reason",""));
            }
            break;
        }
        case MessageType::MSG_ADMIN_PROMOTE: {
            auto j = nlohmann::json::parse(payload, nullptr, false);
            if (!j.is_discarded()) {
                if (j.value("demote", false)) AdminCommands::instance().demote(fd, j.value("target",""));
                else AdminCommands::instance().promote(fd, j.value("target",""));
            }
            break;
        }
        case MessageType::MSG_ADMIN_BROADCAST: {
            auto j = nlohmann::json::parse(payload, nullptr, false);
            if (!j.is_discarded()) AdminCommands::instance().broadcast(fd, j.value("message",""));
            break;
        }
        case MessageType::MSG_ADMIN_UNKICK: {
            auto j = nlohmann::json::parse(payload, nullptr, false);
            if (!j.is_discarded()) AdminCommands::instance().unkick(fd, j.value("target",""), j.value("room",""));
            break;
        }

        // File Transfer
        case MessageType::MSG_FILE_REQUEST:  FileTransfer::instance().handleRequest (fd, payload); break;
        case MessageType::MSG_FILE_ACCEPT:   FileTransfer::instance().handleAccept  (fd, payload); break;
        case MessageType::MSG_FILE_REJECT:   FileTransfer::instance().handleReject  (fd, payload); break;
        case MessageType::MSG_FILE_DATA:     FileTransfer::instance().handleData    (fd, payload); break;
        case MessageType::MSG_FILE_COMPLETE: FileTransfer::instance().handleComplete(fd, payload); break;

        default:
            LOG_WARN("Unknown packet type: " + std::to_string(pkt.header.msg_type));
            break;
    }
}

void TcpServer::handleConnectRequest(int fd, const Packet& pkt){
    auto parsed = Parser::parseConnectRequest(pkt);
    auto sess = getSession(fd);
    if (!sess) return;

    if (!isNicknameValid(parsed.nickname)) {
        sess->sendPacket(Builder::makeConnectReject(ErrorCode::ERR_NICKNAME_INVALID, "Invalid nickname (3-16 alphanumeric characters)"));
        return;
    }

    if (parsed.password.empty()) {
        sess->sendPacket(Builder::makeConnectReject(ErrorCode::ERR_AUTH_FAILED, "Password cannot be empty"));
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

    if (RateLimiter::instance().checkLimit("ip_" + sess->ip() + "_auth", RateLimitType::AUTH) == RateCheckResult::RATE_LIMITED) {
        sess->sendPacket(Builder::makeConnectReject(ErrorCode::ERR_RATE_LIMITED, "Too many requests, please try again later"));
        onClientDisconnected(fd);
        return;
    }

    std::string token;
    ErrorCode err = m_authManager->authenticate(parsed.nickname, parsed.password, fd, token);
    if (err != ErrorCode::ERR_OK) {
        if (err == ErrorCode::ERR_AUTH_FAILED || err == ErrorCode::ERR_AUTH_TOO_MANY_ATTEMPTS) {
            IntrusionDetector::instance().reportViolation(sess->ip(), ViolationType::FAILED_AUTH);
        }
        sess->sendPacket(Builder::makeConnectReject(err, "Invalid nickname or password"));
        return;
    }

    if (IntrusionDetector::instance().isBannedNick(parsed.nickname)) {
        sess->sendPacket(Builder::makeConnectReject(ErrorCode::ERR_PERMISSION_DENIED, "Your nickname is permanently banned."));
        return;
    }

    const auto& cfg = Config::instance().get();
    std::string lastRoom = m_authManager->getLastRoom(parsed.nickname);
    std::string roomToJoin = cfg.default_room;
    
    if (!lastRoom.empty()) {
        std::shared_lock<std::shared_mutex> lock(m_roomsMutex);
        if (m_rooms.count(lastRoom)) {
            roomToJoin = lastRoom;
        }
    }

    sess->setNickname(parsed.nickname);
    sess->setRoom(roomToJoin);
    sess->setAuthenticated(true);
    
    time_t muteUntil = 0;
    bool isMuted = m_authManager->getMuteStateDb(parsed.nickname, muteUntil);
    if (isMuted && (muteUntil == 0 || muteUntil > std::time(nullptr))) {
        sess->setMuted(true, muteUntil);
    } else if (isMuted) {
        m_authManager->updateMuteStateDb(parsed.nickname, false, 0);
        sess->setMuted(false, 0);
    }

    auto role = m_authManager->getUserRole(parsed.nickname);
    if (role == vcs::security::SessionToken::Role::OWNER) sess->setRole(UserRole::OWNER);
    else if (role == vcs::security::SessionToken::Role::ADMIN) sess->setRole(UserRole::ADMIN);
    else sess->setRole(UserRole::USER);

    {
        std::unique_lock<std::shared_mutex> lock(m_sessionsMutex);
        m_nicknames[parsed.nickname] = fd;
    }

    {
        std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
        m_rooms[roomToJoin].members.insert(fd);
    }

    bool isAdmin = (role == vcs::security::SessionToken::Role::ADMIN || role == vcs::security::SessionToken::Role::OWNER);
    sess->sendPacket(Builder::makeConnectAccept(token, roomToJoin, sess->nickname(), isAdmin));

    std::string notify = parsed.nickname + " joined #" + roomToJoin;
    broadcastToRoom(roomToJoin, Builder::makeSystemNotify(notify), fd);
    RoomManager::instance().sendHistoryToClient(fd, roomToJoin, 50);

    LOG_INFO("Client authenticated: " + parsed.nickname + " from " + sess->ip() + " (Room: " + roomToJoin + ")");
}

void TcpServer::handleReconnectRequest(int fd, const Packet& pkt) {
    std::string token = Parser::parseReconnectRequest(pkt);
    auto sess = getSession(fd);
    if (!sess) return;

    if (token.empty()) {
        sess->sendPacket(Builder::makeConnectReject(ErrorCode::ERR_AUTH_FAILED, "Missing token"));
        return;
    }

    std::string nickname;
    ErrorCode err = m_authManager->reconnectWithToken(token, fd, nickname);
    if (err != ErrorCode::ERR_OK) {
        sess->sendPacket(Builder::makeConnectReject(err, "Invalid or expired token"));
        return;
    }

    const auto& cfg = Config::instance().get();
    std::string lastRoom = m_authManager->getLastRoom(nickname);
    std::string roomToJoin = cfg.default_room;
    
    if (!lastRoom.empty()) {
        std::shared_lock<std::shared_mutex> lock(m_roomsMutex);
        if (m_rooms.count(lastRoom)) {
            roomToJoin = lastRoom;
        }
    }

    sess->setNickname(nickname);
    sess->setRoom(roomToJoin);
    sess->setAuthenticated(true);
    
    time_t muteUntil = 0;
    bool isMuted = m_authManager->getMuteStateDb(nickname, muteUntil);
    if (isMuted && (muteUntil == 0 || muteUntil > std::time(nullptr))) {
        sess->setMuted(true, muteUntil);
    } else if (isMuted) {
        m_authManager->updateMuteStateDb(nickname, false, 0);
        sess->setMuted(false, 0);
    }

    auto role = m_authManager->getUserRole(nickname);
    if (role == vcs::security::SessionToken::Role::OWNER) sess->setRole(UserRole::OWNER);
    else if (role == vcs::security::SessionToken::Role::ADMIN) sess->setRole(UserRole::ADMIN);
    else sess->setRole(UserRole::USER);

    {
        std::unique_lock<std::shared_mutex> lock(m_sessionsMutex);
        m_nicknames[nickname] = fd;
    }

    {
        std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
        m_rooms[roomToJoin].members.insert(fd);
    }

    bool isAdmin = (sess->role() == UserRole::ADMIN || sess->role() == UserRole::OWNER);
    sess->sendPacket(Builder::makeConnectAccept(token, roomToJoin, sess->nickname(), isAdmin));

    std::string notify = nickname + " reconnected to #" + roomToJoin;
    broadcastToRoom(roomToJoin, Builder::makeSystemNotify(notify), fd);
    RoomManager::instance().sendHistoryToClient(fd, roomToJoin, 50);

    LOG_INFO("Client reconnected: " + nickname + " from " + sess->ip() + " (Room: " + roomToJoin + ")");
}

void TcpServer::handleChatSend(int fd, const Packet& pkt){
    auto sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    if (sess->isMuted()){
        sess->sendPacket(Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED,"You have been muted!"));
        return;
    }

    std::string fd_key = "fd_" + std::to_string(fd);
    if (RateLimiter::instance().checkLimit(fd_key, RateLimitType::MSG_CHAT) == RateCheckResult::RATE_LIMITED) {
        sess->sendPacket(Builder::makeError(ErrorCode::ERR_RATE_LIMITED, "Please chat slower (Spam detected)"));
        return;
    }

    auto parsed = Parser::parseChatSend(pkt);
    if (parsed.message.empty()) return;

    auto filterRes = MessageFilter::instance().filter(parsed.message, fd, sess->nickname());
    if (filterRes.result != FilterResult::PASS) {
        sess->sendPacket(Builder::makeError(ErrorCode::ERR_MESSAGE_BLOCKED, "Your message was blocked by the security filter"));
        return;
    }

    if ((int)parsed.message.size() > Constants::MAX_MESSAGE_LEN) {
        sess->sendPacket(Builder::makeError(ErrorCode::ERR_MESSAGE_TOO_LONG, "Message is too long"));
        return;
    }

    sess->incrementMsgCount();
    std::string room = sess->currentRoom();
    
    LOG_INFO("CHAT | Room: " + room + " | User: " + sess->nickname() + " | Msg: " + parsed.message);
    
    auto broadcast = Builder::makeChatBroadcast(sess->nickname(),  room, parsed.message);
    broadcastToRoom(room, broadcast, -1); // Broadcast to everyone, including sender

    HistoryEntry entry;
    entry.timestamp = std::time(nullptr);
    entry.sender = sess->nickname();
    entry.room = room;
    entry.message = parsed.message;
    entry.msg_type = HistoryMsgType::CHAT;
    RoomManager::instance().appendHistory(room, entry);
}

void TcpServer::handleChatPrivate(int fd, const Packet& pkt){
    auto sender = getSession(fd);
    if (!sender || !sender->isAuthenticated()) return;

    if (sender->isMuted()){
        sender->sendPacket(Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED,"You have been muted!"));
        return;
    }

    auto parsed = Parser::parseChatPrivate(pkt);
    if (parsed.to == sender->nickname()) {
        sender->sendPacket(Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "Cannot send message to yourself"));
        return;
    }

    if (parsed.to.empty() || parsed.message.empty()) return;

    auto filterRes = MessageFilter::instance().filter(parsed.message, fd, sender->nickname());
    if (filterRes.result != FilterResult::PASS) {
        sender->sendPacket(Builder::makeError(ErrorCode::ERR_MESSAGE_BLOCKED, "Your message was blocked by the security filter"));
        return;
    }

    int targetFd = getFdByNickname(parsed.to);
    if (targetFd != -1) {
        std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
        auto it = m_sessions.find(targetFd);
        if (it != m_sessions.end() && it->second->isAuthenticated()) {
            json j;
            j["from"]    = sender->nickname();
            j["to"]      = parsed.to;
            j["message"] = parsed.message;
            std::string s = j.dump();
            std::vector<uint8_t> payload(s.begin(), s.end());
            Packet p(MessageType::MSG_CHAT_PRIVATE, payload);
            it->second->sendPacket(p);
            sender->sendPacket(p);
            return;
        }
    }
    sender->sendPacket(Builder::makeError(ErrorCode::ERR_ROOM_NOT_FOUND, "Target user not found"));
}

void TcpServer::handleDisconnect(int fd, const Packet&) {
    onClientDisconnected(fd);
}

void TcpServer::handlePing(int fd) {
    auto sess = getSession(fd);
    if (sess) sess->sendPacket(Builder::makePong());
}

void TcpServer::handlePong(int fd) {
    auto sess = getSession(fd);
    if (sess) sess->m_pongReceived = true;
}

void TcpServer::handleUserListRequest(int fd) {
    auto sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    auto users = getUsersInRoom(sess->currentRoom());
    json j = users;
    sess->sendPacket(Builder::makeUserListResponse(j.dump()));
}

void TcpServer::handleRoomListRequest(int fd) {
    auto sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    auto allRooms = m_authManager->loadAllRoomsFromDb();
    std::set<std::string> publicRooms;
    for (const auto& r : allRooms) {
        if (!r.has_password) publicRooms.insert(r.name);
    }

    json j = json::array();
    std::shared_lock<std::shared_mutex> lock(m_roomsMutex);
    for (const auto& [name, roomData] : m_rooms) {
        if (publicRooms.find(name) != publicRooms.end()) {
            json item;
            item["room"] = name;
            item["users"] = roomData.members.size();
            j.push_back(item);
        }
    }
    sess->sendPacket(Builder::makeRoomListResponse(j.dump()));
}

void TcpServer::handleRoomJoin(int fd, const Packet& pkt){
    auto sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    auto parsed = Parser::parseRoomJoin(pkt);
    std::string newRoom = parsed.room_name;
    if (newRoom.empty()) return;

    auto allRooms = m_authManager->loadAllRoomsFromDb();
    bool isPasswordProtected = false;
    bool roomExists = false;
    for (const auto& r : allRooms) {
        if (r.name == newRoom) {
            roomExists = true;
            isPasswordProtected = r.has_password;
            break;
        }
    }

    if (isPasswordProtected) {
        auto err = m_authManager->verifyRoomPasswordDb(newRoom, parsed.password);
        if (err != ErrorCode::ERR_OK) {
            sess->sendPacket(Builder::makeError(err, "Incorrect password or room not found"));
            return;
        }
    } else if (!roomExists && newRoom != Config::instance().get().default_room) {
        sess->sendPacket(Builder::makeError(ErrorCode::ERR_ROOM_NOT_FOUND, "Room not found"));
        return;
    }

    std::string oldRoom = sess->currentRoom();

    {
        std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
        if (m_rooms.count(newRoom) && m_rooms[newRoom].banned_nicks.count(sess->nickname())) {
            sess->sendPacket(Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "You have been kicked from this room."));
            return;
        }
        if (m_rooms.count(oldRoom)) m_rooms[oldRoom].members.erase(fd);
        m_rooms[newRoom].members.insert(fd);
    }

    sess->setRoom(newRoom);
    m_authManager->updateLastRoom(sess->nickname(), newRoom);

    broadcastToRoom(oldRoom, Builder::makeSystemNotify(sess->nickname() + " left #" + oldRoom), fd);
    broadcastToRoom(newRoom, Builder::makeSystemNotify(sess->nickname() + " joined #" + newRoom), fd);
    sess->sendPacket(Builder::makeSystemNotify("You joined #" + newRoom));
    RoomManager::instance().sendHistoryToClient(fd, newRoom, 50);
}

void TcpServer::handleRoomDelete(int fd, const Packet& pkt) {
    auto sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    auto parsed = Parser::parseRoomDelete(pkt);
    std::string roomName = parsed.room_name;
    const auto& cfg = Config::instance().get();

    if (roomName == cfg.default_room) {
        sess->sendPacket(Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "Cannot delete the default room (general)"));
        return;
    }

    std::string creator = m_authManager->getRoomCreatorDb(roomName);
    if (creator.empty()) {
        sess->sendPacket(Builder::makeError(ErrorCode::ERR_ROOM_NOT_FOUND, "Room does not exist"));
        return;
    }

    bool isAdmin = (sess->role() == UserRole::ADMIN || sess->role() == UserRole::OWNER);
    if (creator != sess->nickname() && !isAdmin) {
        sess->sendPacket(Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "Only the room creator or an ADMIN can delete this room"));
        return;
    }

    std::set<int> membersToKick;
    {
        std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
        if (m_rooms.count(roomName)) {
            membersToKick = m_rooms[roomName].members;
            m_rooms.erase(roomName);
        }
    }

    m_authManager->deleteRoomDb(roomName);
    broadcastToRoom(roomName, Builder::makeSystemNotify("Room #" + roomName + " has been deleted."), -1);

    for (int memberFd : membersToKick) {
        auto mSess = getSession(memberFd);
        if (mSess) {
            {
                std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
                m_rooms[cfg.default_room].members.insert(memberFd);
            }
            mSess->setRoom(cfg.default_room);
            mSess->sendPacket(Builder::makeSystemNotify("You were moved to #" + cfg.default_room + " because your room was deleted."));
            broadcastToRoom(cfg.default_room, Builder::makeSystemNotify(mSess->nickname() + " joined #" + cfg.default_room), memberFd);
        }
    }
    
    sess->sendPacket(Builder::makeSystemNotify("Room #" + roomName + " deleted successfully."));
}

void TcpServer::handleAdminRoomInfo(int fd) {
    auto sess = getSession(fd);
    if (!sess || !sess->isAuthenticated() || (sess->role() != UserRole::ADMIN && sess->role() != UserRole::OWNER)) {
        if (sess) sess->sendPacket(Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "You do not have admin privileges"));
        return;
    }

    nlohmann::json j = nlohmann::json::array();
    {
        std::shared_lock<std::shared_mutex> lock(m_roomsMutex);
        for (const auto& [rname, rinfo] : m_rooms) {
            nlohmann::json item;
            item["room"] = rname;
            item["creator"] = rinfo.creator_nick;
            item["count"] = rinfo.members.size();
            j.push_back(item);
        }
    }
    sess->sendPacket(Builder::makeAdminRoomInfoResponse(j.dump()));
}

void TcpServer::handleRoomCreate(int fd, const Packet& pkt){
    auto sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    auto parsed = Parser::parseRoomCreate(pkt);
    std::string roomName = parsed.room_name;
    if (roomName.empty()) return;

    {
        std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
        if (m_rooms.count(roomName)) {
            sess->sendPacket(Builder::makeError(ErrorCode::ERR_INTERNAL, "Room name already exists"));
            return;
        }
        if ((int)m_rooms.size() >= Constants::MAX_ROOMS) {
            sess->sendPacket(Builder::makeError(ErrorCode::ERR_INTERNAL, "System has reached maximum number of rooms"));
            return;
        }
        
        ErrorCode err = m_authManager->createRoomDb(roomName, parsed.password, sess->nickname());
        if (err != ErrorCode::ERR_OK) {
            sess->sendPacket(Builder::makeError(err, "Cannot create room right now, please try again later"));
            return;
        }
        
        m_rooms[roomName] = {sess->nickname(), {}, {}, !parsed.password.empty()};
    }

    sess->sendPacket(Builder::makeSystemNotify("Room #" + roomName + " created"));
    LOG_INFO("Room created: #" + roomName + " by " + sess->nickname());
}

void TcpServer::kickFromRoom(int targetFd, const std::string& adminNick, const std::string& reason) {
    auto target = getSession(targetFd);
    if (!target) return;
    std::string room = target->currentRoom();
    const auto& cfg = Config::instance().get();
    if (room != cfg.default_room) {
        {
            std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
            m_rooms[room].members.erase(targetFd);
            m_rooms[room].banned_nicks.insert(target->nickname());
            m_authManager->banUserFromRoomDb(room, target->nickname());
            m_rooms[cfg.default_room].members.insert(targetFd);
        }
        target->setRoom(cfg.default_room);
        target->sendPacket(Builder::makeSystemNotify("You were kicked to #" + cfg.default_room + " by " + adminNick + ": " + reason));
        broadcastToRoom(cfg.default_room, Builder::makeSystemNotify(target->nickname() + " was kicked here from #" + room), targetFd);
    }
}

void TcpServer::unkickFromRoom(const std::string& targetNick, const std::string& adminNick, const std::string& room) {
    (void)adminNick;
    std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
    if (m_rooms.count(room)) {
        if (m_rooms[room].banned_nicks.erase(targetNick) > 0) {
            m_authManager->unbanUserFromRoomDb(room, targetNick);
        }
    }
}

void TcpServer::handleRoomLeave(int fd){
    auto sess = getSession(fd);
    if (!sess || !sess->isAuthenticated()) return;

    const auto& cfg    = Config::instance().get();
    std::string oldRoom = sess->currentRoom();
    std::string defRoom = cfg.default_room;

    if (oldRoom == defRoom) {
        sess->sendPacket(Builder::makeError(ErrorCode::ERR_INTERNAL, "You cannot leave the default room (general)"));
        return;
    }

    {
        std::unique_lock<std::shared_mutex> lock(m_roomsMutex);
        m_rooms[oldRoom].members.erase(fd);
        m_rooms[defRoom].members.insert(fd);
    }

    sess->setRoom(defRoom);
    broadcastToRoom(oldRoom, Builder::makeSystemNotify(sess->nickname() + " left #" + oldRoom), fd);
    broadcastToRoom(defRoom, Builder::makeSystemNotify(sess->nickname() + " joined #" + defRoom), fd);
    sess->sendPacket(Builder::makeSystemNotify("You are now in #" + defRoom));
}

void TcpServer::onClientDisconnected(int fd) {
    std::string fd_key = "fd_" + std::to_string(fd);
    RateLimiter::instance().removeKey(fd_key);
    auto sess = getSession(fd);
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

    std::string room_to_remove;
    {
        std::shared_lock<std::shared_mutex> slock(m_sessionsMutex);
        auto it = m_sessions.find(fd);
        if (it != m_sessions.end()) {
            room_to_remove = it->second->currentRoom();
        }
    }

    if (!room_to_remove.empty()) {
        std::unique_lock<std::shared_mutex> rlock(m_roomsMutex);
        if (m_rooms.count(room_to_remove)) {
            m_rooms[room_to_remove].members.erase(fd);
        }
    }
    std::unique_lock<std::shared_mutex> lock(m_sessionsMutex);
    auto it = m_sessions.find(fd);
    if (it != m_sessions.end()) {
        if (it->second->isAuthenticated()) {
            m_nicknames.erase(it->second->nickname());
        }
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
        members = it->second.members;
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

std::shared_ptr<ClientSession> TcpServer::getSession(int fd) {
    std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
    auto it = m_sessions.find(fd);
    if (it == m_sessions.end()) return nullptr;
    return it->second;
}

int TcpServer::getFdByNickname(const std::string& nick) {
    std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
    auto it = m_nicknames.find(nick);
    if (it != m_nicknames.end()) return it->second;
    return -1;
}

std::vector<std::shared_ptr<ClientSession>> TcpServer::getSessionsInRoom(const std::string& room) {
    std::set<int> members;
    {
        std::shared_lock<std::shared_mutex> lock(m_roomsMutex);
        auto it = m_rooms.find(room);
        if (it != m_rooms.end()) members = it->second.members;
    }
    std::vector<std::shared_ptr<ClientSession>> result;
    std::shared_lock<std::shared_mutex> lock(m_sessionsMutex);
    for (int fd : members) {
        auto it = m_sessions.find(fd);
        if (it != m_sessions.end()) result.push_back(it->second);
    }
    return result;
}

std::vector<std::string> TcpServer::getUsersInRoom(const std::string& room) {
    auto sessions = getSessionsInRoom(room);
    std::vector<std::string> names;
    for (auto s : sessions) {
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
    return m_nicknames.find(nick) != m_nicknames.end();
}

bool TcpServer::isNicknameValid(const std::string& nick) {
    if (nick.empty() || (int)nick.size() > Constants::MAX_NICKNAME_LEN) return false;
    static const std::regex valid("^[a-zA-Z0-9_]{3,32}$");
    return std::regex_match(nick, valid);
}