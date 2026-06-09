#include "ClientSession.h"
#include "TcpServer.h"
#include "../utils/Logger.h"
#include "../utils/Config.h"
#include "../protocol/Packet.h"
#include "../protocol/Builder.h"
#include "../protocol/Parser.h"
#include "../../common/Constants.h"
#include "../../common/MessageTypes.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

ClientSession::ClientSession(int fd, const std::string& ip, TcpServer* server)
    : m_fd(fd), m_ip(ip), m_nickname(""), m_room(""),
      m_authenticated(false), m_muted(false), m_muteUntil(0),
      m_role(UserRole::USER), m_msgCount(0), m_running(false),
      m_server(server)
{
    m_connectTime = std::time(nullptr);
    m_lastActive  = m_connectTime;
}

ClientSession::~ClientSession() {
    stop();
}

void ClientSession::start() {
    m_running = true;
    receiveLoop();
}

void ClientSession::stop() {
    m_running = false;
    if (m_fd >= 0) {
        ::shutdown(m_fd, SHUT_RDWR);
        ::close(m_fd);
        m_fd = -1;
    }
}

bool ClientSession::sendPacket(const Packet& pkt) {
    std::lock_guard<std::mutex> lock(m_sendMutex);
    if (m_fd < 0) return false;
    auto bytes = packetToBytes(pkt);
    ssize_t total = 0;
    ssize_t len   = static_cast<ssize_t>(bytes.size());
    while (total < len) {
        ssize_t n = ::send(m_fd, bytes.data() + total, len - total, MSG_NOSIGNAL);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

void ClientSession::disconnect(const std::string& reason) {
    if (!reason.empty()) {
        sendPacket(Builder::makeDisconnect(reason));
    }
    stop();
}

bool ClientSession::isTimedOut() const {
    int timeout = Config::instance().get().session_timeout_sec;
    return std::difftime(std::time(nullptr), m_lastActive) > timeout;
}

bool ClientSession::isMuted() const {
    if (!m_muted) return false;
    if (m_muteUntil == 0) return true;
    return std::time(nullptr) < m_muteUntil;
}

void ClientSession::receiveLoop() {
    while (m_running) {
        Packet pkt;
        if (!readPacketFromFd(m_fd, pkt)) {
            if (m_running) {
                LOG_INFO("Client disconnected: " + m_ip + " nick=" + m_nickname);
                m_server->onClientDisconnected(m_fd);
            }
            break;
        }

        m_lastActive = std::time(nullptr);
        m_server->onPacketReceived(m_fd, pkt);
    }
}
