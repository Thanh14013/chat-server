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
#include <nlohmann/json.hpp>
#include <sys/socket.h>

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

void ClientSession::start(){
    m_running = true;
}

void ClientSession::appendAndParseBytes(const uint8_t* data, size_t len) {
    m_readBuffer.insert(m_readBuffer.end(), data, data + len);

    size_t offset = 0;
        while (m_readBuffer.size() - offset >= sizeof(PacketHeader)) {
        PacketHeader hdr;
        std::memcpy(&hdr, m_readBuffer.data() + offset, sizeof(PacketHeader));
        if (hdr.magic[0] != Constants::MAGIC_BYTE_0 || 
            hdr.magic[1] != Constants::MAGIC_BYTE_1 || 
            hdr.version != Constants::PROTOCOL_VERSION) {
            LOG_ERROR("Malformed packet header. Closing connection fd=" + std::to_string(m_fd));
            disconnect();
            return;
        }

        if (hdr.payload_length > static_cast<uint32_t>(Constants::MAX_MESSAGE_LEN + 256)) {
            LOG_ERROR("Payload too large: " + std::to_string(hdr.payload_length) + ". Closing connection fd=" + std::to_string(m_fd));
            disconnect();
            return;
        }

        size_t totalPacketSize = sizeof(PacketHeader) + hdr.payload_length;
                if (m_readBuffer.size() - offset < totalPacketSize) {
            break;
        }
        const uint8_t* payloadStart = m_readBuffer.data() + offset + sizeof(PacketHeader);
        std::vector<uint8_t> payload(payloadStart, payloadStart + hdr.payload_length);
        if (hdr.checksum != computeCRC32(payload)) {
            LOG_ERROR("CRC32 checksum mismatch. Dropping corrupted packet.");
                offset += totalPacketSize;
            continue;
        }

        Packet pkt;
        pkt.header = hdr;
        pkt.payload = std::move(payload);
        m_server->onPacketReceived(m_fd, pkt);

        offset += totalPacketSize;
    }
    if (offset > 0) {
        m_readBuffer.erase(m_readBuffer.begin(), m_readBuffer.begin() + offset);
    }
}
void ClientSession::stop(){
    m_running = false;
    if (m_fd >=0){
        ::shutdown(m_fd, SHUT_RDWR);
        ::close(m_fd);
        m_fd = -1;
    }
}

bool ClientSession::sendPacket(const Packet& pkt){
    std::lock_guard<std::mutex> lock(m_sendMutex);
    if (m_fd < 0) return false;
    auto bytes = packetToBytes(pkt);
    ssize_t total=0;
    ssize_t len = static_cast<ssize_t>(bytes.size());
    while (total < len){
        ssize_t n = ::send(m_fd,bytes.data() + total, len - total, MSG_NOSIGNAL);
        if (n <=0) return false;
        total+=n;
    }
    return true;
}

void ClientSession::disconnect(const std::string& reason) {
    if (!reason.empty()) {
        sendPacket(Builder::makeDisconnect(reason));
    }
    m_server->onClientDisconnected(m_fd);
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