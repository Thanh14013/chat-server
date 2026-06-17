#include "FileTransfer.h"
#include "../core/TcpServer.h"
#include "../core/ClientSession.h"
#include "../protocol/Builder.h"
#include "../security/AuditLogger.h"
#include "../utils/Logger.h"
#include "../../common/MessageTypes.h"
#include "../../common/ErrorCodes.h"
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <algorithm>
#include <cstdio>
#include <sys/stat.h>

using json = nlohmann::json;

FileTransfer& FileTransfer::instance() {
    static FileTransfer inst;
    return inst;
}

void FileTransfer::initialize(TcpServer* server) {
    m_server = server;
}

std::string FileTransfer::generateTransferId() {
    static std::mt19937 gen(std::random_device{}());
    static std::uniform_int_distribution<> dis(0, 15);
    std::ostringstream oss;
    for (int i = 0; i < 16; i++) oss << std::hex << dis(gen);
    return oss.str();
}

std::string FileTransfer::sanitizeFilename(const std::string& name) {
    std::string result;
    for (char c : name) {
        if (c == '/' || c == '\\' || c == '.' && result.empty()) continue;
        if (c == '\0') continue;
        result += c;
    }
    if (result.empty()) result = "file";
    if (result.size() > 128) result = result.substr(0, 128);
    return result;
}

bool FileTransfer::isAllowedExtension(const std::string& filename) {
    static const std::vector<std::string> allowed = {
        ".txt", ".pdf", ".png", ".jpg", ".jpeg",
        ".zip", ".cpp", ".h", ".md", ".log"
    };
    auto pos = filename.rfind('.');
    if (pos == std::string::npos) return false;
    std::string ext = filename.substr(pos);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    for (auto& a : allowed)
        if (ext == a) return true;
    return false;
}

void FileTransfer::handleRequest(int senderFd, const std::string& payloadJson){
    if (!m_server) return;
    auto sender = m_server->getSession(senderFd);
    if (!sender) return;

    json j;
    try { j = json::parse(payloadJson); } catch (...) { return; }

    std::string toNick   = j.value("to", "");
    std::string filename = sanitizeFilename(j.value("filename", ""));
    uint64_t    fileSize = j.value("size", (uint64_t)0);
    std::string sha256   = j.value("sha256", "");

    if (toNick.empty() || filename.empty() || fileSize == 0) {
        sender->sendPacket(Builder::makeError(ErrorCode::ERR_INTERNAL, "Invalid file request"));
        return;
    }

    if ((long long)fileSize > MAX_FILE_BYTES) {
        sender->sendPacket(Builder::makeError(ErrorCode::ERR_FILE_TOO_LARGE,
            "File exceeds 3MB limit"));
        return;
    }

    if (!isAllowedExtension(filename)) {
        sender->sendPacket(Builder::makeError(ErrorCode::ERR_INTERNAL,
            "File type not allowed"));
        return;
    }

    int receiverFd = m_server->getFdByNickname(toNick);
    auto receiver = m_server->getSession(receiverFd);
    if (!receiver) {
        sender->sendPacket(Builder::makeError(ErrorCode::ERR_ROOM_NOT_FOUND, "User not found: " + toNick));
        return;
    }

    std::string tid = generateTransferId();

    {
        std::lock_guard<std::mutex> lk(m_mutex);
        FileTransferSession fs;
        fs.transfer_id = tid;
        fs.sender_fd   = senderFd;
        fs.receiver_fd = receiver->fd();
        fs.filename    = filename;
        fs.file_size   = fileSize;
        fs.sha256_hash = sha256;
        fs.temp_path   = "/tmp/vcs_" + tid;
        fs.start_time  = std::time(nullptr);
        fs.status      = TransferStatus::PENDING;
        m_transfers[tid] = fs;
    }

    json relay;
    relay["transfer_id"] = tid;
    relay["from"]        = sender->nickname();
    relay["filename"]    = filename;
    relay["size"]        = fileSize;
    relay["sha256"]      = sha256;
    std::string rs = relay.dump();
    std::vector<uint8_t> payload(rs.begin(), rs.end());
    receiver->sendPacket(Packet(MessageType::MSG_FILE_REQUEST, payload));

    AUDIT_D(AuditEventType::FILE, sender->nickname(), toNick, "FILE_REQUEST",AuditResult::SUCCESS, sender->ip(),"file=" + filename + " size=" + std::to_string(fileSize));
    LOG_INFO("FileTransfer request: " + sender->nickname() + " -> " + toNick + " file=" + filename + " tid=" + tid);
}

void FileTransfer::handleAccept(int receiverFd, const std::string& payloadJson){
    if (!m_server) return;

    json j;
    try { j = json::parse(payloadJson); } catch (...) { return; }
    std::string tid = j.value("transfer_id", "");

    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_transfers.find(tid);
    if (it == m_transfers.end()) return;

    it->second.status = TransferStatus::ACCEPTED;

    auto sender = m_server->getSession(it->second.sender_fd);
    if (!sender) return;

    std::string rs = j.dump();
    std::vector<uint8_t> payload(rs.begin(), rs.end());
    sender->sendPacket(Packet(MessageType::MSG_FILE_ACCEPT, payload));
    LOG_INFO("FileTransfer accepted: tid=" + tid);
}

void FileTransfer::handleReject(int receiverFd, const std::string& payloadJson) {
    if (!m_server) return;

    json j;
    try { j = json::parse(payloadJson); } catch (...) { return; }
    std::string tid = j.value("transfer_id", "");

    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_transfers.find(tid);
    if (it == m_transfers.end()) return;

    auto sender = m_server->getSession(it->second.sender_fd);
    if (sender) {
        std::string rs = j.dump();
        std::vector<uint8_t> payload(rs.begin(), rs.end());
        sender->sendPacket(Packet(MessageType::MSG_FILE_REJECT, payload));
    }

    m_transfers.erase(it);
    LOG_INFO("FileTransfer rejected: tid=" + tid);
}

void FileTransfer::handleData(int senderFd, const std::string& payloadJson) {
    if (!m_server) return;

    json j;
    try { j = json::parse(payloadJson); } catch (...) { return; }
    std::string tid  = j.value("transfer_id", "");
    std::string data = j.value("data", "");

    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_transfers.find(tid);
    if (it == m_transfers.end()) return;
    if (it->second.sender_fd != senderFd) return;
    if (it->second.status != TransferStatus::ACCEPTED) return;

    it->second.status = TransferStatus::IN_PROGRESS;

    auto receiver = m_server->getSession(it->second.receiver_fd);
    if (!receiver) {
        m_transfers.erase(it);
        return;
    }

    std::string rs = j.dump();
    std::vector<uint8_t> payload(rs.begin(), rs.end());
    receiver->sendPacket(Packet(MessageType::MSG_FILE_DATA, payload));
    LOG_INFO("FileTransfer data relayed: tid=" + tid);
}

void FileTransfer::handleComplete(int senderFd, const std::string& payloadJson) {
    if (!m_server) return;

    json j;
    try { j = json::parse(payloadJson); } catch (...) { return; }
    std::string tid    = j.value("transfer_id", "");
    bool        ok     = j.value("ok", false);

    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_transfers.find(tid);
    if (it == m_transfers.end()) return;
    if (it->second.sender_fd != senderFd) return; // SECURITY CHECK

    auto receiver = m_server->getSession(it->second.receiver_fd);
    if (receiver) {
        std::string rs = j.dump();
        std::vector<uint8_t> payload(rs.begin(), rs.end());
        receiver->sendPacket(Packet(MessageType::MSG_FILE_COMPLETE, payload));
    }

    AUDIT_D(AuditEventType::FILE, "", "", "FILE_TRANSFER_" + std::string(ok ? "OK" : "FAIL"),
            ok ? AuditResult::SUCCESS : AuditResult::FAILURE, "",
            "tid=" + tid + " file=" + it->second.filename);

    LOG_INFO("FileTransfer complete: tid=" + tid + " ok=" + (ok ? "yes" : "no"));
    m_transfers.erase(it);
}

void FileTransfer::cleanupExpired() {
    std::lock_guard<std::mutex> lk(m_mutex);
    time_t now = std::time(nullptr);
    for (auto it = m_transfers.begin(); it != m_transfers.end(); ) {
        if (std::difftime(now, it->second.start_time) > TIMEOUT_SEC) {
            LOG_WARN("FileTransfer expired: tid=" + it->first);
            it = m_transfers.erase(it);
        } else {
            ++it;
        }
    }
}
