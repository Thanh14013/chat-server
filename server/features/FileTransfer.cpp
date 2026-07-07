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

    if (sender->isMuted()){
        sender->sendPacket(Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "You have been muted!"));
        return;
    }

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
                                              "File size exceeds limit (Max: " + std::to_string(MAX_FILE_BYTES / (1024*1024)) + "MB)"));
        return;
    }

    if (!isAllowedExtension(filename)) {
        sender->sendPacket(Builder::makeError(ErrorCode::ERR_INTERNAL,
            "File type not supported"));
        return;
    }

    int receiverFd = m_server->getFdByNickname(toNick);
    auto receiver = m_server->getSession(receiverFd);
    if (!receiver) {
        sender->sendPacket(Builder::makeError(ErrorCode::ERR_ROOM_NOT_FOUND, "User not found in system: " + toNick));
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
        fs.last_activity_time = fs.start_time;
        fs.is_completed_by_sender = false;
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
    LOG_INFO("FileTransfer request: " + sender->nickname() + " -> " + toNick + " file=" + filename);
}

void FileTransfer::handleAccept(int receiverFd, const std::string& payloadJson){
    (void)receiverFd;
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

    j["filename"] = it->second.filename;
    std::string rs = j.dump();
    std::vector<uint8_t> payload(rs.begin(), rs.end());
    sender->sendPacket(Packet(MessageType::MSG_FILE_ACCEPT, payload));
    LOG_INFO("FileTransfer accepted: file=" + it->second.filename);
}

void FileTransfer::handleReject(int receiverFd, const std::string& payloadJson) {
    (void)receiverFd;
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
    LOG_INFO("FileTransfer rejected: file=" + it->second.filename);
}

void FileTransfer::handleData(int senderFd, const std::string& payloadJson) {
    if (!m_server) return;

    json j;
    try { j = json::parse(payloadJson); } catch (...) { return; }
    std::string tid  = j.value("transfer_id", "");


    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_transfers.find(tid);
    if (it == m_transfers.end()) return;
    if (it->second.sender_fd != senderFd) return;
    if (it->second.status != TransferStatus::ACCEPTED && it->second.status != TransferStatus::IN_PROGRESS) return;

    it->second.status = TransferStatus::IN_PROGRESS;
    it->second.last_activity_time = std::time(nullptr);

    auto receiver = m_server->getSession(it->second.receiver_fd);
    if (!receiver) {
        m_transfers.erase(it);
        return;
    }

    std::string rs = j.dump();
    std::vector<uint8_t> payload(rs.begin(), rs.end());
    receiver->sendPacket(Packet(MessageType::MSG_FILE_DATA, payload));
    LOG_INFO("FileTransfer data relayed: file=" + it->second.filename);
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

    it->second.is_completed_by_sender = true;
    it->second.last_activity_time = std::time(nullptr);

    auto receiver = m_server->getSession(it->second.receiver_fd);
    if (receiver) {
        std::string rs = j.dump();
        std::vector<uint8_t> payload(rs.begin(), rs.end());
        receiver->sendPacket(Packet(MessageType::MSG_FILE_COMPLETE, payload));
    }

    AUDIT_D(AuditEventType::FILE, "", "", "FILE_TRANSFER_" + std::string(ok ? "OK" : "FAIL"),
            ok ? AuditResult::SUCCESS : AuditResult::FAILURE, "",
            "tid=" + tid + " file=" + it->second.filename);

    LOG_INFO("FileTransfer complete: file=" + it->second.filename + " ok=" + (ok ? "yes" : "no"));
    // DO NOT erase here, wait for ACK from receiver
}

void FileTransfer::handleAck(int senderFd, const std::string& payloadJson) {
    if (!m_server) return;
    json j;
    try { j = json::parse(payloadJson); } catch (...) { return; }
    std::string tid = j.value("transfer_id", "");
    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_transfers.find(tid);
    if (it == m_transfers.end()) return;
    
    // SenderFd here is the receiver of the file sending the ACK
    if (it->second.receiver_fd != senderFd) return; 

    auto original_sender = m_server->getSession(it->second.sender_fd);
    if (original_sender) {
        std::vector<uint8_t> payload(payloadJson.begin(), payloadJson.end());
        original_sender->sendPacket(Packet(MessageType::MSG_FILE_ACK, payload));
    }
    LOG_INFO("FileTransfer ACKed by receiver: file=" + it->second.filename);
    m_transfers.erase(it);
}

void FileTransfer::cleanupExpired() {
    std::lock_guard<std::mutex> lk(m_mutex);
    time_t now = std::time(nullptr);
    for (auto it = m_transfers.begin(); it != m_transfers.end(); ) {
        if (it->second.status == TransferStatus::IN_PROGRESS) {
            if (!it->second.is_completed_by_sender) {
                if (std::difftime(now, it->second.last_activity_time) > 5) {
                    LOG_WARN("FileTransfer sender timeout: tid=" + it->first);
                    auto receiver = m_server->getSession(it->second.receiver_fd);
                    if (receiver) {
                        receiver->sendPacket(Builder::makeError(ErrorCode::ERR_INTERNAL, "File transfer failed because sender disconnected."));
                    }
                    it = m_transfers.erase(it);
                    continue;
                }
            } else {
                if (std::difftime(now, it->second.last_activity_time) > 5) {
                    LOG_WARN("FileTransfer receiver timeout: tid=" + it->first);
                    auto sender = m_server->getSession(it->second.sender_fd);
                    if (sender) {
                        sender->sendPacket(Builder::makeError(ErrorCode::ERR_INTERNAL, "File transfer failed because receiver disconnected, please try again later."));
                    }
                    it = m_transfers.erase(it);
                    continue;
                }
            }
        } else {
            // PENDING or ACCEPTED but not started
            if (std::difftime(now, it->second.start_time) > TIMEOUT_SEC) {
                LOG_WARN("FileTransfer expired: tid=" + it->first);
                it = m_transfers.erase(it);
                continue;
            }
        }
        ++it;
    }
}
