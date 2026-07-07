#pragma once
#include <cstddef>
#include "../commands/CommandHandler.h"
#include "../commands/CommandParser.h"
#include "../../common/Protocol.h"
#include <thread>
#include <atomic>
#include <map>
#include <mutex>
#include <fstream>
#include <nlohmann/json.hpp>
#include <condition_variable>

class TcpClient;

class ConnectionManager
{
public:
    explicit ConnectionManager(TcpClient *client);
    ~ConnectionManager();

    void run();
    void stop();

    void registerUpload(const std::string &filename, const std::string &filepath);
    std::string getLastIncomingTransferId() const { return m_lastIncomingTransferId; }
    std::string getIncomingFileName(const std::string& tid) const {
        std::lock_guard<std::mutex> lock(m_fileMutex);
        auto it = m_activeDownloads.find(tid);
        if (it != m_activeDownloads.end()) {
            return it->second.filename;
        }
        return "";
    }
    std::string getTransferIdBySender(const std::string& sender) const {
        std::lock_guard<std::mutex> lock(m_fileMutex);
        for (const auto& pair : m_activeDownloads) {
            if (pair.second.sender == sender) {
                return pair.first; // return TID
            }
        }
        return "";
    }

private:
    void onPacketReceived(const Packet &pkt);
    void onHandshakeDone(bool success);

    void handleFileRequest(const nlohmann::json &j);
    void handleFileAccept(const nlohmann::json &j);
    void handleFileData(const nlohmann::json &j);
    void handleFileComplete(const nlohmann::json &j);
    void uploadWorker(std::string transferId, std::string filepath);

    TcpClient *m_client;
    CommandHandler m_cmdHandler;
    CommandParser m_cmdParser;

    std::string m_nickname;

    std::atomic<bool> m_running;
    
    enum class AuthState {
        PENDING_HANDSHAKE,
        HANDSHAKE_FAILED,
        PENDING_AUTH,
        REJECTED,
        AUTHENTICATED
    };
    std::atomic<AuthState> m_authState{AuthState::PENDING_HANDSHAKE};
    std::condition_variable m_authCv;
    std::mutex m_authMutex;
    mutable std::mutex m_fileMutex;
    std::map<std::string, std::string> m_pendingUploads; // filename -> filepath
    std::map<std::string, std::string> m_incomingTransfersMap; // filename -> transfer_id

    struct DownloadState
    {
        std::string filename;
        std::string sender;
        uint64_t expectedSize = 0;
        uint64_t receivedSize = 0;
        std::string expectedHash;
        std::string localFilepath;
        bool isFirstChunk = true;
    };
    std::map<std::string, DownloadState> m_activeDownloads; // transfer_id -> state

    std::string m_lastIncomingTransferId;
};