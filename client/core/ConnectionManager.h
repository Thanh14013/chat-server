#pragma once
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
    std::mutex m_fileMutex;
    std::map<std::string, std::string> m_pendingUploads; // filename -> filepath

    struct DownloadState
    {
        std::string filename;
        uint64_t expectedSize = 0;
        uint64_t receivedSize = 0;
        std::string expectedHash;
    };
    std::map<std::string, DownloadState> m_activeDownloads; // transfer_id -> state
};