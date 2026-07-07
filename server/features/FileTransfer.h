#pragma once
#include <string>
#include <map>
#include <mutex>
#include <ctime>
#include <cstdint>

enum class TransferStatus
{
    PENDING,
    ACCEPTED,
    IN_PROGRESS,
    COMPLETE,
    FAILED
};

struct FileTransferSession
{
    std::string transfer_id;
    int sender_fd;
    int receiver_fd;
    std::string filename;
    uint64_t file_size;
    std::string sha256_hash;
    std::string temp_path;
    time_t start_time;
    time_t last_activity_time;
    bool is_completed_by_sender;
    TransferStatus status;
};

class TcpServer;
class FileTransfer
{
public:
    static FileTransfer &instance();

    void initialize(TcpServer *server);

    void handleRequest(int senderFd, const std::string &payloadJson);
    void handleAccept(int receiverFd, const std::string &payloadJson);
    void handleReject(int receiverFd, const std::string &payloadJson);
    void handleData(int senderFd, const std::string &payloadJson);
    void handleComplete(int senderFd, const std::string &payloadJson);
    void handleAck(int senderFd, const std::string &payloadJson);

    void cleanupExpired();
private:
    FileTransfer() : m_server(nullptr) {};

    std::string generateTransferId();
    std::string sanitizeFilename(const std::string& filename);
    bool isAllowedExtension(const std::string& filename);
    std::string findReceiverFd(const std::string nickname);

    TcpServer* m_server;
    std::map<std::string, FileTransferSession> m_transfers;
    std::mutex m_mutex;

    static constexpr long long MAX_FILE_BYTES = 3LL * 1024 * 1024;
    static constexpr int       TIMEOUT_SEC    = 120;
};