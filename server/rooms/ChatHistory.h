#pragma once
#include <string>
#include <deque>
#include <vector>
#include <mutex>
#include <ctime>
#include "../../common/Protocol.h"
#include "../../common/Constants.h"

enum class HistoryMsgType { CHAT, SYSTEM, FILE_NOTIFY};

struct HistoryEntry{
    time_t timestamp;
    std::string sender;
    std::string room;
    std::string message;
    HistoryMsgType msg_type {HistoryMsgType::CHAT};
};

class ChatHistory{
    public:
        explicit ChatHistory(const std::string& room);

        void append(const HistoryEntry& entry);
        std::vector<HistoryEntry> getRecent(int n = 50);
        Packet serializeForClient(const std::vector<HistoryEntry>& entries);
        void cleanupOldHistory();

        static std::string     typeToStr(HistoryMsgType t);
        static HistoryMsgType  strToType(const std::string& s);
    private:
        void persistEntry(const HistoryEntry& entry);
        std::vector<HistoryEntry> loadFromDb(int n);

        std::string              m_room;
        std::deque<HistoryEntry> m_buffer;
        std::mutex               m_mutex;
};