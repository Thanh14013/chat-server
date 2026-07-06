#include "ChatHistory.h"
#include "../utils/Database.h"
#include "../utils/Logger.h"
#include "../../common/MessageTypes.h"
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <algorithm>

using json = nlohmann::json;

ChatHistory::ChatHistory(const std::string& room) : m_room(room) {}

std::string ChatHistory::typeToStr(HistoryMsgType t) {
    switch (t) {
        case HistoryMsgType::SYSTEM:      return "SYSTEM";
        case HistoryMsgType::FILE_NOTIFY: return "FILE_NOTIFY";
        default:                          return "CHAT";
    }
}

HistoryMsgType ChatHistory::strToType(const std::string& s) {
    if (s == "SYSTEM")      return HistoryMsgType::SYSTEM;
    if (s == "FILE_NOTIFY") return HistoryMsgType::FILE_NOTIFY;
    return HistoryMsgType::CHAT;
}

void ChatHistory::append(const HistoryEntry& entry) {
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_buffer.push_back(entry);
        while ((int)m_buffer.size() > Constants::HISTORY_BUFFER_SIZE)
            m_buffer.pop_front();
    }
    persistEntry(entry);
}

void ChatHistory::persistEntry(const HistoryEntry& entry) {
    if (!Database::instance().isOpen()) return;
    sqlite3* db = Database::instance().handle();

    const char* sql =
        "INSERT INTO ChatHistory (timestamp, sender, room, message, msg_type) "
        "VALUES (?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)entry.timestamp);
    sqlite3_bind_text (stmt, 2, entry.sender.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 3, entry.room.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 4, entry.message.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 5, typeToStr(entry.msg_type).c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<HistoryEntry> ChatHistory::loadFromDb(int n) {
    std::vector<HistoryEntry> result;
    if (!Database::instance().isOpen()) return result;

    sqlite3*    db  = Database::instance().handle();
    const char* sql =
        "SELECT timestamp, sender, room, message, msg_type "
        "FROM ChatHistory WHERE room = ? ORDER BY timestamp DESC LIMIT ?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return result;

    sqlite3_bind_text(stmt, 1, m_room.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 2, n);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        HistoryEntry e;
        e.timestamp = (time_t)sqlite3_column_int64(stmt, 0);
        e.sender    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        e.room      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        e.message   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        e.msg_type  = strToType(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4)));
        result.push_back(e);
    }
    sqlite3_finalize(stmt);
    std::reverse(result.begin(), result.end());
    return result;
}

std::vector<HistoryEntry> ChatHistory::getRecent(int n) {
    std::lock_guard<std::mutex> lk(m_mutex);
    if ((int)m_buffer.size() >= n) {
        return std::vector<HistoryEntry>(m_buffer.end() - n, m_buffer.end());
    }
    return loadFromDb(n);
}

Packet ChatHistory::serializeForClient(const std::vector<HistoryEntry>& entries) {
    json arr = json::array();
    for (auto& e : entries) {
        json item;
        item["ts"]      = (long long)e.timestamp;
        item["sender"]  = e.sender;
        item["room"]    = e.room;
        item["message"] = e.message;
        item["type"]    = typeToStr(e.msg_type);
        arr.push_back(item);
    }
    std::string s = arr.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    return Packet(MessageType::MSG_CHAT_BROADCAST, payload);
}

void ChatHistory::cleanupOldHistory() {
    if (!Database::instance().isOpen()) return;
    time_t      cutoff = std::time(nullptr) - (30LL * 24 * 3600);
    sqlite3*    db     = Database::instance().handle();
    const char* sql    = "DELETE FROM ChatHistory WHERE room=? AND timestamp<?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_text (stmt, 1, m_room.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)cutoff);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    LOG_INFO("ChatHistory cleanup: room=" + m_room);
}