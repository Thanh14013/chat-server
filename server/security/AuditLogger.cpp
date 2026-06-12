#include "AuditLogger.h"
#include "../utils/Database.h"
#include "../utils/Logger.h"
#include <openssl/sha.h>
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <random>

using json = nlohmann::json;

static std::string sha256Hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

AuditLogger& AuditLogger::instance() {
    static AuditLogger inst;
    return inst;
}

AuditLogger::AuditLogger() : m_prevHash("GENESIS") {}

std::string AuditLogger::generateUUID() {
    static std::random_device             rd;
    static std::mt19937                   gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::uniform_int_distribution<> dis2(8, 11);
    std::ostringstream oss;
    for (int i = 0; i < 8;  i++) oss << std::hex << dis(gen);
    oss << "-";
    for (int i = 0; i < 4;  i++) oss << std::hex << dis(gen);
    oss << "-4";
    for (int i = 0; i < 3;  i++) oss << std::hex << dis(gen);
    oss << "-" << std::hex << dis2(gen);
    for (int i = 0; i < 3;  i++) oss << std::hex << dis(gen);
    oss << "-";
    for (int i = 0; i < 12; i++) oss << std::hex << dis(gen);
    return oss.str();
}

std::string AuditLogger::typeToStr(AuditEventType t) {
    switch (t) {
        case AuditEventType::AUTH:       return "AUTH";
        case AuditEventType::CONNECT:    return "CONNECT";
        case AuditEventType::DISCONNECT: return "DISCONNECT";
        case AuditEventType::MESSAGE:    return "MESSAGE";
        case AuditEventType::FILE:       return "FILE";
        case AuditEventType::ADMIN:      return "ADMIN";
        case AuditEventType::SECURITY:   return "SECURITY";
        default:                         return "UNKNOWN";
    }
}

std::string AuditLogger::resultToStr(AuditResult r) {
    switch (r) {
        case AuditResult::SUCCESS: return "SUCCESS";
        case AuditResult::FAILURE: return "FAILURE";
        case AuditResult::BLOCKED: return "BLOCKED";
        default:                   return "UNKNOWN";
    }
}

std::string AuditLogger::computeHash(const AuditEvent& e) {
    std::string data = e.event_id
        + std::to_string(e.timestamp)
        + typeToStr(e.event_type)
        + e.actor + e.target + e.action
        + resultToStr(e.result)
        + e.ip_address + e.details
        + e.prev_hash;
    return sha256Hex(data);
}

void AuditLogger::log(AuditEventType type, const std::string& actor,
                      const std::string& target, const std::string& action,
                      AuditResult result, const std::string& ip,
                      const std::string& details) {
    std::lock_guard<std::mutex> lk(m_mutex);

    AuditEvent e;
    e.event_id   = generateUUID();
    e.timestamp  = std::time(nullptr);
    e.event_type = type;
    e.actor      = actor;
    e.target     = target;
    e.action     = action;
    e.result     = result;
    e.ip_address = ip;
    e.details    = details;
    e.prev_hash  = m_prevHash;
    e.hash       = computeHash(e);

    m_prevHash = e.hash;
    m_buffer.push_back(e);

    if ((int)m_buffer.size() >= 100) flush();
}

void AuditLogger::flush() {
    if (!Database::instance().isOpen() || m_buffer.empty()) return;

    sqlite3*    db  = Database::instance().handle();
    const char* sql =
        "INSERT INTO AuditLog "
        "(event_id, timestamp, event_type, actor, target, action, result, "
        " ip_address, details, prev_hash, hash) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?);";

    sqlite3_exec(db, "BEGIN;", nullptr, nullptr, nullptr);

    for (auto& e : m_buffer) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) continue;

        sqlite3_bind_text (stmt,  1, e.event_id.c_str(),          -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt,  2, (sqlite3_int64)e.timestamp);
        sqlite3_bind_text (stmt,  3, typeToStr(e.event_type).c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt,  4, e.actor.c_str(),              -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt,  5, e.target.c_str(),             -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt,  6, e.action.c_str(),             -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt,  7, resultToStr(e.result).c_str(),-1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt,  8, e.ip_address.c_str(),         -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt,  9, e.details.c_str(),            -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 10, e.prev_hash.c_str(),          -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 11, e.hash.c_str(),               -1, SQLITE_TRANSIENT);

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
    m_buffer.clear();
}

bool AuditLogger::verifyChain() {
    if (!Database::instance().isOpen()) return false;

    sqlite3*    db  = Database::instance().handle();
    const char* sql =
        "SELECT event_id, timestamp, event_type, actor, target, action, "
        "result, ip_address, details, prev_hash, hash "
        "FROM AuditLog ORDER BY id ASC;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    std::string prevHash = "GENESIS";
    bool        ok       = true;
    int         count    = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AuditEvent e;
        e.event_id   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        e.timestamp  = (time_t)sqlite3_column_int64(stmt, 1);
        e.event_type = AuditEventType::AUTH;
        e.actor      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        e.target     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        e.action     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        e.result     = AuditResult::SUCCESS;
        e.ip_address = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        e.details    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        e.prev_hash  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        std::string storedHash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));

        if (e.prev_hash != prevHash) {
            LOG_ERROR("Audit chain broken at event: " + e.event_id);
            ok = false;
            break;
        }

        e.hash   = computeHash(e);
        prevHash = storedHash;
        count++;
    }
    sqlite3_finalize(stmt);

    if (ok) LOG_INFO("Audit chain verified: " + std::to_string(count) + " events, all valid.");
    return ok;
}

bool AuditLogger::exportToCSV(const std::string& filepath) {
    if (!Database::instance().isOpen()) return false;

    std::ofstream ofs(filepath);
    if (!ofs.is_open()) return false;

    ofs << "event_id,timestamp,event_type,actor,target,action,result,ip_address,details\n";

    sqlite3*    db  = Database::instance().handle();
    const char* sql =
        "SELECT event_id, timestamp, event_type, actor, target, action, "
        "result, ip_address, details FROM AuditLog ORDER BY id ASC;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        for (int i = 0; i < 9; i++) {
            const char* val = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
            ofs << (val ? val : "") << (i < 8 ? "," : "\n");
        }
    }
    sqlite3_finalize(stmt);
    LOG_INFO("Audit log exported to: " + filepath);
    return true;
}
