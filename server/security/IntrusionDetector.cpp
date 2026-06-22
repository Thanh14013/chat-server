#include "IntrusionDetector.h"
#include "AuditLogger.h"
#include "../utils/Logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>

using json = nlohmann::json;

IntrusionDetector& IntrusionDetector::instance() {
    static IntrusionDetector inst;
    return inst;
}

int IntrusionDetector::scoreForViolation(ViolationType type) {
    switch (type) {
        case ViolationType::FAILED_AUTH:        return 10;
        case ViolationType::RATE_LIMIT_EXCEEDED:return 5;
        case ViolationType::HMAC_FAILURE:       return 20;
        case ViolationType::REPLAY_ATTACK:      return 50;
        case ViolationType::INJECTION_ATTEMPT:  return 30;
        case ViolationType::HANDSHAKE_FAIL:     return 15;
        case ViolationType::INVALID_PACKET:     return 10;
        case ViolationType::PORT_SCAN:          return 100;
        default:                                return 5;
    }
}

std::string IntrusionDetector::violationToStr(ViolationType type) {
    switch (type) {
        case ViolationType::FAILED_AUTH:        return "FAILED_AUTH";
        case ViolationType::RATE_LIMIT_EXCEEDED:return "RATE_LIMIT_EXCEEDED";
        case ViolationType::HMAC_FAILURE:       return "HMAC_FAILURE";
        case ViolationType::REPLAY_ATTACK:      return "REPLAY_ATTACK";
        case ViolationType::INJECTION_ATTEMPT:  return "INJECTION_ATTEMPT";
        case ViolationType::HANDSHAKE_FAIL:     return "HANDSHAKE_FAIL";
        case ViolationType::INVALID_PACKET:     return "INVALID_PACKET";
        case ViolationType::PORT_SCAN:          return "PORT_SCAN";
        default:                                return "UNKNOWN";
    }
}

IPStatus IntrusionDetector::checkIP(const std::string& ip) {
    std::lock_guard<std::mutex> lk(m_mutex);

    if (m_whitelist.count(ip))  return IPStatus::WHITELISTED;
    if (m_permBans.count(ip))   return IPStatus::BLOCKED;

    auto tit = m_tempBans.find(ip);
    if (tit != m_tempBans.end()) {
        if (std::time(nullptr) < tit->second) return IPStatus::BLOCKED;
        m_tempBans.erase(tit);
    }

    auto& rec = m_records[ip];
    if (rec.ip.empty()) {
        rec.ip         = ip;
        rec.first_seen = std::time(nullptr);
    }
    rec.connection_count++;

    return IPStatus::ALLOWED;
}

void IntrusionDetector::reportViolation(const std::string& ip,
                                         ViolationType type, int fd) {
    if (ip.empty() && fd < 0) return;

    std::lock_guard<std::mutex> lk(m_mutex);

    std::string target_ip = ip;

    auto& rec = m_records[target_ip];
    if (rec.ip.empty()) {
        rec.ip         = target_ip;
        rec.first_seen = std::time(nullptr);
    }

    int score = scoreForViolation(type);
    rec.threat_score += score;
    rec.violations.push_back({ std::time(nullptr), type });

    if ((int)rec.violations.size() > 200) rec.violations.erase(rec.violations.begin());

    LOG_WARN("IDS violation: ip=" + target_ip
             + " type=" + violationToStr(type)
             + " score=" + std::to_string(rec.threat_score));

    AUDIT_D(AuditEventType::SECURITY, target_ip, "",
            "VIOLATION_" + violationToStr(type),
            AuditResult::BLOCKED, target_ip,
            "score=" + std::to_string(rec.threat_score));

    checkThresholds(rec);
}

void IntrusionDetector::checkThresholds(IPRecord& rec) {
    if (rec.threat_score >= PERM_BAN_THRESHOLD) {
        if (!m_permBans.count(rec.ip)) {
            m_permBans.insert(rec.ip);
            LOG_CRITICAL("IDS PERM BAN: " + rec.ip
                         + " score=" + std::to_string(rec.threat_score));
            AuditLogger::instance().log(
                AuditEventType::SECURITY, rec.ip, "", "PERM_BAN",
                AuditResult::BLOCKED, rec.ip,
                "score=" + std::to_string(rec.threat_score));
            exportBanList();
        }
        return;
    }

    if (rec.threat_score >= ATTACK_THRESHOLD) {
        if (!m_tempBans.count(rec.ip)) {
            m_tempBans[rec.ip] = std::time(nullptr) + 86400;
            rec.temp_ban_count++;
            LOG_WARN("IDS TEMP BAN 24h: " + rec.ip);
        }
    } else if (rec.threat_score >= THREAT_THRESHOLD) {
        if (!m_tempBans.count(rec.ip)) {
            m_tempBans[rec.ip] = std::time(nullptr) + 3600;
            rec.temp_ban_count++;
            LOG_WARN("IDS TEMP BAN 1h: " + rec.ip);
        }
    }

    if (rec.temp_ban_count >= MAX_TEMP_BANS && !m_permBans.count(rec.ip)) {
        m_permBans.insert(rec.ip);
        LOG_CRITICAL("IDS ESCALATE TO PERM BAN: " + rec.ip);
        exportBanList();
    }
}

void IntrusionDetector::tempBan(const std::string& ip, int durationSec,
                                  const std::string& reason) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_tempBans[ip] = std::time(nullptr) + durationSec;
    LOG_WARN("Manual temp ban: " + ip + " duration=" + std::to_string(durationSec)
             + " reason=" + reason);
}

void IntrusionDetector::permBan(const std::string& ip, const std::string& reason) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_permBans.insert(ip);
    LOG_WARN("Manual perm ban: " + ip + " reason=" + reason);
    exportBanList();
}

void IntrusionDetector::permBanNick(const std::string& nick, const std::string& reason) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_bannedNicks.insert(nick);
    LOG_WARN("Manual perm ban for Nickname: " + nick + " reason=" + reason);
    exportBanList();
}

void IntrusionDetector::unban(const std::string& ip) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_permBans.erase(ip);
    m_tempBans.erase(ip);
    auto it = m_records.find(ip);
    if (it != m_records.end()) {
        it->second.threat_score = 0;
        it->second.temp_ban_count = 0;
    }
    LOG_INFO("IDS unban IP: " + ip);
}

void IntrusionDetector::unbanNick(const std::string& nick) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_bannedNicks.erase(nick);
    LOG_INFO("IDS unban Nickname: " + nick);
    exportBanList();
}

bool IntrusionDetector::isBannedNick(const std::string& nick) {
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_bannedNicks.count(nick) > 0;
}

void IntrusionDetector::addWhitelist(const std::string& ip) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_whitelist.insert(ip);
    LOG_INFO("Whitelist added: " + ip);
}

void IntrusionDetector::decayScores() {
    std::lock_guard<std::mutex> lk(m_mutex);
    for (auto& [ip, rec] : m_records) {
        if (rec.threat_score > 0) {
            rec.threat_score = std::max(0, (int)(rec.threat_score * 0.9));
        }
    }

    time_t now = std::time(nullptr);
    for (auto it = m_tempBans.begin(); it != m_tempBans.end(); ) {
        if (now >= it->second) it = m_tempBans.erase(it);
        else ++it;
    }
}

void IntrusionDetector::exportBanList(const std::string& path) {
    json banned = json::array();
    for (auto& ip : m_permBans) {
        json e; e["ip"] = ip; e["type"] = "PERMANENT";
        e["ts"] = (long long)std::time(nullptr);
        banned.push_back(e);
    }
    for (auto& [ip, until] : m_tempBans) {
        json e; e["ip"] = ip; e["type"] = "TEMPORARY";
        e["until"] = (long long)until;
        banned.push_back(e);
    }
    for (auto& nick : m_bannedNicks) {
        json e; e["nick"] = nick; e["type"] = "NICKNAME";
        e["ts"] = (long long)std::time(nullptr);
        banned.push_back(e);
    }
    std::ofstream ofs(path);
    if (ofs.is_open()) ofs << banned.dump(2);
}

void IntrusionDetector::loadBanList(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) return;
    json j;
    try { ifs >> j; } catch (...) { return; }

    std::lock_guard<std::mutex> lk(m_mutex);
    for (auto& entry : j) {
        std::string ip   = entry.value("ip", "");
        std::string type = entry.value("type", "");
        if (type == "PERMANENT" && !ip.empty()) m_permBans.insert(ip);
        else if (type == "TEMPORARY" && !ip.empty()) {
            time_t until = (time_t)entry.value("until", (long long)0);
            if (until > std::time(nullptr)) m_tempBans[ip] = until;
        }
        else if (type == "NICKNAME") {
            std::string nick = entry.value("nick", "");
            if (!nick.empty()) m_bannedNicks.insert(nick);
        }
    }
    LOG_INFO("Ban list loaded: " + std::to_string(m_permBans.size()) + " IP bans, " + std::to_string(m_bannedNicks.size()) + " Nick bans.");
}

std::string IntrusionDetector::exportCEF(const std::string& ip,
                                           ViolationType type, int severity) {
    std::ostringstream oss;
    oss << "CEF:0|VCS|SecureChat|1.0"
        << "|" << violationToStr(type)
        << "|" << violationToStr(type)
        << "|" << severity
        << "|src=" << ip
        << " cs1=" << violationToStr(type)
        << " cs1Label=ViolationType"
        << " rt=" << (long long)std::time(nullptr);
    return oss.str();
}
