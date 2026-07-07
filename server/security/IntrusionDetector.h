#pragma once
#include <string>
#include <unordered_map>
#include <map>
#include <set>
#include <vector>
#include <mutex>
#include <ctime>

enum class ThreatLevel { CLEAN = 0, SUSPICIOUS = 1, THREAT = 2, ATTACK = 3 };

enum class ViolationType {
    FAILED_AUTH,
    RATE_LIMIT_EXCEEDED,
    HMAC_FAILURE,
    REPLAY_ATTACK,
    INJECTION_ATTEMPT,
    HANDSHAKE_FAIL,
    INVALID_PACKET,
    PORT_SCAN
};

struct Violation {
    time_t        timestamp;
    ViolationType type;
};

struct IPRecord {
    std::string           ip;
    int                   threat_score;
    std::vector<Violation>violations;
    time_t                ban_until;
    time_t                first_seen;
    int                   connection_count;
    int                   temp_ban_count;
};

enum class IPStatus { ALLOWED, BLOCKED, WHITELISTED };

class IntrusionDetector {
public:
    static IntrusionDetector& instance();

    IPStatus checkIP(const std::string& ip);

    void reportViolation(const std::string& ip, ViolationType type,
                         int fd = -1);

    void tempBan(const std::string& ip, int durationSec, const std::string& reason);
    void permBan(const std::string& ip, const std::string& reason = "Manual ban");
    void permBanNick(const std::string& nick, const std::string& reason = "Manual ban");
    void permBanUser(const std::string& ip, const std::string& nick, const std::string& reason = "Manual ban");
    void unban(const std::string& ip);
    void unbanNick(const std::string& nick);
    void unbanUser(const std::string& ipOrNick);
    bool isBannedNick(const std::string& nick);

    void addWhitelist(const std::string& ip);
    void decayScores();
    void exportBanList(const std::string& path = "ban_list.json");
    void loadBanList(const std::string& path = "ban_list.json");
    void loadBansFromDB();

    std::string exportCEF(const std::string& ip, ViolationType type, int severity);

    static int scoreForViolation(ViolationType type);

private:
    IntrusionDetector() = default;

    std::set<std::string> m_bannedNicks;

    void checkThresholds(IPRecord& rec);
    std::string violationToStr(ViolationType type);

    std::unordered_map<std::string, IPRecord> m_records;
    std::set<std::string>                     m_permBans;
    std::map<std::string, time_t>             m_tempBans;
    std::set<std::string>                     m_whitelist;
    mutable std::mutex                        m_mutex;

    static constexpr int SUSPICIOUS_THRESHOLD = 50;
    static constexpr int THREAT_THRESHOLD     = 100;
    static constexpr int ATTACK_THRESHOLD     = 200;
    static constexpr int PERM_BAN_THRESHOLD   = 500;
    static constexpr int MAX_TEMP_BANS        = 3;
};
