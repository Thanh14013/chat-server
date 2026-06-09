#pragma once
#include <string>
#include <deque>
#include <mutex>
#include <ctime>

enum class AuditEventType {
    AUTH, CONNECT, DISCONNECT, MESSAGE, FILE, ADMIN, SECURITY
};

enum class AuditResult {
    SUCCESS, FAILURE, BLOCKED
};

struct AuditEvent {
    std::string    event_id;
    time_t         timestamp;
    AuditEventType event_type;
    std::string    actor;
    std::string    target;
    std::string    action;
    AuditResult    result;
    std::string    ip_address;
    std::string    details;
    std::string    prev_hash;
    std::string    hash;
};

class AuditLogger {
public:
    static AuditLogger& instance();

    void log(AuditEventType type, const std::string& actor, const std::string& target,
             const std::string& action, AuditResult result,
             const std::string& ip = "", const std::string& details = "");

    void flush();
    bool verifyChain();
    bool exportToCSV(const std::string& filepath);

private:
    AuditLogger();

    std::string generateUUID();
    std::string computeHash(const AuditEvent& e);
    std::string typeToStr(AuditEventType t);
    std::string resultToStr(AuditResult r);
    void        persistEvent(const AuditEvent& e);

    std::string            m_prevHash;
    std::deque<AuditEvent> m_buffer;
    std::mutex             m_mutex;
};

#define AUDIT(type, actor, target, action, result) \
    AuditLogger::instance().log(type, actor, target, action, result)

#define AUDIT_D(type, actor, target, action, result, ip, details) \
    AuditLogger::instance().log(type, actor, target, action, result, ip, details)
