#include "MessageFilter.h"
#include "../utils/Logger.h"
#include "../security/AuditLogger.h"
#include "../../common/Constants.h"
#include <regex>
#include <algorithm>

MessageFilter& MessageFilter::instance() {
    static MessageFilter inst;
    return inst;
}

bool MessageFilter::containsNullByte(const std::string& msg) {
    return msg.find('\0') != std::string::npos;
}

bool MessageFilter::containsInjection(const std::string& msg) {
    std::string upper = msg;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

    static const std::vector<std::string> patterns = {
        "DROP TABLE", "DROP DATABASE",
        "SELECT * FROM", "SELECT COUNT(",
        "INSERT INTO", "UPDATE SET",
        "DELETE FROM", "UNION SELECT",
        "--", "'; ", "\"; ",
        "<SCRIPT", "</SCRIPT>", "JAVASCRIPT:",
        "EVAL(", "EXEC(",
        "../", "..\\",
        "/ETC/PASSWD", "/ETC/SHADOW"
    };

    for (auto& p : patterns) {
        if (upper.find(p) != std::string::npos) return true;
    }
    return false;
}

void MessageFilter::logUrl(const std::string& msg, const std::string& nick) {
    static const std::regex urlRe(
        R"((https?://[^\s]+))",
        std::regex::icase);

    auto begin = std::sregex_iterator(msg.begin(), msg.end(), urlRe);
    auto end   = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        LOG_INFO("URL in message from " + nick + ": " + (*it)[0].str());
    }
}

FilterOutput MessageFilter::filter(const std::string& message,
                                    int senderFd,
                                    const std::string& senderNick) {
    (void)senderFd;

    if ((int)message.size() > Constants::MAX_MESSAGE_LEN) {
        return { FilterResult::BLOCKED_TOO_LONG, "" };
    }

    if (containsNullByte(message)) {
        LOG_WARN("Null byte injection attempt from: " + senderNick);
        AUDIT_D(AuditEventType::SECURITY, senderNick, "", "NULL_BYTE_INJECT",
                AuditResult::BLOCKED, "", "null byte in message");
        return { FilterResult::BLOCKED_NULL_BYTE, "" };
    }

    if (containsInjection(message)) {
        LOG_WARN("Injection attempt from: " + senderNick + " msg=" + message);
        AUDIT_D(AuditEventType::SECURITY, senderNick, "", "INJECTION_ATTEMPT",
                AuditResult::BLOCKED, "", message.substr(0, 128));
        return { FilterResult::BLOCKED_INJECTION, "" };
    }

    logUrl(message, senderNick);

    return { FilterResult::PASS, message };
}
