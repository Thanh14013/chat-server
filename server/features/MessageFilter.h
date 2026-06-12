#pragma once
#include <string>

enum class FilterResult {
    PASS,
    BLOCKED_SPAM,
    BLOCKED_INJECTION,
    BLOCKED_NULL_BYTE,
    BLOCKED_TOO_LONG
};

struct FilterOutput {
    FilterResult result;
    std::string  message;
};

class MessageFilter {
public:
    static MessageFilter& instance();

    FilterOutput filter(const std::string& message, int senderFd,
                        const std::string& senderNick);

private:
    MessageFilter() = default;

    bool containsInjection(const std::string& msg);
    bool containsNullByte(const std::string& msg);
    void logUrl(const std::string& msg, const std::string& nick);
};