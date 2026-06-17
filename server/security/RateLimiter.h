#pragma once
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <string>

enum class RateCheckResult { ALLOWED, RATE_LIMITED };

enum class RateLimitType {
    MSG_CHAT,
    CONNECT,
    AUTH,
    FILE_TRANSFER
};

struct TokenBucket {
    double   tokens;
    double   max_tokens;
    double   refill_rate;
    std::chrono::steady_clock::time_point last_refill;
    int      violations;
    std::mutex mtx;

    TokenBucket(double max, double rate)
        : tokens(max), max_tokens(max), refill_rate(rate),
          last_refill(std::chrono::steady_clock::now()), violations(0) {}

    bool consume(double cost = 1.0);
};

class RateLimiter {
public:
    static RateLimiter& instance();

    RateCheckResult checkLimit(const std::string& key, RateLimitType type, double cost = 1.0);

    int    getViolations(const std::string& key);
    double getTokens(const std::string& key);

    void removeKey(const std::string& key);

private:
    RateLimiter() = default;

    std::unordered_map<std::string, TokenBucket*> m_buckets;
    std::mutex                                    m_mapMutex;

    double getDefaultRate(RateLimitType type) const;
};
