#pragma once
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <string>

enum class RateCheckResult { ALLOWED, RATE_LIMITED };

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

    void addClient(int fd, double maxRate = -1.0);
    void removeClient(int fd);

    RateCheckResult checkLimit(int fd, double cost = 1.0);

    int    getViolations(int fd);
    double getTokens(int fd);

private:
    RateLimiter() = default;

    std::unordered_map<int, TokenBucket*> m_buckets;
    std::mutex                            m_mapMutex;

    double defaultRate() const;
};
