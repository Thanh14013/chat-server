#include "RateLimiter.h"
#include "../utils/Config.h"
#include "../utils/Logger.h"
#include "IntrusionDetector.h"
#include "AuditLogger.h"
#include "../../common/Constants.h"
#include <algorithm>

bool TokenBucket::consume(double cost) {
    std::lock_guard<std::mutex> lk(mtx);

    auto now     = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - last_refill).count();
    last_refill  = now;

    tokens = std::min(max_tokens, tokens + elapsed * refill_rate);

    if (tokens >= cost) {
        tokens -= cost;
        return true;
    }
    violations++;
    return false;
}

RateLimiter& RateLimiter::instance() {
    static RateLimiter inst;
    return inst;
}

double RateLimiter::defaultRate() const {
    return static_cast<double>(Config::instance().get().rate_limit_msg_per_sec);
}

void RateLimiter::addClient(int fd, double maxRate) {
    double rate = (maxRate > 0) ? maxRate : defaultRate();
    std::lock_guard<std::mutex> lk(m_mapMutex);
    m_buckets[fd] = new TokenBucket(rate, rate);
}

void RateLimiter::removeClient(int fd) {
    std::lock_guard<std::mutex> lk(m_mapMutex);
    auto it = m_buckets.find(fd);
    if (it != m_buckets.end()) {
        delete it->second;
        m_buckets.erase(it);
    }
}

RateCheckResult RateLimiter::checkLimit(int fd, double cost) {
    TokenBucket* bucket = nullptr;
    {
        std::lock_guard<std::mutex> lk(m_mapMutex);
        auto it = m_buckets.find(fd);
        if (it == m_buckets.end()) return RateCheckResult::ALLOWED;
        bucket = it->second;
    }

    if (bucket->consume(cost)) return RateCheckResult::ALLOWED;

    int v = bucket->violations;
    if (v >= 4) {
        IntrusionDetector::instance().reportViolation(
            "", ViolationType::RATE_LIMIT_EXCEEDED, fd);
    }

    LOG_WARN("Rate limit hit: fd=" + std::to_string(fd)
             + " violations=" + std::to_string(v));

    AUDIT_D(AuditEventType::SECURITY, "", "", "RATE_LIMITED",
            AuditResult::BLOCKED, "", "fd=" + std::to_string(fd));
    return RateCheckResult::RATE_LIMITED;
}

int RateLimiter::getViolations(int fd) {
    std::lock_guard<std::mutex> lk(m_mapMutex);
    auto it = m_buckets.find(fd);
    return it != m_buckets.end() ? it->second->violations : 0;
}

double RateLimiter::getTokens(int fd) {
    std::lock_guard<std::mutex> lk(m_mapMutex);
    auto it = m_buckets.find(fd);
    return it != m_buckets.end() ? it->second->tokens : 0.0;
}
