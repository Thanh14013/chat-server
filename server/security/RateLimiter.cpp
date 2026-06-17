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

double RateLimiter::getDefaultRate(RateLimitType type) const {
    const auto& cfg = Config::instance().get();
    switch (type) {
        case RateLimitType::MSG_CHAT:
            return static_cast<double>(cfg.rate_limit_msg_per_sec);
        case RateLimitType::CONNECT:
            return static_cast<double>(cfg.connect_rate_per_min) / 60.0;
        case RateLimitType::AUTH:
            return static_cast<double>(cfg.auth_rate_per_min) / 60.0;
        case RateLimitType::FILE_TRANSFER:
            return static_cast<double>(cfg.file_transfer_per_hour) / 3600.0;
    }
    return 1.0;
}

void RateLimiter::removeKey(const std::string& key) {
    std::lock_guard<std::mutex> lk(m_mapMutex);
    auto it = m_buckets.find(key);
    if (it != m_buckets.end()) {
        delete it->second;
        m_buckets.erase(it);
    }
}

RateCheckResult RateLimiter::checkLimit(const std::string& key, RateLimitType type, double cost) {
    TokenBucket* bucket = nullptr;
    {
        std::lock_guard<std::mutex> lk(m_mapMutex);
        auto it = m_buckets.find(key);
        if (it == m_buckets.end()) {
            double rate = getDefaultRate(type);
            bucket = new TokenBucket(rate * 2.0, rate); 
            m_buckets[key] = bucket;
        } else {
            bucket = it->second;
        }
    }

    if (bucket->consume(cost)) return RateCheckResult::ALLOWED;

    int v = bucket->violations;
    if (v >= 4) {
        IntrusionDetector::instance().reportViolation(
            key, ViolationType::RATE_LIMIT_EXCEEDED, -1);
    }

    LOG_WARN("Rate limit hit: key=" + key + " type=" + std::to_string(static_cast<int>(type))
             + " violations=" + std::to_string(v));

    AUDIT_D(AuditEventType::SECURITY, "", "", "RATE_LIMITED",
            AuditResult::BLOCKED, "", "key=" + key);
    return RateCheckResult::RATE_LIMITED;
}

int RateLimiter::getViolations(const std::string& key) {
    std::lock_guard<std::mutex> lk(m_mapMutex);
    auto it = m_buckets.find(key);
    return it != m_buckets.end() ? it->second->violations : 0;
}

double RateLimiter::getTokens(const std::string& key) {
    std::lock_guard<std::mutex> lk(m_mapMutex);
    auto it = m_buckets.find(key);
    return it != m_buckets.end() ? it->second->tokens : 0.0;
}
