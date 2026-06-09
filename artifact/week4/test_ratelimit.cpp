#include "test_framework.h"
#include "../server/security/RateLimiter.h"
#include "../server/security/IntrusionDetector.h"
#include <thread>
#include <chrono>

TEST(token_bucket_allows_within_rate) {
    TokenBucket bucket(10.0, 10.0);
    for (int i = 0; i < 10; i++) {
        ASSERT_TRUE(bucket.consume(1.0));
    }
}

TEST(token_bucket_blocks_when_empty) {
    TokenBucket bucket(3.0, 10.0);
    ASSERT_TRUE(bucket.consume(1.0));
    ASSERT_TRUE(bucket.consume(1.0));
    ASSERT_TRUE(bucket.consume(1.0));
    ASSERT_FALSE(bucket.consume(1.0));
}

TEST(token_bucket_refills_over_time) {
    TokenBucket bucket(1.0, 10.0);
    ASSERT_TRUE(bucket.consume(1.0));
    ASSERT_FALSE(bucket.consume(1.0));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(bucket.consume(1.0));
}

TEST(token_bucket_caps_at_max) {
    TokenBucket bucket(5.0, 100.0);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ASSERT_EQ(bucket.violations, 0);

    for (int i = 0; i < 5; i++) bucket.consume(1.0);
    ASSERT_FALSE(bucket.consume(1.0));
}

TEST(token_bucket_tracks_violations) {
    TokenBucket bucket(1.0, 0.1);
    bucket.consume(1.0);
    bucket.consume(1.0);
    bucket.consume(1.0);
    ASSERT_TRUE(bucket.violations >= 2);
}

TEST(ratelimiter_add_remove_client) {
    RateLimiter& rl = RateLimiter::instance();
    rl.addClient(9999, 100.0);
    auto result = rl.checkLimit(9999);
    ASSERT_EQ(result, RateCheckResult::ALLOWED);
    rl.removeClient(9999);
}

TEST(ratelimiter_unknown_fd_allowed) {
    RateLimiter& rl = RateLimiter::instance();
    auto result = rl.checkLimit(88888);
    ASSERT_EQ(result, RateCheckResult::ALLOWED);
}

TEST(ids_clean_ip_allowed) {
    IntrusionDetector& ids = IntrusionDetector::instance();
    auto status = ids.checkIP("10.0.0.1");
    ASSERT_TRUE(status == IPStatus::ALLOWED || status == IPStatus::WHITELISTED);
}

TEST(ids_whitelisted_ip) {
    IntrusionDetector& ids = IntrusionDetector::instance();
    ids.addWhitelist("192.168.1.250");
    ASSERT_EQ(ids.checkIP("192.168.1.250"), IPStatus::WHITELISTED);
}

TEST(ids_temp_ban_blocks) {
    IntrusionDetector& ids = IntrusionDetector::instance();
    ids.tempBan("172.16.0.99", 3600, "test");
    ASSERT_EQ(ids.checkIP("172.16.0.99"), IPStatus::BLOCKED);
    ids.unban("172.16.0.99");
}

TEST(ids_perm_ban_blocks) {
    IntrusionDetector& ids = IntrusionDetector::instance();
    ids.permBan("10.99.99.99", "test perm ban");
    ASSERT_EQ(ids.checkIP("10.99.99.99"), IPStatus::BLOCKED);
    ids.unban("10.99.99.99");
}

TEST(ids_unban_restores_access) {
    IntrusionDetector& ids = IntrusionDetector::instance();
    ids.tempBan("10.1.2.3", 3600, "test");
    ASSERT_EQ(ids.checkIP("10.1.2.3"), IPStatus::BLOCKED);
    ids.unban("10.1.2.3");
    auto s = ids.checkIP("10.1.2.3");
    ASSERT_TRUE(s == IPStatus::ALLOWED || s == IPStatus::WHITELISTED);
}

TEST(ids_score_for_violations) {
    ASSERT_EQ(IntrusionDetector::scoreForViolation(ViolationType::FAILED_AUTH),    10);
    ASSERT_EQ(IntrusionDetector::scoreForViolation(ViolationType::REPLAY_ATTACK),  50);
    ASSERT_EQ(IntrusionDetector::scoreForViolation(ViolationType::PORT_SCAN),      100);
    ASSERT_EQ(IntrusionDetector::scoreForViolation(ViolationType::HMAC_FAILURE),   20);
}

TEST(ids_cef_format) {
    IntrusionDetector& ids = IntrusionDetector::instance();
    std::string cef = ids.exportCEF("1.2.3.4", ViolationType::FAILED_AUTH, 5);
    ASSERT_TRUE(cef.find("CEF:0") != std::string::npos);
    ASSERT_TRUE(cef.find("src=1.2.3.4") != std::string::npos);
    ASSERT_TRUE(cef.find("VCS") != std::string::npos);
}

int main() {
    return run_all_tests("Rate Limiter & IDS Tests");
}
