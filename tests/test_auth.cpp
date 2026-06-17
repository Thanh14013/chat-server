#include "test_framework.h"
#include "../common/ErrorCodes.h"
#include "../server/security/AuditLogger.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <set>

static std::string sha256_hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

static std::vector<uint8_t> pbkdf2(const std::string& pass, const std::string& salt,
                                    int iterations = 100000, int keylen = 32) {
    std::vector<uint8_t> out(keylen);
    PKCS5_PBKDF2_HMAC(pass.c_str(), (int)pass.size(),
                      reinterpret_cast<const unsigned char*>(salt.c_str()), (int)salt.size(),
                      iterations, EVP_sha256(), keylen, out.data());
    return out;
}

static std::vector<uint8_t> rand_bytes(int n) {
    std::vector<uint8_t> buf(n);
    RAND_bytes(buf.data(), n);
    return buf;
}

TEST(sha256_deterministic) {
    ASSERT_EQ(sha256_hex("hello"), sha256_hex("hello"));
}

TEST(sha256_different_inputs) {
    ASSERT_NE(sha256_hex("hello"), sha256_hex("world"));
}

TEST(sha256_length) {
    ASSERT_EQ(sha256_hex("test").size(), (size_t)64);
}

TEST(pbkdf2_same_password_different_salt) {
    auto h1 = pbkdf2("password123", "salt_a");
    auto h2 = pbkdf2("password123", "salt_b");
    ASSERT_NE(h1, h2);
}

TEST(pbkdf2_same_inputs_same_output) {
    auto h1 = pbkdf2("password123", "salt_x");
    auto h2 = pbkdf2("password123", "salt_x");
    ASSERT_EQ(h1, h2);
}

TEST(pbkdf2_output_length) {
    auto h = pbkdf2("password", "salt", 100000, 32);
    ASSERT_EQ(h.size(), (size_t)32);
}

TEST(pbkdf2_different_passwords) {
    auto h1 = pbkdf2("password1", "salt");
    auto h2 = pbkdf2("password2", "salt");
    ASSERT_NE(h1, h2);
}

TEST(hmac_sha256_correct) {
    std::string key  = "secret_key";
    std::string data = "message data";
    unsigned char out1[32], out2[32];
    unsigned int  len = 32;

    HMAC(EVP_sha256(),
         key.c_str(), (int)key.size(),
         reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
         out1, &len);
    HMAC(EVP_sha256(),
         key.c_str(), (int)key.size(),
         reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
         out2, &len);

    ASSERT_EQ(std::memcmp(out1, out2, 32), 0);
}

TEST(hmac_different_key_different_output) {
    unsigned char out1[32], out2[32];
    unsigned int len = 32;
    std::string data = "message";

    HMAC(EVP_sha256(), "key1", 4,
         reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), out1, &len);
    HMAC(EVP_sha256(), "key2", 4,
         reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), out2, &len);

    ASSERT_NE(std::memcmp(out1, out2, 32), 0);
}

TEST(hmac_tampered_data_different_output) {
    unsigned char out1[32], out2[32];
    unsigned int len = 32;
    std::string key  = "key";
    std::string d1   = "original";
    std::string d2   = "0riginal";

    HMAC(EVP_sha256(), key.c_str(), (int)key.size(),
         reinterpret_cast<const unsigned char*>(d1.c_str()), d1.size(), out1, &len);
    HMAC(EVP_sha256(), key.c_str(), (int)key.size(),
         reinterpret_cast<const unsigned char*>(d2.c_str()), d2.size(), out2, &len);

    ASSERT_NE(std::memcmp(out1, out2, 32), 0);
}

TEST(csprng_produces_bytes) {
    auto bytes = rand_bytes(32);
    ASSERT_EQ(bytes.size(), (size_t)32);
}

TEST(csprng_no_repeats_in_100_nonces) {
    std::set<std::vector<uint8_t>> seen;
    for (int i = 0; i < 100; i++) {
        auto n = rand_bytes(16);
        ASSERT_TRUE(seen.find(n) == seen.end());
        seen.insert(n);
    }
}

TEST(audit_logger_log_and_flush) {
    AuditLogger::instance().log(
        AuditEventType::AUTH, "testuser", "", "LOGIN",
        AuditResult::SUCCESS, "127.0.0.1", "unit test");
    AuditLogger::instance().flush();
}

TEST(error_codes_distinct) {
    ASSERT_NE((int)ErrorCode::ERR_OK,               (int)ErrorCode::ERR_AUTH_FAILED);
    ASSERT_NE((int)ErrorCode::ERR_NICKNAME_TAKEN,   (int)ErrorCode::ERR_ROOM_FULL);
    ASSERT_NE((int)ErrorCode::ERR_RATE_LIMITED,     (int)ErrorCode::ERR_INTERNAL);
}

int main() {
    return run_all_tests("Auth & Crypto Tests");
}
