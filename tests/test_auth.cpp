#include "TestMacro.h"
#include "../server/security/AuthManager.h"
#include "../server/security/SessionToken.h"
#include "../crypto/random.h"
#include "../common/ErrorCodes.h"
#include <sqlite3.h>

using namespace vcs::security;
using namespace vcs::crypto;

void test_session_token() {
    auto secret = CSPRNG::getInstance().getBytes(32);
    SessionToken token_manager(secret);

    auto token = token_manager.generate("alice", SessionToken::Role::USER);
    ASSERT_TRUE(!token.empty());

    auto claims = token_manager.validate(token);
    ASSERT_TRUE(claims.valid);
    ASSERT_FALSE(claims.expired);
    ASSERT_TRUE(claims.sub == "alice");
    ASSERT_TRUE(claims.role == SessionToken::Role::USER);

    auto bad_token = token;
    size_t last_dot = bad_token.rfind('.');
    bad_token[last_dot + 1] = (bad_token[last_dot + 1] == 'a' ? 'b' : 'a');
    auto bad_claims = token_manager.validate(bad_token);
    ASSERT_FALSE(bad_claims.valid);

    token_manager.revoke(token);
    auto revoked_claims = token_manager.validate(token);
    ASSERT_FALSE(revoked_claims.valid);

    // Edge case: Malformed tokens
    ASSERT_FALSE(token_manager.validate("NOT_A_JWT").valid);
    ASSERT_FALSE(token_manager.validate("header.payload").valid);
    ASSERT_FALSE(token_manager.validate("header.payload.signature.extra").valid);
    
    // Edge case: Empty nickname
    auto empty_token = token_manager.generate("", SessionToken::Role::GUEST);
    auto empty_claims = token_manager.validate(empty_token);
    ASSERT_TRUE(empty_claims.valid);
    ASSERT_TRUE(empty_claims.sub == "");
}

void test_auth_manager() {
    sqlite3* db = nullptr;
    sqlite3_open(":memory:", &db);
    
    // Create users table
    const char *create_sql = "CREATE TABLE IF NOT EXISTS Users ("
                             "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                             "nickname TEXT UNIQUE NOT NULL, "
                             "password_hash TEXT NOT NULL, "
                             "salt TEXT NOT NULL, "
                             "role TEXT DEFAULT 'USER', "
                             "failed_attempts INTEGER DEFAULT 0, "
                             "locked_until INTEGER DEFAULT 0, "
                             "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
                             "last_login DATETIME"
                             ");";
    sqlite3_exec(db, create_sql, nullptr, nullptr, nullptr);

    auto secret = CSPRNG::getInstance().getBytes(32);
    auto token_mgr = std::make_shared<SessionToken>(secret);
    AuthManager am(db, token_mgr);

    auto err = am.registerUser("bob", "password123");
    ASSERT_TRUE(err == ErrorCode::ERR_OK);

    err = am.registerUser("bob", "password123");
    ASSERT_TRUE(err == ErrorCode::ERR_NICKNAME_TAKEN);

    std::string token;
    err = am.authenticate("bob", "password123", 100, token);
    ASSERT_TRUE(err == ErrorCode::ERR_OK);
    ASSERT_TRUE(!token.empty());

    err = am.authenticate("bob", "wrongpass", 101, token);
    ASSERT_TRUE(err == ErrorCode::ERR_AUTH_FAILED);

    for(int i=0; i<4; ++i) am.authenticate("bob", "wrong", 100, token);
    err = am.authenticate("bob", "wrong", 100, token);
    ASSERT_TRUE(err == ErrorCode::ERR_AUTH_TOO_MANY_ATTEMPTS);

    std::string nick;
    am.registerUser("alice2", "pass");
    am.authenticate("alice2", "pass", 102, token);

    err = am.reconnectWithToken(token, 103, nick);
    ASSERT_TRUE(err == ErrorCode::ERR_OK);
    ASSERT_TRUE(nick == "alice2");

    // Edge case: SQL Injection attempts (Prepared statements should prevent this, but regex catches it first)
    std::string sql_inject = "admin' OR 1=1 --";
    err = am.registerUser(sql_inject, "pass");
    ASSERT_TRUE(err == ErrorCode::ERR_NICKNAME_INVALID);
    err = am.authenticate(sql_inject, "pass", 104, token);
    ASSERT_TRUE(err == ErrorCode::ERR_AUTH_FAILED);

    // Edge case: valid string resembling SQL
    std::string sql_like = "admin_OR_1";
    err = am.registerUser(sql_like, "pass");
    ASSERT_TRUE(err == ErrorCode::ERR_OK);
    err = am.authenticate(sql_like, "pass", 104, token);
    ASSERT_TRUE(err == ErrorCode::ERR_OK);

    // Edge case: Extreme password length
    std::string long_pass(1000, 'A');
    err = am.registerUser("longpassuser", long_pass);
    ASSERT_TRUE(err == ErrorCode::ERR_OK);
    err = am.authenticate("longpassuser", long_pass, 105, token);
    ASSERT_TRUE(err == ErrorCode::ERR_OK);
}

int main() {
    RUN_TEST(test_session_token);
    RUN_TEST(test_auth_manager);
    return test::PrintTestResults("Auth Module");
}
