#include "test_framework.h"
#include "../server/security/AuthManager.h"
#include "../server/utils/Database.h"
#include "../server/security/SessionToken.h"
#include "../common/ErrorCodes.h"
#include <memory>
#include <vector>
#include <string>

using namespace vcs::security;

TEST(auth_manager_register_duplicate) {
    Database::instance().open(":memory:");
    std::vector<uint8_t> secret(32, 'a');
    auto token_mgr = std::make_shared<SessionToken>(secret);
    AuthManager auth(Database::instance().handle(), token_mgr);
    
    ErrorCode e1 = auth.registerUser("user1", "pass1");
    ASSERT_EQ(e1, ErrorCode::ERR_OK);
    
    ErrorCode e2 = auth.registerUser("user1", "pass2");
    ASSERT_EQ(e2, ErrorCode::ERR_NICKNAME_TAKEN);
    
    Database::instance().close();
}

TEST(auth_manager_invalid_login) {
    Database::instance().open(":memory:");
    std::vector<uint8_t> secret(32, 'a');
    auto token_mgr = std::make_shared<SessionToken>(secret);
    AuthManager auth(Database::instance().handle(), token_mgr);
    auth.registerUser("user1", "pass1");
    
    std::string token;
    ErrorCode e1 = auth.authenticate("user1", "wrongpass", 1, token);
    ASSERT_EQ(e1, ErrorCode::ERR_AUTH_FAILED);
    
    ErrorCode e2 = auth.authenticate("user_not_exist", "pass", 1, token);
    ASSERT_EQ(e2, ErrorCode::ERR_AUTH_FAILED);
    Database::instance().close();
}

TEST(auth_manager_room_creation) {
    Database::instance().open(":memory:");
    std::vector<uint8_t> secret(32, 'a');
    auto token_mgr = std::make_shared<SessionToken>(secret);
    AuthManager auth(Database::instance().handle(), token_mgr);
    
    auth.registerUser("creator", "pass1");
    ErrorCode e = auth.createRoomDb("test_room", "room_pass", "creator");
    ASSERT_EQ(e, ErrorCode::ERR_OK);
    
    ErrorCode e2 = auth.createRoomDb("test_room", "room_pass", "creator");
    ASSERT_NE(e2, ErrorCode::ERR_OK); // Duplicate room
    
    Database::instance().close();
}

TEST(auth_manager_room_password) {
    Database::instance().open(":memory:");
    std::vector<uint8_t> secret(32, 'a');
    auto token_mgr = std::make_shared<SessionToken>(secret);
    AuthManager auth(Database::instance().handle(), token_mgr);
    
    auth.registerUser("creator", "pass1");
    auth.createRoomDb("test_room", "room_pass", "creator");
    
    ErrorCode e1 = auth.verifyRoomPasswordDb("test_room", "room_pass");
    ASSERT_EQ(e1, ErrorCode::ERR_OK);
    
    ErrorCode e2 = auth.verifyRoomPasswordDb("test_room", "wrong_pass");
    ASSERT_EQ(e2, ErrorCode::ERR_AUTH_FAILED);
    
    ErrorCode e3 = auth.verifyRoomPasswordDb("not_exist", "pass");
    ASSERT_EQ(e3, ErrorCode::ERR_ROOM_NOT_FOUND);
    
    Database::instance().close();
}

TEST(auth_manager_room_bans) {
    Database::instance().open(":memory:");
    std::vector<uint8_t> secret(32, 'a');
    auto token_mgr = std::make_shared<SessionToken>(secret);
    AuthManager auth(Database::instance().handle(), token_mgr);
    
    auth.registerUser("creator", "pass");
    auth.registerUser("bad_user", "pass");
    auth.createRoomDb("test_room", "room_pass", "creator");
    
    auth.banUserFromRoomDb("test_room", "bad_user");
    auto banned = auth.getBannedUsersForRoomDb("test_room");
    ASSERT_EQ(banned.size(), (size_t)1);
    ASSERT_EQ(banned[0], "bad_user");
    
    auth.unbanUserFromRoomDb("test_room", "bad_user");
    auto banned2 = auth.getBannedUsersForRoomDb("test_room");
    ASSERT_EQ(banned2.size(), (size_t)0);
    
    Database::instance().close();
}

int main() {
    return run_all_tests("AuthManager Edge Case Tests");
}
