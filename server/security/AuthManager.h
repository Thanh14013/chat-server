#pragma once
#include "SessionToken.h"
#include "../../common/ErrorCodes.h"
#include <string>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <ctime>
#include <memory>

struct sqlite3;
;

namespace vcs::security
{
    class AuthManager
    {
    public:
        static constexpr int MAX_FAILED_ATTEMPTS = 5;
        static constexpr int LOCKOUT_SECONDS = 900; // 15 minutes

        explicit AuthManager(sqlite3 *db, std::shared_ptr<SessionToken> token_manager);
        ~AuthManager();

        AuthManager(const AuthManager &) = delete;
        AuthManager &operator=(const AuthManager &) = delete;

        ErrorCode registerUser(const std::string& nickname, std::string password);

        ErrorCode authenticate(const std::string& nickname, std::string password, int fd, std::string& token_out);

        struct ValidationResult{int fd; bool valid;};
        ValidationResult validateToken(const std::string& token) const;

        void revokeToken(const std::string& token);

        bool isNicknameTaken(const std::string& nickname) const;

        SessionToken::Role getUserRole(const std::string& nickname) const;

        void removeSessionByFd(int fd);
    
    private:
        sqlite3* db_;
        std::shared_ptr<SessionToken> token_manager_;

        mutable std::shared_mutex sessions_mutex_;
        std::unordered_map<std::string, int> active_sessions_;

        bool isValidNickname(const std::string& nick) const;
        void incrementFailedAttempts(const std::string& nickname);
        void resetFailedAttempts(const std::string& nickname);
        bool isAccountLocked(const std::string& nickname) const;
        void ensureTablesExist();
    };
}