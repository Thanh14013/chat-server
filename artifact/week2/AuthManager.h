#pragma once
#include "SessionToken.h"
#include "../../common/ErrorCodes.h"

#include <string>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <ctime>
#include <memory>

// Forward declaration to avoid including sqlite3.h in the header
struct sqlite3;

namespace vcs::security {

/**
 * User authentication and session management.
 *
 * Storage: SQLite via the shared Database utility from server/utils/Database.
 * The in-memory active_sessions map maps token → socket_fd for fast lookup.
 *
 * Security policy:
 *  - Passwords stored as PBKDF2-HMAC-SHA256 with random salt; never plaintext.
 *  - After 5 failed attempts: account locked for 15 minutes.
 *  - Nicknames validated with regex [a-zA-Z0-9_]{3,32}.
 *  - OPENSSL_cleanse called on password buffers immediately after hashing.
 */
class AuthManager {
public:
    static constexpr int MAX_FAILED_ATTEMPTS  = 5;
    static constexpr int LOCKOUT_SECONDS      = 900; // 15 minutes

    // Constructor takes a raw sqlite3* borrowed from Database singleton
    explicit AuthManager(sqlite3* db, std::shared_ptr<SessionToken> token_manager);
    ~AuthManager();

    // Non-copyable
    AuthManager(const AuthManager&)            = delete;
    AuthManager& operator=(const AuthManager&) = delete;

    /**
     * Register a new user account.
     *
     * @param nickname  Must match [a-zA-Z0-9_]{3,32}.
     * @param password  Plaintext (scrubbed internally after PBKDF2).
     * @return ERR_OK, ERR_NICKNAME_TAKEN, ERR_NICKNAME_INVALID, ERR_INTERNAL.
     */
    ErrorCode registerUser(const std::string& nickname, std::string password);

    /**
     * Authenticate a user and issue a session token.
     *
     * @param nickname  Existing account nickname.
     * @param password  Plaintext (scrubbed internally after PBKDF2 verify).
     * @param fd        Socket file descriptor of the authenticated client.
     * @param token_out Filled with signed session token on success.
     * @return ERR_OK, ERR_AUTH_FAILED, ERR_AUTH_TOO_MANY_ATTEMPTS, ERR_INTERNAL.
     */
    ErrorCode authenticate(const std::string& nickname,
                           std::string        password,
                           int                fd,
                           std::string&       token_out);

    /**
     * Validate a session token for incoming requests.
     * @return {fd, valid} — fd is -1 if token invalid/expired.
     */
    struct ValidationResult { int fd; bool valid; };
    ValidationResult validateToken(const std::string& token) const;

    /**
     * Revoke a session token (logout or server-side kick).
     */
    void revokeToken(const std::string& token);

    /** Returns true if the nickname is already in the SQLite users table. */
    bool isNicknameTaken(const std::string& nickname) const;

    /** Returns the role of an authenticated user, or GUEST if unknown. */
    SessionToken::Role getUserRole(const std::string& nickname) const;

    /**
     * Remove all sessions associated with a socket fd.
     * Called when a client disconnects.
     */
    void removeSessionByFd(int fd);

private:
    sqlite3*                        db_;
    std::shared_ptr<SessionToken>   token_manager_;

    // active_sessions: token_string → fd
    mutable std::shared_mutex       sessions_mutex_;
    std::unordered_map<std::string, int> active_sessions_;

    // ── Helpers ───────────────────────────────────────────────────────────────
    bool        isValidNickname(const std::string& nick) const;
    void        incrementFailedAttempts(const std::string& nickname);
    void        resetFailedAttempts(const std::string& nickname);
    bool        isAccountLocked(const std::string& nickname) const;
    void        ensureTablesExist();
};

} // namespace vcs::security
