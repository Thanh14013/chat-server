#include "AuthManager.h"
#include "../../crypto/sha256.h"
#include "../../crypto/random.h"

#include <sqlite3.h>
#include <openssl/crypto.h>

#include <regex>
#include <stdexcept>
#include <cstring>

namespace vcs::security {

// ── Lifecycle ─────────────────────────────────────────────────────────────────

AuthManager::AuthManager(sqlite3* db, std::shared_ptr<SessionToken> token_manager)
    : db_(db), token_manager_(std::move(token_manager)) {
    if (!db_) throw std::runtime_error("AuthManager: null sqlite3 handle");
    ensureTablesExist();
}

AuthManager::~AuthManager() = default;

// ── Table initialisation ──────────────────────────────────────────────────────

void AuthManager::ensureTablesExist() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS Users (
            nickname        TEXT    PRIMARY KEY,
            password_hash   TEXT    NOT NULL,
            salt            TEXT    NOT NULL,
            role            TEXT    NOT NULL DEFAULT 'USER',
            created_at      INTEGER NOT NULL,
            last_login      INTEGER DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until    INTEGER NOT NULL DEFAULT 0
        );
    )";
    char* errmsg = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err(errmsg ? errmsg : "unknown");
        sqlite3_free(errmsg);
        throw std::runtime_error("AuthManager: cannot create Users table: " + err);
    }
}

// ── Validation ────────────────────────────────────────────────────────────────

bool AuthManager::isValidNickname(const std::string& nick) const {
    static const std::regex pattern("^[a-zA-Z0-9_]{3,32}$");
    return std::regex_match(nick, pattern);
}

// ── registerUser ──────────────────────────────────────────────────────────────

ErrorCode AuthManager::registerUser(const std::string& nickname, std::string password) {
    if (!isValidNickname(nickname)) return ErrorCode::ERR_NICKNAME_INVALID;
    if (isNicknameTaken(nickname))  return ErrorCode::ERR_NICKNAME_TAKEN;

    // Generate unique salt for this user
    auto salt = vcs::crypto::SHA256Hash::generateSalt();

    // PBKDF2 hash — password is zeroed inside pbkdf2()
    std::string hash = vcs::crypto::SHA256Hash::pbkdf2(password, salt);
    // 'password' is now scrubbed

    std::string salt_hex = vcs::crypto::SHA256Hash::toHex(salt.data(), salt.size());
    time_t now = std::time(nullptr);

    const char* sql =
        "INSERT INTO Users (nickname, password_hash, salt, role, created_at) "
        "VALUES (?, ?, ?, 'USER', ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return ErrorCode::ERR_INTERNAL;
    }

    sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hash.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, salt_hex.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(now));

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? ErrorCode::ERR_OK : ErrorCode::ERR_INTERNAL;
}

// ── authenticate ─────────────────────────────────────────────────────────────

ErrorCode AuthManager::authenticate(const std::string& nickname,
                                     std::string        password,
                                     int                fd,
                                     std::string&       token_out) {
    if (isAccountLocked(nickname)) {
        OPENSSL_cleanse(password.data(), password.size());
        return ErrorCode::ERR_AUTH_TOO_MANY_ATTEMPTS;
    }

    // Fetch stored hash and salt from SQLite
    const char* sql =
        "SELECT password_hash, salt, role FROM Users WHERE nickname = ?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        OPENSSL_cleanse(password.data(), password.size());
        return ErrorCode::ERR_INTERNAL;
    }

    sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_TRANSIENT);

    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        OPENSSL_cleanse(password.data(), password.size());
        incrementFailedAttempts(nickname);
        return ErrorCode::ERR_AUTH_FAILED;
    }

    std::string stored_hash(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    std::string salt_hex   (reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
    std::string role_str   (reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
    sqlite3_finalize(stmt);

    // Reconstruct salt from hex
    auto salt_bytes_vec = vcs::crypto::SHA256Hash::fromHex(salt_hex);
    vcs::crypto::SHA256Hash::SaltBytes salt{};
    std::copy_n(salt_bytes_vec.begin(),
                std::min(salt_bytes_vec.size(), salt.size()),
                salt.begin());

    // Compute PBKDF2 of provided password (password is zeroed after this call)
    std::string computed_hash = vcs::crypto::SHA256Hash::pbkdf2(password, salt);
    // 'password' is now scrubbed

    // Constant-time string comparison to prevent timing attacks
    bool match = (computed_hash.size() == stored_hash.size()) &&
                 (CRYPTO_memcmp(computed_hash.data(), stored_hash.data(),
                                computed_hash.size()) == 0);

    if (!match) {
        incrementFailedAttempts(nickname);
        return ErrorCode::ERR_AUTH_FAILED;
    }

    // Success: reset failed attempts and update last_login
    resetFailedAttempts(nickname);

    const char* update_sql = "UPDATE Users SET last_login = ? WHERE nickname = ?;";
    sqlite3_stmt* upd_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, update_sql, -1, &upd_stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(upd_stmt, 1, static_cast<sqlite3_int64>(std::time(nullptr)));
        sqlite3_bind_text(upd_stmt, 2, nickname.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(upd_stmt);
        sqlite3_finalize(upd_stmt);
    }

    // Issue session token
    auto role = SessionToken::stringToRole(role_str);
    token_out = token_manager_->generate(nickname, role);

    // Register in active sessions map
    {
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
        active_sessions_[token_out] = fd;
    }

    return ErrorCode::ERR_OK;
}

// ── validateToken ─────────────────────────────────────────────────────────────

AuthManager::ValidationResult AuthManager::validateToken(const std::string& token) const {
    auto claims = token_manager_->validate(token);
    if (!claims.valid) return {-1, false};

    std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
    auto it = active_sessions_.find(token);
    if (it == active_sessions_.end()) return {-1, false};
    return {it->second, true};
}

// ── revokeToken ───────────────────────────────────────────────────────────────

void AuthManager::revokeToken(const std::string& token) {
    token_manager_->revoke(token);
    std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
    active_sessions_.erase(token);
}

// ── removeSessionByFd ─────────────────────────────────────────────────────────

void AuthManager::removeSessionByFd(int fd) {
    std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
    for (auto it = active_sessions_.begin(); it != active_sessions_.end(); ) {
        if (it->second == fd) {
            it = active_sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

// ── isNicknameTaken ───────────────────────────────────────────────────────────

bool AuthManager::isNicknameTaken(const std::string& nickname) const {
    const char* sql = "SELECT 1 FROM Users WHERE nickname = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_TRANSIENT);
    bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

// ── getUserRole ───────────────────────────────────────────────────────────────

SessionToken::Role AuthManager::getUserRole(const std::string& nickname) const {
    const char* sql = "SELECT role FROM Users WHERE nickname = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return SessionToken::Role::GUEST;

    sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_TRANSIENT);
    SessionToken::Role role = SessionToken::Role::GUEST;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string s(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
        role = SessionToken::stringToRole(s);
    }
    sqlite3_finalize(stmt);
    return role;
}

// ── Brute-force protection ────────────────────────────────────────────────────

void AuthManager::incrementFailedAttempts(const std::string& nickname) {
    const char* sql =
        "UPDATE Users SET failed_attempts = failed_attempts + 1, "
        "locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END "
        "WHERE nickname = ?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return;

    time_t lock_time = std::time(nullptr) + LOCKOUT_SECONDS;
    sqlite3_bind_int(stmt,   1, MAX_FAILED_ATTEMPTS);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(lock_time));
    sqlite3_bind_text(stmt,  3, nickname.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void AuthManager::resetFailedAttempts(const std::string& nickname) {
    const char* sql =
        "UPDATE Users SET failed_attempts = 0, locked_until = 0 WHERE nickname = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

bool AuthManager::isAccountLocked(const std::string& nickname) const {
    const char* sql =
        "SELECT locked_until, failed_attempts FROM Users WHERE nickname = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_TRANSIENT);
    bool locked = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        time_t locked_until    = static_cast<time_t>(sqlite3_column_int64(stmt, 0));
        int    failed_attempts = sqlite3_column_int(stmt, 1);
        if (failed_attempts >= MAX_FAILED_ATTEMPTS && std::time(nullptr) < locked_until) {
            locked = true;
        }
    }
    sqlite3_finalize(stmt);
    return locked;
}

} // namespace vcs::security
