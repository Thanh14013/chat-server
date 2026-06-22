#include "AuthManager.h"
#include "../../crypto/sha256.h"
#include "../../crypto/random.h"
#include <sqlite3.h>
#include <openssl/crypto.h>
#include <regex>
#include <stdexcept>
#include <cstring>

namespace vcs::security
{
    AuthManager::AuthManager(sqlite3 *db, std::shared_ptr<SessionToken> token_manager)
        : db_(db), token_manager_(std::move(token_manager))
    {
        if (!db_)
            throw std::runtime_error("AuthManager: null sqlite3 handle");
        ensureTablesExist();
        ensureOwnerExists();
    }

    AuthManager::~AuthManager() = default;

    void AuthManager::ensureOwnerExists()
    {
        if (isNicknameTaken("thanh123")) return;

        auto salt = vcs::crypto::SHA256Hash::generateSalt();
        std::string pwd = "thanh123";
        std::string hash = vcs::crypto::SHA256Hash::pbkdf2(pwd, salt);
        std::string salt_hex = vcs::crypto::SHA256Hash::toHex(salt.data(), salt.size());
        time_t now = std::time(nullptr);

        const char *sql =
            "INSERT INTO Users (nickname, password_hash, salt, role, created_at) "
            "VALUES (?, ?, ?, 'OWNER', ?);";

        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return;

        sqlite3_bind_text(stmt, 1, "thanh123", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, salt_hex.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(now));

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    void AuthManager::ensureTablesExist()
    {
        const char *sql = R"(
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

        char *errmsg = nullptr;
        if (sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg) != SQLITE_OK)
        {
            std::string err(errmsg ? errmsg : "unknown");
            sqlite3_free(errmsg);
            throw std::runtime_error("AuthManager: cannot create Users table: " + err);
        }
    }

    bool AuthManager::isValidNickname(const std::string &nick) const
    {
        static const std::regex pattern("^[a-zA-Z0-9_]{3,32}$");
        return std::regex_match(nick, pattern);
    }

    ErrorCode AuthManager::registerUser(const std::string &nickname, std::string password)
    {
        if (!isValidNickname(nickname))
            return ErrorCode::ERR_NICKNAME_INVALID;
        if (isNicknameTaken(nickname))
            return ErrorCode::ERR_NICKNAME_TAKEN;

        auto salt = vcs::crypto::SHA256Hash::generateSalt();

        std::string hash = vcs::crypto::SHA256Hash::pbkdf2(password, salt);

        std::string salt_hex = vcs::crypto::SHA256Hash::toHex(salt.data(), salt.size());

        time_t now = std::time(nullptr);

        const char *sql =
            "INSERT INTO Users (nickname, password_hash, salt, role, created_at) "
            "VALUES (?, ?, ?, 'USER', ?);";

        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        {
            return ErrorCode::ERR_INTERNAL;
        }

        sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, salt_hex.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(now));

        // run sql
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return (rc == SQLITE_DONE) ? ErrorCode::ERR_OK : ErrorCode::ERR_INTERNAL;
    }

    ErrorCode AuthManager::authenticate(const std::string &nickname, std::string password, int fd, std::string &token_out)
    {
        if (isAccountLocked(nickname))
        {
            OPENSSL_cleanse(password.data(), password.size());
            return ErrorCode::ERR_AUTH_TOO_MANY_ATTEMPTS;
        }

        const char *sql =
            "SELECT password_hash, salt, role FROM Users WHERE nickname = ?;";

        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        {
            OPENSSL_cleanse(password.data(), password.size());
            return ErrorCode::ERR_INTERNAL;
        }

        sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_TRANSIENT);

        int step = sqlite3_step(stmt);
        if (step != SQLITE_ROW)
        {
            sqlite3_finalize(stmt);
            OPENSSL_cleanse(password.data(), password.size());
            incrementFailedAttempts(nickname);
            return ErrorCode::ERR_AUTH_FAILED;
        }

        std::string stored_hash(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
        std::string salt_hex(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)));
        std::string role_str(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2)));
        sqlite3_finalize(stmt);

        auto salt_bytes_vec = vcs::crypto::SHA256Hash::fromHex(salt_hex);
        vcs::crypto::SHA256Hash::SaltBytes salt{};
        std::copy_n(salt_bytes_vec.begin(), std::min(salt_bytes_vec.size(), salt.size()), salt.begin());

        std::string pwd = password;
        std::string computed_hash = vcs::crypto::SHA256Hash::pbkdf2(pwd, salt);

        bool match = (computed_hash.size() == stored_hash.size()) && (CRYPTO_memcmp(computed_hash.data(), stored_hash.data(), computed_hash.size()) == 0);

        if (!match)
        {
            incrementFailedAttempts(nickname);
            return ErrorCode::ERR_AUTH_FAILED;
        }

        resetFailedAttempts(nickname);

        const char *update_sql = "UPDATE Users SET last_login = ? WHERE nickname = ?;";
        sqlite3_stmt *upd_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, update_sql, -1, &upd_stmt, nullptr) == SQLITE_OK)
        {
            sqlite3_bind_int64(upd_stmt, 1, static_cast<sqlite3_int64>(std::time(nullptr)));
            sqlite3_bind_text(upd_stmt, 2, nickname.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(upd_stmt);
            sqlite3_finalize(upd_stmt);
        }

        auto role = SessionToken::stringToRole(role_str);
        token_out = token_manager_->generate(nickname, role);
        {
            std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
            active_sessions_[token_out] = fd;
        }
        return ErrorCode::ERR_OK;
    }

    ErrorCode AuthManager::reconnectWithToken(const std::string &token, int new_fd, std::string &nickname_out)
    {
        auto claims = token_manager_->validate(token);
        if (!claims.valid) {
            return ErrorCode::ERR_AUTH_FAILED;
        }

        if (isAccountLocked(claims.sub)) {
            return ErrorCode::ERR_AUTH_TOO_MANY_ATTEMPTS;
        }

        nickname_out = claims.sub;

        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
        active_sessions_[token] = new_fd;
        return ErrorCode::ERR_OK;
    }

    AuthManager::ValidationResult AuthManager::validateToken(const std::string &token) const
    {
        auto claims = token_manager_->validate(token);
        if (!claims.valid)
            return {-1, false};

        std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
        auto it = active_sessions_.find(token);
        if (it == active_sessions_.end())
            return {-1, false};
        return {it->second, true};
    }

    void AuthManager::revokeToken(const std::string &token)
    {
        token_manager_->revoke(token);
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
        active_sessions_.erase(token);
    }

    void AuthManager::removeSessionByFd(int fd)
    {
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
        for (auto it = active_sessions_.begin(); it != active_sessions_.end();)
        {
            if (it->second == fd)
            {
                it = active_sessions_.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    bool AuthManager::isNicknameTaken(const std::string &nickname) const
    {
        const char *sql = "SELECT 1 FROM Users WHERE nickname = ? LIMIT 1;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return false;

        sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_TRANSIENT);
        bool found = (sqlite3_step(stmt) == SQLITE_ROW);
        sqlite3_finalize(stmt);
        return found;
    }

    SessionToken::Role AuthManager::getUserRole(const std::string &nickname) const
    {
        const char *sql = "SELECT role FROM Users WHERE nickname = ? LIMIT 1;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return SessionToken::Role::GUEST;

        sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_TRANSIENT);
        SessionToken::Role role = SessionToken::Role::GUEST;
        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            std::string s(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
            role = SessionToken::stringToRole(s);
        }
        sqlite3_finalize(stmt);
        return role;
    }

    void AuthManager::incrementFailedAttempts(const std::string &nickname)
    {
        const char *sql =
            "UPDATE Users SET failed_attempts = failed_attempts + 1, "
            "locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END "
            "WHERE nickname = ?;";

        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return;

        time_t lock_time = std::time(nullptr) + LOCKOUT_SECONDS;
        sqlite3_bind_int(stmt, 1, MAX_FAILED_ATTEMPTS);
        sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(lock_time));
        sqlite3_bind_text(stmt, 3, nickname.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    void AuthManager::resetFailedAttempts(const std::string &nickname)
    {
        const char *sql =
            "UPDATE Users SET failed_attempts = 0, locked_until = 0 WHERE nickname = ?;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return;
        sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    bool AuthManager::isAccountLocked(const std::string &nickname) const
    {
        const char *sql =
            "SELECT locked_until, failed_attempts FROM Users WHERE nickname = ? LIMIT 1;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return false;

        sqlite3_bind_text(stmt, 1, nickname.c_str(), -1, SQLITE_TRANSIENT);
        bool locked = false;
        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            time_t locked_until = static_cast<time_t>(sqlite3_column_int64(stmt, 0));
            int failed_attempts = sqlite3_column_int(stmt, 1);
            if (failed_attempts >= MAX_FAILED_ATTEMPTS && std::time(nullptr) < locked_until)
            {
                locked = true;
            }
        }
        sqlite3_finalize(stmt);
        return locked;
    }

    ErrorCode AuthManager::createRoomDb(const std::string& room_name, const std::string& password, const std::string& creator_nick) {
        std::string hash = "";
        std::string salt_hex = "";

        if (!password.empty()) {
            std::string pwd = password;
            auto salt = vcs::crypto::SHA256Hash::generateSalt();
            hash = vcs::crypto::SHA256Hash::pbkdf2(pwd, salt);
            salt_hex = vcs::crypto::SHA256Hash::toHex(salt.data(), salt.size());
        }

        const char *sql = "INSERT INTO Rooms (room_name, password_hash, salt, creator_nick, created_at) VALUES (?, ?, ?, ?, ?);";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return ErrorCode::ERR_INTERNAL;

        time_t now = std::time(nullptr);
        sqlite3_bind_text(stmt, 1, room_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, salt_hex.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, creator_nick.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(now));

        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return (rc == SQLITE_DONE) ? ErrorCode::ERR_OK : ErrorCode::ERR_INTERNAL;
    }

    ErrorCode AuthManager::verifyRoomPasswordDb(const std::string& room_name, const std::string& password) {
        const char *sql = "SELECT password_hash, salt FROM Rooms WHERE room_name = ? LIMIT 1;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return ErrorCode::ERR_INTERNAL;

        sqlite3_bind_text(stmt, 1, room_name.c_str(), -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return ErrorCode::ERR_ROOM_NOT_FOUND;
        }

        std::string stored_hash(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
        std::string salt_hex(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)));
        sqlite3_finalize(stmt);

        if (stored_hash.empty()) return ErrorCode::ERR_OK; // No password required
        if (password.empty()) return ErrorCode::ERR_AUTH_FAILED; // Password required but empty

        auto salt_bytes_vec = vcs::crypto::SHA256Hash::fromHex(salt_hex);
        vcs::crypto::SHA256Hash::SaltBytes salt{};
        std::copy_n(salt_bytes_vec.begin(), std::min(salt_bytes_vec.size(), salt.size()), salt.begin());

        std::string pwd = password;
        std::string computed_hash = vcs::crypto::SHA256Hash::pbkdf2(pwd, salt);
        bool match = (computed_hash.size() == stored_hash.size()) && (CRYPTO_memcmp(computed_hash.data(), stored_hash.data(), computed_hash.size()) == 0);

        return match ? ErrorCode::ERR_OK : ErrorCode::ERR_AUTH_FAILED;
    }

    ErrorCode AuthManager::deleteRoomDb(const std::string& room_name) {
        const char *sql = "DELETE FROM Rooms WHERE room_name = ?;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return ErrorCode::ERR_INTERNAL;

        sqlite3_bind_text(stmt, 1, room_name.c_str(), -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return (rc == SQLITE_DONE) ? ErrorCode::ERR_OK : ErrorCode::ERR_INTERNAL;
    }

    std::string AuthManager::getRoomCreatorDb(const std::string& room_name) {
        const char *sql = "SELECT creator_nick FROM Rooms WHERE room_name = ? LIMIT 1;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return "";

        sqlite3_bind_text(stmt, 1, room_name.c_str(), -1, SQLITE_TRANSIENT);

        std::string creator = "";
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            creator = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
        }
        sqlite3_finalize(stmt);
        return creator;
    }

    std::vector<AuthManager::RoomData> AuthManager::loadAllRoomsFromDb() {
        std::vector<RoomData> rooms;
        const char *sql = "SELECT room_name, creator_nick, password_hash FROM Rooms;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return rooms;

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            RoomData r;
            r.name = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
            r.creator = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)));
            std::string pass_hash = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2)));
            r.has_password = !pass_hash.empty();
            rooms.push_back(r);
        }
        sqlite3_finalize(stmt);
        return rooms;
    }

    ErrorCode AuthManager::banUserFromRoomDb(const std::string& room_name, const std::string& nickname) {
        const char *sql = "INSERT OR IGNORE INTO RoomBans (room_name, nickname, created_at) VALUES (?, ?, strftime('%s','now'));";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return ErrorCode::ERR_INTERNAL;
        sqlite3_bind_text(stmt, 1, room_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, nickname.c_str(), -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return (rc == SQLITE_DONE) ? ErrorCode::ERR_OK : ErrorCode::ERR_INTERNAL;
    }

    ErrorCode AuthManager::unbanUserFromRoomDb(const std::string& room_name, const std::string& nickname) {
        const char *sql = "DELETE FROM RoomBans WHERE room_name = ? AND nickname = ?;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return ErrorCode::ERR_INTERNAL;
        sqlite3_bind_text(stmt, 1, room_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, nickname.c_str(), -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return (rc == SQLITE_DONE) ? ErrorCode::ERR_OK : ErrorCode::ERR_INTERNAL;
    }

    std::vector<std::string> AuthManager::getBannedUsersForRoomDb(const std::string& room_name) {
        std::vector<std::string> banned;
        const char *sql = "SELECT nickname FROM RoomBans WHERE room_name = ?;";
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return banned;
        sqlite3_bind_text(stmt, 1, room_name.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            banned.push_back(std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0))));
        }
        sqlite3_finalize(stmt);
        return banned;
    }
}