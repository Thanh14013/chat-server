#include "Database.h"
#include "Logger.h"

Database &Database::instance()
{
    static Database inst;
    return inst;
}
Database::Database() : m_db(nullptr), m_open(false) {}

Database::~Database()
{
    close();
}

bool Database::open(const std::string &path)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    int rc = sqlite3_open(path.c_str(), &m_db);
    if (rc != SQLITE_OK)
    {
        LOG_ERROR("Failed to open database: " + std::string(sqlite3_errmsg(m_db)));
        return false;
    }
    sqlite3_exec(m_db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
    m_open = true;
    LOG_INFO("Database opened: " + path);
    return createTables();
}

void Database::close()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_db)
    {
        sqlite3_close(m_db);
        m_db = nullptr;
        m_open = false;
    }
}

bool Database::isOpen() const
{
    return m_open;
}

bool Database::execute(const std::string &sql)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    char *errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK)
    {
        LOG_ERROR("SQL error: " + std::string(errMsg));
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

sqlite3 *Database::handle()
{
    return m_db;
}

bool Database::createTables()
{
    const std::string sql = R"(
        CREATE TABLE IF NOT EXISTS Users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname      TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            salt          TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'USER',
            created_at    INTEGER NOT NULL,
            last_login    INTEGER,
            failed_attempts INTEGER DEFAULT 0,
            locked_until  INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS ChatHistory (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            sender    TEXT    NOT NULL,
            room      TEXT    NOT NULL,
            message   TEXT    NOT NULL,
            msg_type  TEXT    NOT NULL DEFAULT 'CHAT'
        );

        CREATE TABLE IF NOT EXISTS AuditLog (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id   TEXT    NOT NULL,
            timestamp  INTEGER NOT NULL,
            event_type TEXT    NOT NULL,
            actor      TEXT,
            target     TEXT,
            action     TEXT    NOT NULL,
            result     TEXT    NOT NULL,
            ip_address TEXT,
            details    TEXT,
            prev_hash  TEXT    NOT NULL,
            hash       TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_chat_room_ts ON ChatHistory(room, timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_ts     ON AuditLog(timestamp);
    )";

    char *errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK)
    {
        LOG_ERROR("Failed to create tables: " + std::string(errMsg));
        sqlite3_free(errMsg);
        return false;
    }
    LOG_INFO("Database tables ready.");
    return true;
}