#pragma once
#include <string>
#include <mutex>
#include <sqlite3.h>

class Database
{
public:
    static Database &instance();

    bool open(const std::string &path);
    void close();
    bool isOpen() const;

    bool execute(const std::string &sql);
    sqlite3 *handle();

private:
    Database();
    ~Database();

    bool createTables();

    sqlite3 *m_db;
    std::mutex m_mutex;
    bool m_open;
};