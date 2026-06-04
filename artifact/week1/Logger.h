#pragma once
#include <string>
#include <mutex>
#include <fstream>

enum class LogLevel {
    DEBUG = 0,
    INFO,
    WARN,
    ERROR,
    CRITICAL
};

class Logger {
public:
    static Logger& instance();

    void setLevel(LogLevel level);
    void setLogDir(const std::string& dir);

    void debug(const std::string& msg);
    void info(const std::string& msg);
    void warn(const std::string& msg);
    void error(const std::string& msg);
    void critical(const std::string& msg);

private:
    Logger();
    ~Logger();

    void log(LogLevel level, const std::string& msg);
    void rotateIfNeeded();
    std::string levelToString(LogLevel level);
    std::string currentTimestamp();
    std::string currentDateStr();

    LogLevel    m_level;
    std::mutex  m_mutex;
    std::ofstream m_file;
    std::string m_logDir;
    std::string m_currentDate;
};

#define LOG_DEBUG(msg)    Logger::instance().debug(msg)
#define LOG_INFO(msg)     Logger::instance().info(msg)
#define LOG_WARN(msg)     Logger::instance().warn(msg)
#define LOG_ERROR(msg)    Logger::instance().error(msg)
#define LOG_CRITICAL(msg) Logger::instance().critical(msg)
