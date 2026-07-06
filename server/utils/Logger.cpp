#include "Logger.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <sys/stat.h>
#include <thread>

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

Logger::Logger() : m_level(LogLevel::INFO), m_logDir("logs") {}

Logger::~Logger() {
    if (m_file.is_open()) m_file.close();
}

void Logger::setLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_level = level;
}

void Logger::setLogDir(const std::string& dir) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logDir = dir;
    mkdir(dir.c_str(), 0755);
}

std::string Logger::currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto tt  = std::chrono::system_clock::to_time_t(now);
    auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&tt), "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setw(3) << std::setfill('0') << ms.count();
    return oss.str();
}

std::string Logger::currentDateStr() {
    auto now = std::chrono::system_clock::now();
    auto tt  = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&tt), "%Y%m%d");
    return oss.str();
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:    return "DEBUG";
        case LogLevel::INFO:     return "INFO ";
        case LogLevel::WARN:     return "WARN ";
        case LogLevel::ERROR:    return "ERROR";
        case LogLevel::CRITICAL: return "CRIT ";
        default:                 return "?????";
    }
}

void Logger::rotateIfNeeded() {
    std::string today = currentDateStr();
    if (today == m_currentDate && m_file.is_open()) return;

    if (m_file.is_open()) m_file.close();
    m_currentDate = today;

    std::string path = m_logDir + "/server_" + today + ".log";
    m_file.open(path, std::ios::app);
}

void Logger::log(LogLevel level, const std::string& msg) {
    if (level < m_level) return;

    std::ostringstream oss;
    std::thread::id tid = std::this_thread::get_id(); // Kept just in case it's used elsewhere, but we won't output it
    oss << "[" << currentTimestamp() << "]"
        << " [" << levelToString(level) << "] "
        << msg;

    std::string line = oss.str();

    std::lock_guard<std::mutex> lock(m_mutex);
    std::cout << line << "\n";
    rotateIfNeeded();
    if (m_file.is_open()) {
        m_file << line << "\n";
        m_file.flush();
    }
}

void Logger::debug(const std::string& msg)    { log(LogLevel::DEBUG,    msg); }
void Logger::info(const std::string& msg)     { log(LogLevel::INFO,     msg); }
void Logger::warn(const std::string& msg)     { log(LogLevel::WARN,     msg); }
void Logger::error(const std::string& msg)    { log(LogLevel::ERROR,    msg); }
void Logger::critical(const std::string& msg) { log(LogLevel::CRITICAL, msg); }
