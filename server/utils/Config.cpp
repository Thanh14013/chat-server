#include "Config.h"
#include "Logger.h"
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

Config& Config::instance(){
    static Config inst;
    return inst;
}

const ServerConfig& Config::get() const {
    return m_cfg;
}

bool Config::load(const std::string& path){
    std::ifstream f(path);
    if (!f.is_open()){
        LOG_WARN("Config file not found: " + path + ". Using defaults.");
        return false;
    }

    try {
        json j = json::parse(f);

        if (j.contains("server")) {
            auto& s =j["server"];
            m_cfg.port               = s.value("port", m_cfg.port);
            m_cfg.max_clients        = s.value("max_clients", m_cfg.max_clients);
            m_cfg.thread_pool_size   = s.value("thread_pool_size", m_cfg.thread_pool_size);
            m_cfg.session_timeout_sec= s.value("session_timeout_seconds", m_cfg.session_timeout_sec);
        }
        
        if (j.contains("security")) {
            auto& s = j["security"];
            m_cfg.require_auth           = s.value("require_auth", m_cfg.require_auth);
            m_cfg.max_auth_attempts      = s.value("max_auth_attempts", m_cfg.max_auth_attempts);
            m_cfg.rate_limit_msg_per_sec = s.value("rate_limit_msg_per_sec", m_cfg.rate_limit_msg_per_sec);
            m_cfg.enable_encryption      = s.value("enable_encryption", m_cfg.enable_encryption);
            m_cfg.enable_audit_log       = s.value("enable_audit_log", m_cfg.enable_audit_log);
        }

        if (j.contains("rooms")) {
            auto& s = j["rooms"];
            m_cfg.default_room  = s.value("default_room", m_cfg.default_room);
            m_cfg.max_rooms     = s.value("max_rooms", m_cfg.max_rooms);
            m_cfg.history_size  = s.value("history_size", m_cfg.history_size);
        }

        if (j.contains("admin")) {
            m_cfg.admin_password_hash = j["admin"].value("admin_password_hash", "");
        }

        LOG_INFO("Config loaded from: " + path);
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Config parse error: " + std::string(e.what()));
        return false;
    }
}