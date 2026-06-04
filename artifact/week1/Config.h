#pragma once
#include <string>
#include <cstdint>

struct ServerConfig {
    uint16_t    port                  = 9000;
    int         max_clients           = 256;
    int         thread_pool_size      = 32;
    int         session_timeout_sec   = 3600;

    bool        require_auth          = false;
    int         max_auth_attempts     = 5;
    int         rate_limit_msg_per_sec= 10;
    bool        enable_encryption     = false;
    bool        enable_audit_log      = true;

    std::string default_room          = "general";
    int         max_rooms             = 32;
    int         history_size          = 100;

    std::string admin_password_hash   = "";
};

class Config {
public:
    static Config& instance();

    bool load(const std::string& path);
    const ServerConfig& get() const;

private:
    Config() = default;
    ServerConfig m_cfg;
};
