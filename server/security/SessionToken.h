#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <cstdint>
#include <ctime>

namespace vcs::security{
    class SessionToken{
        public:
            static constexpr int SESSION_LIFETIME_SEC = 3600;
            enum class Role { GUEST, USER, ADMIN, OWNER };

            struct Claims{
                std::string sub;
                Role role;
                time_t iat;
                time_t exp;
                std::string jti; //JWT ID
                bool valid;
                bool expired;
            };

            explicit SessionToken(std::vector<uint8_t> secret_key);

            SessionToken(const SessionToken&)            = delete;
            SessionToken& operator=(const SessionToken&) = delete;

            std::string generate(const std::string& nickname, Role role) const;

            Claims validate(const std::string& token_string) const;

            void revoke(const std::string& token_string);

            bool isRevoked(const std::string& jti) const;

            static std::string roleToString(Role r);
            static Role stringToRole(const std::string& s);
        
        private:
            std::vector<uint8_t> secret_key_;
            mutable std::mutex blacklist_mutex_;
            std::unordered_set<std::string> blacklist_;

            static std::string base64urlEncode(const std::vector<uint8_t>& data);
            static std::vector<uint8_t> base64urlDecode(const std::string& encoded);
            static std::string base64urlEncode(const std::string& data);
            static std::string generateJTI();
    };
}