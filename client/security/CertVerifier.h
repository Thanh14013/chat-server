#pragma once
#include <string>
#include <unordered_map>
#include <mutex>

namespace vcs::client{
    class CertVerifier{
        public:
            enum class TrustStatus { TRUSTED, NEW, CHANGED};

            static CertVerifier& getInstance();

            CertVerifier(const CertVerifier&)            = delete;
            CertVerifier& operator=(const CertVerifier&) = delete;
            
            TrustStatus verifyServerKey(const std::string& host, int port, const std::string& pubkey_pem);

            void saveServerKey(const std::string& host, int port, const std::string& pubkey_pem);

            void clearKnownServers();

            static bool promptUserOnChange(const std::string& host, int port, const std::string& old_fp, const std::string& new_fp);
        
        private:
            CertVerifier();

            void loadFromDisk();
            void saveToDisk() const;
            std::string knownServersPath() const;

            static std::string fingerprintOf(const std::string& pybkey_pem);
            static std::string makeKey(const std::string& host, int port);

            mutable std::mutex mutex_;
            std::unordered_map<std::string, std::string> known_servers_;
            bool loaded_ = false;
    };
}