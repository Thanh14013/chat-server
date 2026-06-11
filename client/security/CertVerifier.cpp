#include "CertVerifier.h"
#include "../../crypto/sha256.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <cstdlib>
#include <sys/stat.h>

using json = nlohmann::json;

namespace vcs::client
{
    CertVerifier::CertVerifier() = default;
    CertVerifier &CertVerifier::getInstance()
    {
        static CertVerifier instance;
        return instance;
    }

    std::string CertVerifier::knownServersPath() const
    {
        const char *home = std::getenv("HOME");
        std::string dir = home ? std::string(home) + "/.vcs_chat" : "tmp/.vcs_chat";

        mkdir(dir.c_str(), 755);

        return dir + "/known_servers.json";
    }

    std::string CertVerifier::fingerprintOf(const std::string &pubkey_pem)
    {
        std::string hex = vcs::crypto::SHA256Hash::hash(pubkey_pem);
        return "sha256" + hex;
    }

    std::string CertVerifier::makeKey(const std::string &host, int port)
    {
        return host + ":" + std::to_string(port);
    }

    void CertVerifier::loadFromDisk()
    {
        if (loaded_)
            return;
        loaded_ = true;

        std::ifstream f(knownServersPath());
        if (!f.is_open())
            return;

        try
        {
            json j;
            f >> j;
            for (auto &[key, val] : j.items())
            {
                known_servers_[key] = val.get<std::string>();
            }
        }
        catch (...)
        {
            known_servers_.clear();
        }
    }

    void CertVerifier::saveToDisk() const
    {
        json j;
        for (auto &[key, val] : known_servers_)
        {
            j[key] = val;
        }

        std::ofstream f(knownServersPath(), std::ios::trunc);
        if (!f.is_open())
            return; // best-effort write
        f << j.dump(2) << "\n";
    }

    CertVerifier::TrustStatus CertVerifier::verifyServerKey(const std::string &host, int port, const std::string &pubkey_pem)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        loadFromDisk();

        std::string key = makeKey(host, port);
        std::string fp = fingerprintOf(pubkey_pem);

        auto it = known_servers_.find(key);
        if (it == known_servers_.end())
        {
            known_servers_[key] = fp;
            saveToDisk();
            return TrustStatus::NEW;
        }

        if (it->second == fp)
            return TrustStatus::TRUSTED;

        return TrustStatus::CHANGED;
    }

    void CertVerifier::saveServerKey(const std::string &host, int port, const std::string &pubkey_pem)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        loadFromDisk();

        std::string key = makeKey(host, port);
        known_servers_[key] = fingerprintOf(pubkey_pem);
        saveToDisk();
    }

    void CertVerifier::clearKnownServers()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        known_servers_.clear();
        saveToDisk();
    }

    std::string CertVerifier::getFingerprint(const std::string &host, int port)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        loadFromDisk();
        std::string key = makeKey(host, port);
        auto it = known_servers_.find(key);
        if (it != known_servers_.end()) return it->second;
        return "";
    }

    bool CertVerifier::promptUserOnChange(const std::string &host, int port, const std::string &old_fp, const std::string &new_fp)
    {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║        WARNING: SERVER KEY FINGERPRINT CHANGED!              ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  Host : " << host << ":" << port <<"                         ║\n";
        std::cout << "║  Old  : " << old_fp <<"                                      ║\n";
        std::cout << "║  New  : " << new_fp <<"                                      ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  This could indicate a Man-in-the-Middle attack!             ║\n";
        std::cout << "║                                                              ║\n";
        std::cout << "║  Type /trust to accept new key  (NOT recommended)            ║\n";
        std::cout << "║  Press Enter to disconnect       (recommended)               ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        std::cout << "> ";
        std::cout.flush();

        std::string input;
        if (!std::getline(std::cin, input))
            return false;

        // Trim whitespace
        size_t start = input.find_first_not_of(" \t\r\n");
        if (start != std::string::npos)
            input = input.substr(start);

        return (input == "/trust");
    }
}