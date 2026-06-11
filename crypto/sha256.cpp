#include "sha256.h"
#include "random.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>

namespace vcs::crypto
{
    static std::string bytesToHex(const uint8_t *data, size_t len)
    {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; ++i)
            ss << std::setw(2) << static_cast<unsigned>(data[i]);
        return ss.str();
    }

    std::string SHA256Hash::hash(const std::vector<uint8_t> &data)
    {
        uint8_t digest[SHA256_DIGEST_LENGTH]{};
        if (!SHA256(data.data(), data.size(), digest))
        {
            throw std::runtime_error("SHA256Hash::hash: SHA256() failed");
        }
        return bytesToHex(digest, SHA256_DIGEST_LENGTH);
    }

    std::string SHA256Hash::hash(const std::string &data)
    {
        const std::vector<uint8_t> bytes(data.begin(), data.end());
        return hash(bytes);
    }

    std::string SHA256Hash::hashFile(const std::string &filepath)
    {
        std::ifstream file(filepath, std::ios::binary);
        if (!file)
            throw std::runtime_error("SHA256Hash::hashFile: cannot open " + filepath);

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
            throw std::runtime_error("SHA256Hash::hashFile: EVP_MD_CTX_new failed");

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA256Hash::hashFile: DigestInit failed");
        }

        char buf[8192];
        while (file.read(buf, sizeof(buf)) || file.gcount() > 0)
        {
            if (EVP_DigestUpdate(ctx, buf, static_cast<size_t>(file.gcount())) != 1)
            {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("SHA256Hash::hashFile: DigestUpdate failed");
            }
        }

        uint8_t digest[EVP_MAX_MD_SIZE]{};
        unsigned int dlen = 0;
        if (EVP_DigestFinal_ex(ctx, digest, &dlen) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA256Hash::hashFile: DigestFinal failed");
        }

        EVP_MD_CTX_free(ctx);
        return bytesToHex(digest, dlen);
    }

    std::string SHA256Hash::pbkdf2(std::vector<uint8_t> &password,
                                   const SaltBytes &salt,
                                   int iterations)
    {
        uint8_t derived[HASH_LEN]{};

        int rc = PKCS5_PBKDF2_HMAC(
            reinterpret_cast<const char *>(password.data()),
            static_cast<int>(password.size()),
            salt.data(),
            static_cast<int>(salt.size()),
            iterations,
            EVP_sha256(),
            static_cast<int>(HASH_LEN),
            derived);

        // CRITICAL: scrub plaintext password from RAM immediately after hashing
        // Prevents recovery from memory dumps
        OPENSSL_cleanse(password.data(), password.size());

        if (rc != 1)
        {
            throw std::runtime_error("SHA256Hash::pbkdf2: PKCS5_PBKDF2_HMAC failed");
        }

        return bytesToHex(derived, HASH_LEN);
    }

    std::string SHA256Hash::pbkdf2(std::string &password,
                                   const SaltBytes &salt,
                                   int iterations)
    {
        uint8_t derived[HASH_LEN]{};

        int rc = PKCS5_PBKDF2_HMAC(
            password.data(),
            static_cast<int>(password.size()),
            salt.data(),
            static_cast<int>(salt.size()),
            iterations,
            EVP_sha256(),
            static_cast<int>(HASH_LEN),
            derived);

        // CRITICAL: scrub plaintext password
        OPENSSL_cleanse(password.data(), password.size());
        password.clear();

        if (rc != 1)
        {
            throw std::runtime_error("SHA256Hash::pbkdf2: PKCS5_PBKDF2_HMAC failed");
        }

        return bytesToHex(derived, HASH_LEN);
    }

    // ── Salt generation ───────────────────────────────────────────────────────────

    SHA256Hash::SaltBytes SHA256Hash::generateSalt()
    {
        SaltBytes salt{};
        CSPRNG::getInstance().getBytes(salt.data(), SALT_LEN);
        return salt;
    }

    // ── Encoding helpers ──────────────────────────────────────────────────────────

    std::string SHA256Hash::toHex(const uint8_t *data, size_t len)
    {
        return bytesToHex(data, len);
    }

    std::string SHA256Hash::toHex(const std::vector<uint8_t> &data)
    {
        return bytesToHex(data.data(), data.size());
    }

    std::vector<uint8_t> SHA256Hash::fromHex(const std::string &hex)
    {
        if (hex.size() % 2 != 0)
            throw std::runtime_error("SHA256Hash::fromHex: odd hex length");
        std::vector<uint8_t> out;
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2)
        {
            unsigned byte = 0;
            std::istringstream ss(hex.substr(i, 2));
            ss >> std::hex >> byte;
            out.push_back(static_cast<uint8_t>(byte));
        }
        return out;
    }
}