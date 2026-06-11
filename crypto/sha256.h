#pragma once
#include <string>
#include <vector>
#include <array>
#include <cstdint>

namespace vcs::crypto
{
    class SHA256Hash
    {
    public:
        static constexpr size_t HASH_LEN = 32;
        static constexpr size_t SALT_LEN = 16;
        static constexpr int PBKDF2_ITERATIONS = 100'000;

        using HashBytes = std::array<uint8_t, HASH_LEN>;
        using SaltBytes = std::array<uint8_t, SALT_LEN>;

        static std::string hash(const std::vector<uint8_t> &data);

        static std::string hash(const std::string &data);

        static std::string hashFile(const std::string &filePath);

        static std::string pbkdf2(std::vector<uint8_t> &password, const SaltBytes &salt, int iterations = PBKDF2_ITERATIONS);

        static std::string pbkdf2(std::string &password, const SaltBytes &salt, int iterations = PBKDF2_ITERATIONS);

        static SaltBytes generateSalt();

        /** Convert raw bytes to lowercase hex string. */
        static std::string toHex(const uint8_t *data, size_t len);
        static std::string toHex(const std::vector<uint8_t> &data);

        /** Convert hex string back to bytes. */
        static std::vector<uint8_t> fromHex(const std::string &hex);
    };
}