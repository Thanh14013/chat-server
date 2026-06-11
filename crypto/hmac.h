#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace vcs::crypto{
    class HMACSHA256{
        public:
            static constexpr size_t DIGEST_LEN = 32;

            static std::vector<uint8_t> compute(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);

            static std::vector<uint8_t> compute(const std::string& data, const std::vector<uint8_t>& key);

            static bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& expected);

            static bool verify(const std::string& data,const std::vector<uint8_t>& key, const std::vector<uint8_t>& expected);
    };
}