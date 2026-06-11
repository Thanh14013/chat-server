#pragma once
#include <vector>
#include <array>
#include <stdexcept>
#include <cstdint>
#include <cstddef>

namespace vcs::crypto {
    class AES256GCM{
        public:
            static constexpr size_t KEY_LEN = 32;
            static constexpr size_t IV_LEN = 16;
            static constexpr size_t TAG_LEN = 16;

            using KeyBytes = std::array<uint8_t, KEY_LEN>;
            using IVBytes = std::array<uint8_t, IV_LEN>;

            explicit AES256GCM(const KeyBytes& key);

            explicit AES256GCM(const std::vector<uint8_t>& key);

            ~AES256GCM();

            AES256GCM(const AES256GCM&) = delete;
            AES256GCM& operator=(const AES256GCM&) = delete;

            AES256GCM(AES256GCM&&) noexcept;
            AES256GCM& operator=(AES256GCM&&) noexcept;

            std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad = {}) const;

            std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& aad ={}) const;

            static KeyBytes generateKey();

            static IVBytes generateIV();
        
        private:
            KeyBytes key_;
    };
}