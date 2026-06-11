#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

typedef struct evp_pkey_st EVP_PKEY;

namespace vcs::crypto
{
    class RSA2048
    {
    public:
        static constexpr int KEY_BITS = 2048;

        RSA2048();
        ~RSA2048();

        RSA2048(const RSA2048 &) = delete;
        RSA2048 &operator=(const RSA2048 &) = delete;

        RSA2048(RSA2048 &&) noexcept;
        RSA2048 &operator=(RSA2048 &&) noexcept;

        // ── Server-side ──────────────────────────────────────────────────────────
        void generateKeyPair();

        std::string getPublicKeyPEM() const;

        std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) const;

        // ── Client-side ──────────────────────────────────────────────────────────
        void loadPublicKeyPEM(const std::string& pem);

        std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) const;

        // ── Utility ──────────────────────────────────────────────────────────────
        bool hasPrivateKey() const;
        bool hasPublicKey() const;

    private:
        EVP_PKEY* pkey_ = nullptr;
        bool has_private_ = false;
    };
}