#include "aes.h"
#include "random.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>
#include <cassert>

namespace vcs::crypto
{
    AES256GCM::AES256GCM(const KeyBytes &key) : key_(key) {}

    AES256GCM::AES256GCM(const std::vector<uint8_t> &key)
    {
        if (key.size() != KEY_LEN)
        {
            throw std::runtime_error("AES256GCM: key must be exactly 32 bytes");
        }
        std::copy(key.begin(), key.end(), key_.begin());
    }

    AES256GCM::~AES256GCM()
    {
        OPENSSL_cleanse(key_.data(), KEY_LEN);
    }

    AES256GCM::AES256GCM(AES256GCM &&other) noexcept : key_(other.key_)
    {
        OPENSSL_cleanse(other.key_.data(), KEY_LEN);
    }

    AES256GCM &AES256GCM::operator=(AES256GCM &&other) noexcept
    {
        if (this != &other)
        {
            key_ = other.key_;
            OPENSSL_cleanse(other.key_.data(), KEY_LEN);
        }
        return *this;
    }

    std::vector<uint8_t> AES256GCM::encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &aad) const
    {

        IVBytes iv = generateIV();

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            throw std::runtime_error("AES256GCM::encrypt: EVP_CIPHER_CTX_new failed");

        std::vector<uint8_t> output;
        output.reserve(IV_LEN + plaintext.size() + TAG_LEN);

        output.insert(output.end(), iv.begin(), iv.end());

        try
        {
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
                throw std::runtime_error("EVP_EncryptInit_ex (cipher) failed");

            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1)
                throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");

            if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), iv.data()) != 1)
                throw std::runtime_error("EVP_EncryptInit_ex (key/iv) failed");

            if (!aad.empty())
            {
                int aad_len = 0;
                if (EVP_EncryptUpdate(ctx, nullptr, &aad_len,
                                      aad.data(), static_cast<int>(aad.size())) != 1)
                    throw std::runtime_error("EVP_EncryptUpdate (AAD) failed");
            }

            std::vector<uint8_t> ciphertext(plaintext.size());
            int out_len = 0;
            if (!plaintext.empty())
            {
                if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                                      plaintext.data(), static_cast<int>(plaintext.size())) != 1)
                    throw std::runtime_error("EVP_EncryptUpdate (data) failed");
            }

            // Finalise (GCM produces no extra output here)
            int final_len = 0;
            if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1)
                throw std::runtime_error("EVP_EncryptFinal_ex failed");

            output.insert(output.end(), ciphertext.begin(), ciphertext.begin() + out_len + final_len);

            // Extract 16-byte GCM authentication tag
            std::array<uint8_t, TAG_LEN> tag{};
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data()) != 1)
                throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");

            output.insert(output.end(), tag.begin(), tag.end());
        }
        catch (...)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }
        EVP_CIPHER_CTX_free(ctx);
        return output;
    }

    std::vector<uint8_t> AES256GCM::decrypt(const std::vector<uint8_t> &ciphertext,
                                            const std::vector<uint8_t> &aad) const
    {
        // Minimum: IV(16) + empty plaintext + TAG(16)
        if (ciphertext.size() < IV_LEN + TAG_LEN)
        {
            throw std::runtime_error("AES256GCM::decrypt: input too short");
        }

        // Extract IV from front
        IVBytes iv{};
        std::copy(ciphertext.begin(), ciphertext.begin() + IV_LEN, iv.begin());

        // Extract tag from back
        std::array<uint8_t, TAG_LEN> tag{};
        std::copy(ciphertext.end() - TAG_LEN, ciphertext.end(), tag.begin());

        // Middle portion is the actual ciphertext
        size_t enc_len = ciphertext.size() - IV_LEN - TAG_LEN;
        const uint8_t *enc_data = ciphertext.data() + IV_LEN;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            throw std::runtime_error("AES256GCM::decrypt: EVP_CIPHER_CTX_new failed");

        std::vector<uint8_t> plaintext(enc_len);

        try
        {
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
                throw std::runtime_error("EVP_DecryptInit_ex (cipher) failed");

            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1)
                throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");

            if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), iv.data()) != 1)
                throw std::runtime_error("EVP_DecryptInit_ex (key/iv) failed");

            // Feed AAD
            if (!aad.empty())
            {
                int aad_out = 0;
                if (EVP_DecryptUpdate(ctx, nullptr, &aad_out,
                                      aad.data(), static_cast<int>(aad.size())) != 1)
                    throw std::runtime_error("EVP_DecryptUpdate (AAD) failed");
            }

            // Decrypt
            int out_len = 0;
            if (enc_len > 0)
            {
                if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                                      enc_data, static_cast<int>(enc_len)) != 1)
                    throw std::runtime_error("EVP_DecryptUpdate (data) failed");
            }

            // Set expected tag before final verification
            // Cast away const — OpenSSL API requires non-const pointer but does not modify
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                                    const_cast<uint8_t *>(tag.data())) != 1)
                throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");

            // EVP_DecryptFinal_ex returns 1 on tag match, 0 on tampering
            int final_len = 0;
            if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) != 1)
            {
                throw std::runtime_error("AES256GCM::decrypt: authentication tag mismatch — packet tampered");
            }

            plaintext.resize(out_len + final_len);
        }
        catch (...)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }

        EVP_CIPHER_CTX_free(ctx);
        return plaintext;
    }
    AES256GCM::KeyBytes AES256GCM::generateKey()
    {
        KeyBytes key{};
        CSPRNG::getInstance().getBytes(key.data(), KEY_LEN);
        return key;
    }

    AES256GCM::IVBytes AES256GCM::generateIV()
    {
        IVBytes iv{};
        CSPRNG::getInstance().getBytes(iv.data(), IV_LEN);
        return iv;
    }
}
