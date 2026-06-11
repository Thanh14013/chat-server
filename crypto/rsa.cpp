#include "rsa.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>

namespace vcs::crypto
{
    static std::string opensslLastError()
    {
        unsigned long err = ERR_get_error();
        if (err == 0)
            return "unknown OpenSSL error";
        char buf[256]{};
        ERR_error_string_n(err, buf, sizeof(buf));
        return std::string(buf);
    }

    RSA2048::RSA2048() = default;

    RSA2048::~RSA2048()
    {
        if (pkey_)
        {
            EVP_PKEY_free(pkey_);
            pkey_ = nullptr;
        }
    }

    RSA2048::RSA2048(RSA2048 &&other) noexcept
        : pkey_(other.pkey_), has_private_(other.has_private_)
    {
        other.pkey_ = nullptr;
        other.has_private_ = false;
    }

    RSA2048 &RSA2048::operator=(RSA2048 &&other) noexcept
    {
        if (this != &other)
        {
            if (pkey_)
                EVP_PKEY_free(pkey_);
            pkey_ = other.pkey_;
            has_private_ = other.has_private_;
            other.pkey_ = nullptr;
            other.has_private_ = false;
        }
        return *this;
    }

    void RSA2048::generateKeyPair()
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx)
            throw std::runtime_error("RSA2048::generateKeyPair: EVP_PKEY_CTX_new_id failed");

        if (EVP_PKEY_keygen_init(ctx) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("RSA2048::generateKeyPair: keygen_init failed");
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_BITS) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("RSA2048::generateKeyPair: set_rsa_keygen_bits failed");
        }

        if (pkey_)
            EVP_PKEY_free(pkey_);
        pkey_ = nullptr;

        if (EVP_PKEY_keygen(ctx, &pkey_) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("RSA2048::generateKeyPair: keygen failed — " + opensslLastError());
        }

        EVP_PKEY_CTX_free(ctx);
        has_private_ = true;
    }

    std::string RSA2048::getPublicKeyPEM() const
    {
        if (!pkey_)
            throw std::runtime_error("RSA2048::getPublicKeyPEM: no key loaded");

        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio)
            throw std::runtime_error("RSA2048::getPublicKeyPEM: BIO_new failed");

        if (PEM_write_bio_PUBKEY(bio, pkey_) != 1)
        {
            BIO_free(bio);
            throw std::runtime_error("RSA2048::getPublicKeyPEM: PEM_write_bio_PUBKEY failed");
        }

        char *pem_data = nullptr;
        long pem_len = BIO_get_mem_data(bio, &pem_data);
        std::string pem(pem_data, static_cast<size_t>(pem_len));
        BIO_free(bio);
        return pem;
    }

    void RSA2048::loadPublicKeyPEM(const std::string &pem)
    {
        BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (!bio)
            throw std::runtime_error("RSA2048::loadPublicKeyPEM: BIO_new_mem_buf failed");

        if (pkey_)
            EVP_PKEY_free(pkey_);
        pkey_ = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey_)
        {
            throw std::runtime_error("RSA2048::loadPublicKeyPEM: invalid PEM — " + opensslLastError());
        }
        has_private_ = false;
    }

    std::vector<uint8_t> RSA2048::encrypt(const std::vector<uint8_t> &plaintext) const
    {
        if (!pkey_)
            throw std::runtime_error("RSA2048::encrypt: no public key loaded");

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
        if (!ctx)
            throw std::runtime_error("RSA2048::encrypt: EVP_PKEY_CTX_new failed");

        if (EVP_PKEY_encrypt_init(ctx) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("RSA2048::encrypt: encrypt_init failed");
        }

        // OAEP padding — protects against Bleichenbacher attack
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("RSA2048::encrypt: set_rsa_padding (OAEP) failed");
        }

        // Determine output length
        size_t out_len = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &out_len,
                             plaintext.data(), plaintext.size()) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("RSA2048::encrypt: size query failed");
        }

        std::vector<uint8_t> ciphertext(out_len);
        if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &out_len,
                             plaintext.data(), plaintext.size()) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("RSA2048::encrypt: encryption failed — " + opensslLastError());
        }

        ciphertext.resize(out_len);
        EVP_PKEY_CTX_free(ctx);
        return ciphertext;
    }

    std::vector<uint8_t> RSA2048::decrypt(const std::vector<uint8_t> &ciphertext) const
    {
        if (!pkey_ || !has_private_)
        {
            throw std::runtime_error("RSA2048::decrypt: private key not available");
        }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
        if (!ctx)
            throw std::runtime_error("RSA2048::decrypt: EVP_PKEY_CTX_new failed");

        if (EVP_PKEY_decrypt_init(ctx) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("RSA2048::decrypt: decrypt_init failed");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("RSA2048::decrypt: set_rsa_padding (OAEP) failed");
        }

        size_t out_len = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &out_len,
                             ciphertext.data(), ciphertext.size()) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("RSA2048::decrypt: size query failed");
        }

        std::vector<uint8_t> plaintext(out_len);
        if (EVP_PKEY_decrypt(ctx, plaintext.data(), &out_len,
                             ciphertext.data(), ciphertext.size()) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("RSA2048::decrypt: decryption failed — " + opensslLastError());
        }

        plaintext.resize(out_len);
        EVP_PKEY_CTX_free(ctx);
        return plaintext;
    }
    
    bool RSA2048::hasPrivateKey() const { return pkey_ && has_private_; }
    bool RSA2048::hasPublicKey()  const { return pkey_ != nullptr; }
}