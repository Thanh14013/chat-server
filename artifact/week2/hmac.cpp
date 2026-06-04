#include "hmac.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include <stdexcept>
#include <cstring>

namespace vcs::crypto {

// ── compute ───────────────────────────────────────────────────────────────────

std::vector<uint8_t> HMACSHA256::compute(const std::vector<uint8_t>& data,
                                          const std::vector<uint8_t>& key) {
    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int  digest_len = 0;

    // Fresh HMAC_CTX per call — ensures thread safety
    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx) throw std::runtime_error("HMACSHA256::compute: HMAC_CTX_new failed");

    if (HMAC_Init_ex(ctx, key.data(), static_cast<int>(key.size()),
                     EVP_sha256(), nullptr) != 1 ||
        HMAC_Update(ctx, data.data(), data.size())                  != 1 ||
        HMAC_Final(ctx, digest, &digest_len)                        != 1) {
        HMAC_CTX_free(ctx);
        throw std::runtime_error("HMACSHA256::compute: HMAC operation failed");
    }

    HMAC_CTX_free(ctx);
    return std::vector<uint8_t>(digest, digest + digest_len);
}

std::vector<uint8_t> HMACSHA256::compute(const std::string&           data,
                                          const std::vector<uint8_t>& key) {
    const std::vector<uint8_t> data_bytes(data.begin(), data.end());
    return compute(data_bytes, key);
}

// ── verify (constant-time) ────────────────────────────────────────────────────

bool HMACSHA256::verify(const std::vector<uint8_t>& data,
                         const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& expected) {
    auto computed = compute(data, key);

    if (computed.size() != expected.size()) return false;

    // CRYPTO_memcmp is OpenSSL's constant-time comparison.
    // Do NOT use memcmp() or std::equal() — they short-circuit and leak timing.
    return CRYPTO_memcmp(computed.data(), expected.data(), computed.size()) == 0;
}

bool HMACSHA256::verify(const std::string&           data,
                         const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& expected) {
    const std::vector<uint8_t> data_bytes(data.begin(), data.end());
    return verify(data_bytes, key, expected);
}

} // namespace vcs::crypto
