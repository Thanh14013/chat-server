#include "SessionToken.h"
#include "../../crypto/hmac.h"
#include "../../crypto/random.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <iomanip>

using json = nlohmann::json;

namespace vcs::security
{
    SessionToken::SessionToken(std::vector<uint8_t> secret_key)
        : secret_key_(std::move(secret_key))
    {
        if (secret_key_.size() < 32)
        {
            throw std::runtime_error("SessionToken: secret_key must be >= 32 bytes");
        }
    }

    std::string SessionToken::roleToString(Role r)
    {
        switch (r)
        {
        case Role::OWNER:
            return "OWNER";
        case Role::ADMIN:
            return "ADMIN";
        case Role::USER:
            return "USER";
        default:
            return "GUEST";
        }
    }

    SessionToken::Role SessionToken::stringToRole(const std::string &s)
    {
        if (s == "OWNER")
            return Role::OWNER;
        if (s == "ADMIN")
            return Role::ADMIN;
        if (s == "USER")
            return Role::USER;
        return Role::GUEST;
    }

    std::string SessionToken::base64urlEncode(const std::vector<uint8_t> &data)
    {
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO *mem = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, mem);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(b64, data.data(), static_cast<int>(data.size()));
        BIO_flush(b64);

        BUF_MEM *bptr;
        BIO_get_mem_ptr(b64, &bptr);
        std::string encoded(bptr->data, bptr->length);
        BIO_free_all(b64);

        // Convert to base64url: replace + with -, / with _, strip =
        std::replace(encoded.begin(), encoded.end(), '+', '-');
        std::replace(encoded.begin(), encoded.end(), '/', '_');
        encoded.erase(std::remove(encoded.begin(), encoded.end(), '='), encoded.end());
        return encoded;
    }

    std::string SessionToken::base64urlEncode(const std::string &data)
    {
        return base64urlEncode(std::vector<uint8_t>(data.begin(), data.end()));
    }

    std::vector<uint8_t> SessionToken::base64urlDecode(const std::string &encoded)
    {
        // Convert base64url back to standard base64
        std::string b64 = encoded;
        std::replace(b64.begin(), b64.end(), '-', '+');
        std::replace(b64.begin(), b64.end(), '_', '/');
        // Re-add padding
        while (b64.size() % 4 != 0)
            b64 += '=';

        BIO *b64_bio = BIO_new(BIO_f_base64());
        BIO *mem_bio = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
        b64_bio = BIO_push(b64_bio, mem_bio);
        BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

        std::vector<uint8_t> out(b64.size());
        int decoded_len = BIO_read(b64_bio, out.data(), static_cast<int>(out.size()));
        BIO_free_all(b64_bio);

        if (decoded_len < 0)
            throw std::runtime_error("SessionToken: base64url decode failed");
        out.resize(static_cast<size_t>(decoded_len));
        return out;
    }

    std::string SessionToken::generateJTI()
    {
        // 16 random bytes → hex string (UUID-like, without dashes for simplicity)
        auto bytes = vcs::crypto::CSPRNG::getInstance().getBytes(16);
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto b : bytes)
            ss << std::setw(2) << static_cast<unsigned>(b);
        return ss.str();
    }

    std::string SessionToken::generate(const std::string &nickname, Role role) const
    {
        time_t now = std::time(nullptr);

        // Header
        json header_json = {
            {"alg", "HMAC-SHA256"},
            {"typ", "VCS-SESSION"}};
        std::string header_b64 = base64urlEncode(header_json.dump());

        // Payload
        json payload_json = {
            {"sub", nickname},
            {"iat", static_cast<int64_t>(now)},
            {"exp", static_cast<int64_t>(now + SESSION_LIFETIME_SEC)},
            {"jti", generateJTI()},
            {"role", roleToString(role)}};
        std::string payload_b64 = base64urlEncode(payload_json.dump());

        // Signing input: header.payload
        std::string signing_input = header_b64 + "." + payload_b64;

        // Signature: HMAC-SHA256(signing_input, secret_key_)
        auto sig_bytes = vcs::crypto::HMACSHA256::compute(signing_input, secret_key_);
        std::string sig_b64 = base64urlEncode(sig_bytes);

        return signing_input + "." + sig_b64;
    }

    SessionToken::Claims SessionToken::validate(const std::string &token_string) const
    {
        Claims result{};
        result.valid = false;
        result.expired = false;

        size_t dot1 = token_string.find('.');
        if (dot1 == std::string::npos)
            return result;
        size_t dot2 = token_string.find('.', dot1 + 1);
        if (dot2 == std::string::npos)
            return result;

        std::string header_b64 = token_string.substr(0, dot1);
        std::string payload_b64 = token_string.substr(dot1 + 1, dot2 - dot1 - 1);
        std::string sig_b64 = token_string.substr(dot2 + 1);
        std::string signing_input = header_b64 + "." + payload_b64;

        auto expected_sig = vcs::crypto::HMACSHA256::compute(signing_input, secret_key_);
        std::vector<uint8_t> provided_sig;
        try
        {
            provided_sig = base64urlDecode(sig_b64);
        }
        catch (...)
        {
            return result;
        }

        if (!vcs::crypto::HMACSHA256::verify(signing_input, secret_key_, provided_sig))
        {
            return result; // signature mismatch
        }

        try
        {
            auto payload_bytes = base64urlDecode(payload_b64);
            std::string payload_str(payload_bytes.begin(), payload_bytes.end());
            auto payload = json::parse(payload_str);

            result.sub = payload.at("sub").get<std::string>();
            result.role = stringToRole(payload.at("role").get<std::string>());
            result.iat = static_cast<time_t>(payload.at("iat").get<int64_t>());
            result.exp = static_cast<time_t>(payload.at("exp").get<int64_t>());
            result.jti = payload.at("jti").get<std::string>();
        }
        catch (...)
        {
            return result;
        }

        // Check expiry
        time_t now = std::time(nullptr);
        if (now > result.exp)
        {
            result.expired = true;
            return result;
        }

        // Check blacklist
        if (isRevoked(result.jti))
        {
            return result;
        }

        result.valid = true;
        return result;
    }

    void SessionToken::revoke(const std::string &token_string)
    {
        // Parse jti without full validation (token may be expired but we still revoke)
        size_t dot1 = token_string.find('.');
        if (dot1 == std::string::npos)
            return;
        size_t dot2 = token_string.find('.', dot1 + 1);
        if (dot2 == std::string::npos)
            return;

        std::string payload_b64 = token_string.substr(dot1 + 1, dot2 - dot1 - 1);
        try
        {
            auto payload_bytes = base64urlDecode(payload_b64);
            std::string payload_str(payload_bytes.begin(), payload_bytes.end());
            auto payload = json::parse(payload_str);
            std::string jti = payload.at("jti").get<std::string>();

            std::lock_guard<std::mutex> lock(blacklist_mutex_);
            blacklist_.insert(jti);
        }
        catch (...)
        {
            // Silently ignore malformed tokens during revocation
        }
    }

    bool SessionToken::isRevoked(const std::string &jti) const
    {
        std::lock_guard<std::mutex> lock(blacklist_mutex_);
        return blacklist_.count(jti) > 0;
    }
}