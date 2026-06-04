#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <cstdint>
#include <ctime>

namespace vcs::security {

/**
 * JWT-style session token (self-implemented, no external JWT library).
 *
 * Format (base64url encoded, dot-separated):
 *   header.payload.signature
 *
 * Header (JSON):  {"alg":"HMAC-SHA256","typ":"VCS-SESSION"}
 * Payload (JSON): {"sub":"<nick>","iat":<unix>,"exp":<unix>,"jti":"<uuid>","role":"<role>"}
 * Signature:      HMAC-SHA256(header + "." + payload, server_secret_key)
 *
 * Security notes:
 *  - server_secret_key: 32 random bytes generated at startup, never persisted.
 *  - All tokens are invalidated on server restart (acceptable for this project).
 *  - jti (JWT ID) is a random UUID — added to in-memory blacklist on revoke.
 *  - Token lifetime: SESSION_LIFETIME_SEC (3600 s by default).
 */
class SessionToken {
public:
    static constexpr int SESSION_LIFETIME_SEC = 3600; // 1 hour

    enum class Role { GUEST, USER, ADMIN };

    struct Claims {
        std::string sub;    // subject (nickname)
        Role        role;
        time_t      iat;    // issued at
        time_t      exp;    // expires at
        std::string jti;    // JWT ID
        bool        valid;
        bool        expired;
    };

    /**
     * Initialise with a fresh 32-byte server secret key.
     * Call once from CryptoEngine::initialize().
     */
    explicit SessionToken(std::vector<uint8_t> secret_key);

    // Non-copyable
    SessionToken(const SessionToken&)            = delete;
    SessionToken& operator=(const SessionToken&) = delete;

    /**
     * Generate a new signed session token.
     * @param nickname  Validated nickname of authenticated user.
     * @param role      Privilege level.
     * @return          Dot-separated base64url token string.
     */
    std::string generate(const std::string& nickname, Role role) const;

    /**
     * Validate a token string.
     * @return Claims with valid=false if signature mismatch, or revoked.
     *         expired=true if past exp timestamp.
     */
    Claims validate(const std::string& token_string) const;

    /**
     * Revoke a token by adding its jti to the in-memory blacklist.
     * Revoked tokens are rejected by validate() even if not expired.
     */
    void revoke(const std::string& token_string);

    /** Check if a jti is in the revocation set. */
    bool isRevoked(const std::string& jti) const;

    static std::string roleToString(Role r);
    static Role        stringToRole(const std::string& s);

private:
    std::vector<uint8_t>        secret_key_;
    mutable std::mutex          blacklist_mutex_;
    std::unordered_set<std::string> blacklist_; // revoked jti values

    // ── Internal ──────────────────────────────────────────────────────────────
    static std::string base64urlEncode(const std::vector<uint8_t>& data);
    static std::string base64urlEncode(const std::string& data);
    static std::vector<uint8_t> base64urlDecode(const std::string& encoded);
    static std::string generateJTI();
};

} // namespace vcs::security
