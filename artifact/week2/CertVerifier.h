#pragma once
#include <string>
#include <unordered_map>
#include <mutex>

namespace vcs::client {

/**
 * CertVerifier — "Trust On First Use" (TOFU) certificate pinning.
 *
 * Mitigates Man-in-the-Middle attacks by persisting the SHA-256 fingerprint
 * of the server's RSA public key to ~/.vcs_chat/known_servers.json.
 *
 * Behaviour:
 *  - NEW     : First time seeing this host:port. Fingerprint is saved.
 *  - TRUSTED : Fingerprint matches stored value. Connection proceeds silently.
 *  - CHANGED : Fingerprint differs from stored. Loud warning is displayed.
 *              User must type /trust to accept — otherwise we disconnect.
 *
 * Why TOFU instead of full PKI: the project uses self-generated RSA keys with
 * no CA infrastructure. TOFU provides meaningful protection against passive
 * MitM and opportunistic attacks while keeping the implementation simple.
 */
class CertVerifier {
public:
    enum class TrustStatus { TRUSTED, NEW, CHANGED };

    /**
     * Singleton accessor.
     * known_servers.json is loaded from disk on first access.
     */
    static CertVerifier& getInstance();

    CertVerifier(const CertVerifier&)            = delete;
    CertVerifier& operator=(const CertVerifier&) = delete;

    /**
     * Verify the server's public key PEM for a given host:port.
     *
     * @param host        Server hostname or IP.
     * @param port        Server port number.
     * @param pubkey_pem  PEM string received in KEY_OFFER.
     * @return            TRUSTED / NEW / CHANGED.
     */
    TrustStatus verifyServerKey(const std::string& host,
                                 int                port,
                                 const std::string& pubkey_pem);

    /**
     * Save (or overwrite) the fingerprint for host:port.
     * Called after user explicitly runs /trust.
     */
    void saveServerKey(const std::string& host,
                       int                port,
                       const std::string& pubkey_pem);

    /** Remove all known server fingerprints (for /trust reset). */
    void clearKnownServers();

    /**
     * Print the CHANGED fingerprint warning to stdout.
     * Returns true if the user typed /trust, false to disconnect.
     * This is a blocking interactive prompt.
     */
    static bool promptUserOnChange(const std::string& host,
                                    int                port,
                                    const std::string& old_fp,
                                    const std::string& new_fp);

private:
    CertVerifier();

    // ── Persistence ───────────────────────────────────────────────────────────
    void loadFromDisk();
    void saveToDisk() const;
    std::string knownServersPath() const;

    // ── Helpers ───────────────────────────────────────────────────────────────
    static std::string fingerprintOf(const std::string& pubkey_pem);
    static std::string makeKey(const std::string& host, int port);

    mutable std::mutex                       mutex_;
    std::unordered_map<std::string, std::string> known_servers_; // "host:port" → "sha256:..."
    bool                                     loaded_ = false;
};

} // namespace vcs::client
