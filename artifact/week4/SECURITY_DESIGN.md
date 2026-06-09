# VCS SecureChat — Security Design

---

## 1. Cryptographic Primitives (Week 2)

### AES-256-GCM for Session Encryption

**Why GCM over CBC?**
AES-256-GCM is an Authenticated Encryption with Associated Data (AEAD) cipher.
It simultaneously provides confidentiality (AES counter mode) and integrity
(GHASH authentication tag). This eliminates the need for a separate HMAC layer
and avoids Padding Oracle attacks that affect CBC mode when not carefully implemented.

**Why 256-bit key?**
128-bit is sufficient against known attacks, but 256-bit has negligible performance
cost on modern CPUs (AES-NI instructions) and provides headroom against future
cryptanalytic advances.

**IV / Nonce:**
- 12 bytes (96-bit), randomly generated per message using `RAND_bytes()`
- Never reused — GCM security breaks catastrophically on nonce reuse
- Transmitted in plaintext prepended to ciphertext (standard practice)

### RSA-2048 for Key Exchange

**Why RSA-2048 over ECDH?**
RSA-2048 is more widely understood and easier to audit in an interview context.
The public key serializes cleanly to PEM format for transmission.

**Padding:** OAEP (Optimal Asymmetric Encryption Padding) — `RSA_PKCS1_OAEP_PADDING`.
PKCS#1 v1.5 is intentionally avoided because it is vulnerable to the
Bleichenbacher adaptive chosen-ciphertext attack.

**Future improvement:** Replace with ECDH P-256 for Perfect Forward Secrecy —
each session generates an ephemeral key pair, so compromise of the server's
long-term key does not expose past sessions.

### HMAC-SHA256 for Packet Integrity (Week 1 baseline)

Applied over `header || payload` using the AES session key as the HMAC key.
The comparison uses `CRYPTO_memcmp()` (constant-time) to prevent timing attacks.

### PBKDF2-SHA256 for Password Hashing

- Iterations: 100,000 (NIST SP 800-132 recommendation for 2023)
- Salt: 16 random bytes per user, stored alongside hash
- Output: 32 bytes

**Why not bcrypt or Argon2?**
PBKDF2 is available directly from OpenSSL with no additional dependency.
For a production system, Argon2id (winner of the Password Hashing Competition)
would be preferred due to its memory-hardness.

---

## 2. Authentication Design

### Session Token

A JWT-inspired token with three base64url-encoded parts:

```
header.payload.signature
```

- **Header:** `{"alg":"HMAC-SHA256","typ":"VCS-SESSION"}`
- **Payload:** `{"sub":"nickname","iat":...,"exp":...,"jti":"uuid","role":"USER"}`
- **Signature:** HMAC-SHA256 of `header.payload` using a 32-byte server secret

The server secret is generated at startup with `RAND_bytes()` and never persisted.
This means all tokens are invalidated on server restart — an acceptable trade-off
for a chat system (clients simply reconnect).

### Privilege Model

```
OWNER  (1 per server) — all operations including promote/shutdown
  └── ADMIN           — kick, mute, ban, broadcast
        └── USER      — chat, file transfer, room management
              └── GUEST — read-only (future)
```

Role checks happen server-side on every admin packet — clients cannot bypass by
sending raw packets.

---

## 3. Network Security

### Why TCP, not UDP?

Chat requires reliable, ordered delivery. TCP provides this at the OS level.
UDP would require implementing retransmission and ordering in application code —
added complexity with no latency benefit for a chat use case.

### Why Custom Crypto Instead of TLS?

For this project: to demonstrate understanding of the underlying cryptographic
primitives — key exchange, symmetric encryption, integrity, authentication.

In a production deployment, OpenSSL TLS 1.3 would be the correct choice:
it provides PFS via ECDHE, certificate validation, and has been audited extensively.

### Binary Protocol Design Rationale

A fixed-length header with a length-prefix payload was chosen over text delimiters
(e.g., newlines) because:
- No ambiguity about message boundaries
- Immune to delimiter injection attacks
- Easier to validate: check magic bytes + version first, reject invalid packets early

---

## 4. Audit Trail Design

### Hash Chain Mechanism

```
genesis = "GENESIS"
hash[0] = SHA256( data[0] + genesis  )
hash[1] = SHA256( data[1] + hash[0]  )
hash[n] = SHA256( data[n] + hash[n-1])
```

If an attacker directly modifies SQLite row *k*, `hash[k]` will no longer match
`SHA256(data[k] + hash[k-1])`. Furthermore, every subsequent row's `prev_hash`
field will be incorrect, making the tampering immediately detectable by
`AuditLogger::verifyChain()`.

### Async Flush Strategy

Events are buffered in memory (deque, max 100) and flushed to SQLite in batch
transactions every 5 minutes or when the buffer is full. This reduces I/O pressure.
The trade-off: up to 100 events could be lost on a crash — acceptable for
audit logging where eventual durability is sufficient.

---

## 5. Concurrency Model

### Thread-per-Client vs. epoll

The server uses a fixed-size thread pool (default 32 workers) where each client
connection is served by a thread. This model:

- Is straightforward to reason about (no callback inversion)
- Handles 100+ concurrent clients comfortably on modern hardware
- Avoids the complexity of async I/O state machines

For higher scale (10,000+ concurrent connections), epoll + async I/O (reactor
pattern) would be necessary. The current design is intentionally understandable
and demonstrable.

### Lock Ordering (Deadlock Prevention)

When multiple locks must be held simultaneously, they are always acquired in
this order to prevent deadlocks:

```
1. sessionsMutex (shared_mutex, TcpServer)
2. roomsMutex    (shared_mutex, RoomManager)
3. sendMutex     (mutex, per ClientSession)
```

No code path acquires these in reverse order.

---

## 6. Defense in Depth

Each layer provides independent protection. A bypass of one layer does not
compromise the others:

```
Network Layer:   IntrusionDetector — IP-level blocking before connection accepted
Transport Layer: RateLimiter       — per-connection message rate limiting
Protocol Layer:  CRC32 + HMAC      — packet integrity, replay prevention
Auth Layer:      Session tokens    — identity verification per request
Application Layer: MessageFilter   — content-level injection detection
Audit Layer:     AuditLogger       — tamper-evident record of all actions
```

This means an attacker who successfully sends a malformed packet (bypasses
network filter) still faces HMAC verification. An attacker who forges a valid
packet still needs a valid session token. An attacker who gets a token still
cannot execute admin commands without the ADMIN role.
