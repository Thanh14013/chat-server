# Tuần 2 — Security Core

> **Mục tiêu tuần 2:** Toàn bộ giao tiếp phải được mã hoá. Không có packet nào đi qua mạng dưới dạng plaintext sau tuần này. Đây là tuần **quan trọng nhất** của dự án — là điểm phân biệt với 90% bài nộp khác.

---

## Checklist cuối tuần 2

- [x] RSA-2048 key pair được sinh trên server lúc khởi động
- [x] Handshake protocol: client ↔ server trao đổi key trước khi chat
- [x] AES-256-GCM mã hoá toàn bộ payload sau handshake (tích hợp AEAD kiểm tra toàn vẹn)
- [x] HMAC-SHA256 chỉ sử dụng để ký JWT-style Session Token
- [x] Nonce 16-byte chống replay attack
- [x] Password được hash bằng PBKDF2 (không lưu plaintext)
- [x] Session token JWT-style với expiry
- [x] Sequence number chống packet injection
- [x] Server reject kết nối không qua crypto handshake

---

## Mô hình bảo mật (Security Model)

```
Kết nối mới
     │
     ▼
[1] TCP Connect
     │
     ▼
[2] CRYPTO_HELLO     ← client thông báo bắt đầu handshake
     │
     ▼
[3] KEY_OFFER        ← server gửi RSA-2048 public key + server_nonce
     │
     ▼
[4] KEY_ACCEPT       ← client sinh AES-256 session key + IV
                         RSA-encrypt(session_key + client_nonce)
                         gửi lại server
     │
     ▼
[5] HANDSHAKE_OK     ← server xác nhận, hai bên đã có shared secret
     │
     ▼
[6] CONNECT_REQUEST  ← gửi nickname + PBKDF2(password)
                         payload được AES-GCM encrypt
                         + GCM Auth Tag (thay thế HMAC)
                         + sequence_num = 1
     │
     ▼
[7] SESSION_TOKEN    ← server trả JWT-style token
     │
     ▼
[Mọi packet tiếp theo đều: AES-GCM encrypted + GCM Auth Tag + seq_num tăng dần]
```

---

## Cấu trúc file tuần 2 (bổ sung vào tuần 1)

```
vcs-securechat/
├── crypto/                  ← MỚI — thư viện crypto độc lập
│   ├── aes.h / .cpp
│   ├── rsa.h / .cpp
│   ├── hmac.h / .cpp
│   ├── sha256.h / .cpp
│   └── random.h / .cpp
├── server/
│   └── security/            ← MỚI
│       ├── CryptoEngine.h / .cpp
│       ├── KeyExchange.h / .cpp
│       ├── AuthManager.h / .cpp
│       └── SessionToken.h / .cpp
└── client/
    └── security/            ← MỚI
        ├── ClientCrypto.h / .cpp
        └── CertVerifier.h / .cpp
```

---

## Chi tiết từng file

---

### `crypto/aes.h / .cpp`

**Mục đích:** Implement AES-256-GCM encryption/decryption wrapper trên OpenSSL (hỗ trợ AEAD)

**Nội dung quan trọng:**
```
AES256GCM class:
  Fields:
    - key[32]   : uint8_t (256-bit key)
    - iv[16]    : uint8_t (initialization vector — phải random, unique mỗi message)

  Methods:
    - encrypt(plaintext, aad)  → {ciphertext, auth_tag_16_bytes}
    - decrypt(ciphertext, auth_tag, aad) → plaintext
    - generateKey()       → key        : static helper
    - generateIV()        → iv         : static helper (dùng CSPRNG)

  Quan trọng:
    - IV KHÔNG được tái sử dụng — sinh mới cho từng message
    - IV được đính kèm ở đầu ciphertext (16 bytes đầu = IV)
    - Không cần Padding (GCM là stream cipher)
    - Mỗi AES instance gắn với 1 client session
```

**Lý do chọn GCM:** Tuân thủ chuẩn AEAD, đảm bảo Encrypt-then-MAC (tránh hoàn toàn Padding Oracle Attack có thể gặp nếu tự implement CBC + MAC riêng rẽ).

---

### `crypto/rsa.h / .cpp`

**Mục đích:** RSA-2048 key generation, encrypt (public), decrypt (private)

**Nội dung quan trọng:**
```
RSA2048 class:
  Methods:
    - generateKeyPair()               : tạo cặp key, gọi một lần lúc server start
    - getPublicKeyPEM()  → string     : export public key dạng PEM để gửi cho client
    - loadPublicKeyPEM(string)        : client load public key từ server
    - encrypt(data, pubkey) → bytes   : RSA_PKCS1_OAEP_PADDING
    - decrypt(data, privkey) → bytes  : dùng private key giải mã AES session key

  Lưu ý bảo mật:
    - KHÔNG lưu private key ra file trong bản demo
    - Dùng OAEP padding (không dùng PKCS1v1.5 — dễ bị Bleichenbacher attack)
    - Key size = 2048 bit (cân bằng security vs performance)
    - Server chỉ có 1 RSA key pair trong toàn bộ lifetime
```

---

### `crypto/hmac.h / .cpp`

**Mục đích:** HMAC-SHA256 được sử dụng riêng để xác minh tính toàn vẹn của JWT-style Session Token (không dùng cho packet)

**Nội dung quan trọng:**
```
HMACSHA256 class:
  Methods:
    - compute(data, key) → signature : vector<uint8_t> 32 bytes
    - verify(data, key, sig) → bool  : constant-time comparison (tránh timing attack)

  Cách dùng:
    - Không còn dùng cho packet (packet đã chuyển sang dùng AEAD của AES-256-GCM).
    - HMAC chỉ dùng để ký Token JWT bằng server_secret_key.

  Lưu ý:
    - PHẢI dùng constant-time comparison — không dùng memcmp() thông thường
    - OpenSSL HMAC_CTX đã thread-safe nếu mỗi call tạo context mới
```

---

### `crypto/sha256.h / .cpp`

**Mục đích:** SHA-256 hash — dùng cho password hashing và file checksum

**Nội dung quan trọng:**
```
SHA256 class:
  Methods:
    - hash(data) → hex_string        : hash dữ liệu bất kỳ
    - hashFile(filepath) → hex_string: hash file cho file transfer integrity

  PBKDF2 wrapper (dùng OpenSSL PKCS5_PBKDF2_HMAC):
    - pbkdf2(password, salt, iterations=100000) → hash
    - generateSalt() → 16 random bytes (dùng CSPRNG)

  Lưu ý:
    - Không hash password thuần SHA256 — phải PBKDF2 với salt
    - 100.000 iterations là khuyến nghị NIST 2023
    - Salt phải unique per user, lưu cùng hash trong database
    - TRỌNG YẾU: Bắt buộc dùng `OPENSSL_cleanse` hoặc `memset_s` để xoá sạch plaintext password khỏi RAM sau khi băm, chống memory dump.
```

---

### `crypto/random.h / .cpp`

**Mục đích:** Cryptographically Secure Pseudo-Random Number Generator

**Nội dung quan trọng:**
```
CSPRNG class (singleton):
  Methods:
    - getBytes(n) → vector<uint8_t>  : n random bytes từ OpenSSL RAND_bytes
    - getUInt32() → uint32_t         : random integer
    - getNonce() → array<uint8_t,16> : 16-byte nonce cho anti-replay

  Lưu ý:
    - KHÔNG dùng rand(), srand(), mt19937 cho mục đích crypto
    - OpenSSL RAND_bytes đọc từ /dev/urandom — đủ entropy
    - Seed tự động, không cần manual seed
```

---

### `server/security/CryptoEngine.h / .cpp`

**Mục đích:** Facade layer — bọc tất cả crypto operations cho server dùng

**Nội dung quan trọng:**
```
CryptoEngine class (singleton):
  Fields:
    - rsa_keypair : RSA2048          (sinh một lần lúc start)
    - session_keys: map<fd, AES256GCM> (mỗi client có key riêng)

  Methods:
    - initialize()                   : sinh RSA key pair
    - getPublicKeyPEM() → string     : gửi cho client trong handshake
    - establishSession(fd, encrypted_key_bytes) → bool
        + decrypt AES session key bằng RSA private key
        + lưu vào session_keys[fd]
    - encryptPayload(fd, plaintext) → {ciphertext, auth_tag}
    - decryptPayload(fd, ciphertext, auth_tag) → plaintext
    - removeSession(fd)              : gọi khi client disconnect

  Thread safety:
    - session_keys được bảo vệ bởi shared_mutex
    - Cho phép concurrent reads (nhiều client gửi/nhận cùng lúc)
```

---

### `server/security/KeyExchange.h / .cpp`

**Mục đích:** Quản lý quá trình handshake — state machine

**Nội dung quan trọng:**
```
HandshakeState enum:
  WAITING_HELLO
  SENT_KEY_OFFER
  WAITING_KEY_ACCEPT
  ESTABLISHED
  FAILED

KeyExchange class:
  Per-client state (lưu trong ClientSession):
    - state           : HandshakeState
    - server_nonce    : array<uint8_t,16>  (sinh ngẫu nhiên, gửi cho client)
    - client_nonce    : array<uint8_t,16>  (client gửi lại, verify)
    - handshake_time  : time_t

  Methods:
    - handleHello(fd, packet) → Packet   : nhận CRYPTO_HELLO, trả KEY_OFFER
    - handleKeyAccept(fd, packet) → bool : nhận KEY_ACCEPT, decrypt session key
    - isEstablished(fd) → bool
    - getHandshakeTimeoutSeconds() = 30  : nếu không xong trong 30s → disconnect

  Bảo mật:
    - Server nonce ngăn client dùng lại cùng session key từ session cũ
    - Nếu handshake fail 3 lần → block IP tạm thời (5 phút)
```

---

### `server/security/AuthManager.h / .cpp`

**Mục đích:** Quản lý xác thực người dùng — nickname, password, session

**Nội dung quan trọng:**
```
UserRecord struct:
  - nickname          : string
  - password_hash     : string  (PBKDF2 output, hex-encoded)
  - salt              : string  (hex-encoded)
  - role              : enum {GUEST, USER, ADMIN}
  - created_at        : time_t
  - last_login        : time_t
  - failed_attempts   : int     (reset khi login thành công)
  - locked_until      : time_t  (0 nếu không bị lock)

AuthManager class:
  Fields:
    - active_sessions : map<token, fd>
    (Sử dụng server/utils/Database để thao tác trực tiếp với SQLite, không giữ in-memory db lớn)

  Methods:
    - registerUser(nickname, password) → ErrorCode
        + validate nickname (regex: [a-zA-Z0-9_]{3,32})
        + query SQLite kiểm tra duplicate
        + PBKDF2 hash password với random salt (ngay sau đó xoá plain password bằng `OPENSSL_cleanse`)
        + INSERT vào bảng Users trong SQLite
    - authenticate(nickname, password) → {token, ErrorCode}
        + query SQLite lấy thông tin UserRecord
        + check failed_attempts → ERR_AUTH_TOO_MANY_ATTEMPTS nếu ≥ 5
        + verify PBKDF2 hash (đồng thời xoá plain password bằng `OPENSSL_cleanse`)
        + sinh session token
        + update last_login trong SQLite
    - validateToken(token) → {fd, valid}
    - revokeToken(token)
    - isNicknameTaken(nickname) → bool
    - getUserRole(nickname) → Role

  Bảo mật:
    - Sau 5 lần fail → lock account 15 phút
    - Password hash không bao giờ log ra
    - Database SQLite không lưu plaintext password, chỉ lưu salt + PBKDF2 hash
```

---

### `server/security/SessionToken.h / .cpp`

**Mục đích:** Sinh và xác minh session token — JWT-style nhưng tự implement

**Nội dung quan trọng:**
```
Token format (base64url encoded):
  header.payload.signature

  Header (JSON):
    { "alg": "HMAC-SHA256", "typ": "VCS-SESSION" }

  Payload (JSON):
    {
      "sub": "nickname",
      "iat": 1700000000,     (issued at — unix timestamp)
      "exp": 1700003600,     (expires at — iat + 3600 giây)
      "jti": "random_uuid",  (JWT ID — chống token reuse)
      "role": "USER"
    }

  Signature:
    HMAC-SHA256(header + "." + payload, server_secret_key)

  server_secret_key:
    - 32 random bytes sinh khi server start
    - KHÔNG persist ra file
    - Hệ quả: tất cả token expire khi server restart (chấp nhận được)

SessionToken class:
  Methods:
    - generate(nickname, role) → token_string
    - validate(token_string) → {nickname, role, valid, expired}
    - revoke(token_string)    : thêm vào blacklist (in-memory set)
    - isRevoked(jti) → bool
```

---

### `client/security/ClientCrypto.h / .cpp`

**Mục đích:** Xử lý crypto phía client — đối xứng với CryptoEngine trên server

**Nội dung quan trọng:**
```
ClientCrypto class:
  Fields:
    - aes_session_key : vector<uint8_t>   (32 bytes, tự sinh)
    - aes_session_iv  : vector<uint8_t>   (16 bytes, per-message)
    - server_pubkey   : RSA public key    (nhận từ server)
    - handshake_done  : bool

  Methods:
    - startHandshake() → Packet (MSG_CRYPTO_HELLO)
    - processKeyOffer(packet) → Packet (MSG_CRYPTO_KEY_ACCEPT)
        + parse server RSA public key
        + sinh AES-256 session key (32 random bytes)
        + sinh client_nonce (16 random bytes)
        + RSA-encrypt(session_key || client_nonce) bằng server pubkey
        + trả packet KEY_ACCEPT
    - processHandshakeOk(packet)     : set handshake_done = true
    - encryptPacket(plain_packet) → encrypted_packet
    - decryptPacket(enc_packet)  → plain_packet
    - isReady() → bool

  Bảo mật:
    - Session key được overwrite bằng zero khi disconnect
    - Không cache server public key giữa các session
```

---

### `client/security/CertVerifier.h / .cpp`

**Mục đích:** Giả lập certificate pinning — ngăn Man-in-the-Middle attack

**Nội dung quan trọng:**
```
CertVerifier class:
  Cơ chế: "Trust On First Use" (TOFU) — đơn giản nhưng hiệu quả
    - Lần đầu connect → lưu SHA256 fingerprint của server pubkey vào ~/.vcs_chat/known_servers
    - Lần sau connect → so sánh fingerprint
    - Nếu fingerprint thay đổi → CẢNH BÁO lớn, hỏi user có tiếp tục không

  known_servers file format (JSON):
    { "127.0.0.1:9000": "sha256:abc123...", ... }

  Methods:
    - verifyServerKey(host, port, pubkey_pem) → {TRUSTED, NEW, CHANGED}
    - saveServerKey(host, port, pubkey_pem)
    - clearKnownServers()   : cho /trust reset

  Hiển thị cho user khi CHANGED:
    "⚠️  WARNING: Server key fingerprint changed!
     Old: SHA256:abc...
     New: SHA256:xyz...
     This could be a Man-in-the-Middle attack!
     Type /trust to accept new key (NOT recommended)
     Press Enter to disconnect (recommended)"
```

---

## Packet format sau khi có crypto (tuần 2 trở đi)

```
Packet on-wire format:
┌─────────────────────────────────────────────────────┐
│  HEADER (17 bytes, PLAINTEXT)                       │
│  magic[2] | version[1] | msg_type[1] | flags[1]    │
│  seq_num[4] | payload_length[4] | checksum_crc32[4] │
├─────────────────────────────────────────────────────┤
│  IV (16 bytes, PLAINTEXT)                           │
│  AES IV cho message này — RANDOM mỗi lần            │
├─────────────────────────────────────────────────────┤
│  ENCRYPTED PAYLOAD (variable)                       │
│  AES-256-GCM( plaintext_data )                      │
├─────────────────────────────────────────────────────┤
│  GCM AUTH TAG (16 bytes)                            │
│  Tạo bởi AES-GCM (thay thế hoàn toàn HMAC)          │
└─────────────────────────────────────────────────────┘

Total overhead per packet: 17 + 16 + 16 = 49 bytes
```

**Lý do IV plaintext:** IV không cần bí mật, chỉ cần unique. Đặt trước ciphertext là convention chuẩn.

---

## Replay Attack Prevention

```
Mỗi ClientSession có:
  - expected_seq_num : uint32_t = 0
  - seen_nonces      : set<array<uint8_t,16>> (window 1000 nonces)

Khi nhận packet:
  1. Nếu packet.seq_num < expected_seq_num → DROP (replay)
  2. Nếu packet.seq_num > expected_seq_num + 100 → DROP (suspicious jump)
  3. Nếu nonce đã thấy → DROP (replay)
  4. Nếu ok → process, update expected_seq_num
```

---

## Kết quả kiểm thử cuối tuần 2

```bash
# Dùng Wireshark / tcpdump bắt traffic:
# tcpdump -i lo -X port 9000

# Mong đợi: không thấy bất kỳ plaintext nào (nickname, message)
# Chỉ thấy binary garbage sau crypto handshake

# Test replay attack:
# Bắt packet bằng raw socket, gửi lại → server drop với log:
# [WARN] Replay attack detected from 127.0.0.1 seq=5 expected=8

# Test wrong HMAC:
# Modify 1 byte trong packet → server drop:
# [WARN] HMAC verification failed from 127.0.0.1

# Test MITM (fingerprint):
# Thay đổi server key → client cảnh báo và disconnect
```
