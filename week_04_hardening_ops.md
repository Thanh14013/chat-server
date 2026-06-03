# Tuần 4 — Hardening & Ops

> **Mục tiêu tuần 4:** Biến hệ thống thành production-ready. Tập trung hoàn toàn vào bảo mật tầng vận hành, chống tấn công, đo lường hiệu năng, và documentation đẳng cấp. Đây là tuần **tạo ra sự khác biệt giữa candidate tốt và candidate xuất sắc.**

---

## Checklist cuối tuần 4

- [x] Rate limiter với Token Bucket Algorithm
- [x] Intrusion Detection System (IDS): phát hiện brute force, port scan, flood
- [x] IP blacklist động: tự ban sau N lần vi phạm
- [x] Tamper-proof audit log với chain hash (đã viết skeleton tuần 3)
- [x] Memory safety: valgrind clean, không leak
- [x] Load test: benchmark với 50-100 concurrent clients
- [x] Threat Model document
- [x] Security Design document
- [x] README chi tiết (cài đặt, chạy, kiến trúc, security notes)
- [x] Protocol Spec document
- [x] Demo script để present

---

## Cấu trúc file tuần 4 (bổ sung)

```
vcs-securechat/
├── server/
│   └── security/
│       ├── RateLimiter.h / .cpp         ← MỚI
│       └── IntrusionDetector.h / .cpp   ← MỚI
├── tests/
│   ├── test_crypto.cpp                  ← MỚI
│   ├── test_protocol.cpp                ← MỚI
│   ├── test_auth.cpp                    ← MỚI
│   ├── test_ratelimit.cpp               ← MỚI
│   └── benchmark_load.cpp              ← MỚI
├── scripts/
│   ├── benchmark.sh                     ← MỚI
│   └── security_check.sh               ← MỚI
└── docs/
    ├── PROTOCOL_SPEC.md                 ← MỚI
    ├── SECURITY_DESIGN.md               ← MỚI
    ├── THREAT_MODEL.md                  ← MỚI
    └── API_COMMANDS.md                  ← MỚI
```

---

## Chi tiết từng file

---

### `server/security/RateLimiter.h / .cpp`

**Mục đích:** Giới hạn tốc độ gửi tin nhắn per-client bằng Token Bucket Algorithm — chống spam và DoS

**Nội dung quan trọng:**
```
TokenBucket struct (per-client):
  Fields:
    - tokens          : double          (số token hiện có)
    - max_tokens      : double          (= RATE_LIMIT_MSG_PER_SEC)
    - refill_rate     : double          (tokens/second)
    - last_refill_time: chrono::steady_clock::time_point
    - mutex           : mutex

  Methods:
    - consume(n=1) → bool
        + tính số token đã refill kể từ last_refill_time
        + cộng token, cap tại max_tokens
        + nếu tokens >= n → tokens -= n, return true
        + nếu tokens < n  → return false (rate limited)

  Vì sao Token Bucket tốt hơn simple counter?
    - Cho phép "burst" ngắn hạn (Alice gửi 3 tin liên tiếp sau khi im lặng 1 phút)
    - Smooth out traffic, không bị phạt vì burst hợp lý
    - Thực tế network/API đều dùng token bucket

RateLimiter class (singleton):
  Fields:
    - buckets : unordered_map<int, TokenBucket>  (fd → bucket)

  Methods:
    - addClient(fd)
    - removeClient(fd)
    - checkLimit(fd, cost=1) → {ALLOWED, RATE_LIMITED}
    - getStats(fd) → {current_tokens, violations_count}

  Cấu hình (từ server_config.json):
    - msg_rate_per_sec = 10      (tin nhắn chat)
    - connect_rate_per_min = 5   (kết nối mới từ cùng IP)
    - auth_rate_per_min = 5      (lần thử login)
    - file_transfer_per_hour = 20

  Khi bị rate limit:
    - Lần 1-3: gửi ERR_RATE_LIMITED, tin nhắn bị drop
    - Lần 4+: cộng điểm violation vào IntrusionDetector
    - Log: [WARN] Rate limit hit: fd=5 ip=192.168.1.1 violations=4
```

---

### `server/security/IntrusionDetector.h / .cpp`

**Mục đích:** Phát hiện các pattern tấn công, tự động phản ứng — mini-IDS

**Nội dung quan trọng:**
```
ThreatLevel enum:
  CLEAN      = 0
  SUSPICIOUS = 1   (ghi log, theo dõi)
  THREAT     = 2   (throttle, cảnh báo admin)
  ATTACK     = 3   (ban tạm thời)

IPRecord struct:
  - ip              : string
  - threat_score    : int        (cộng dồn, decay theo thời gian)
  - violations      : vector<{timestamp, violation_type}>
  - ban_until       : time_t     (0 nếu không bị ban)
  - first_seen      : time_t
  - connection_count: int

IntrusionDetector class (singleton):
  Fields:
    - ip_records  : unordered_map<string, IPRecord>
    - ban_list    : set<string>             (IP bị ban vĩnh viễn)
    - temp_bans   : map<string, time_t>     (IP bị ban tạm)
    - whitelist   : set<string>             (admin IPs không bị chặn)

  Methods:
    - checkIP(ip) → {ALLOWED, BLOCKED, WHITELISTED}
    - reportViolation(ip, violation_type, severity)
        + cộng threat_score tương ứng
        + nếu score > THREAT_THRESHOLD → temp_ban 1 giờ
        + nếu score > ATTACK_THRESHOLD → perm_ban + alert admin
    - tempBan(ip, duration_seconds, reason)
    - permBan(ip, reason)
    - unban(ip)
    - decayScores()    : gọi mỗi 10 phút, giảm threat_score 10%/phút
    - exportBanList()  : lưu ban_list.json

  Violation types và điểm số:
    FAILED_AUTH          → +10  (sai password)
    RATE_LIMIT_EXCEEDED  → +5   (gửi quá nhanh)
    HMAC_FAILURE         → +20  (packet giả mạo)
    REPLAY_ATTACK        → +50  (replay packet)
    INJECTION_ATTEMPT    → +30  (SQL/command injection)
    HANDSHAKE_FAIL       → +15  (crypto handshake lỗi)
    INVALID_PACKET       → +10  (packet format sai)
    PORT_SCAN            → +100 (kết nối liên tục, không send data)

  Auto-ban thresholds:
    score ≥ 100  → temp ban 1 giờ
    score ≥ 200  → temp ban 24 giờ
    score ≥ 500  → perm ban + ghi vào audit log với CRITICAL level
    3 temp bans  → tự động escalate lên perm ban

  Điểm đặc biệt cho VCS:
    - Giả lập SIEM lite: export events theo format CEF (Common Event Format)
      CEF:0|VCS|SecureChat|1.0|AUTH_FAIL|Failed authentication|5|src=192.168.1.1 suser=admin
    - Có thể tích hợp vào SIEM thực của VCS
```

---

### `tests/test_crypto.cpp`

**Mục đích:** Unit tests cho toàn bộ crypto module

**Nội dung quan trọng:**
```
Test cases:
  AES-256:
    - test_encrypt_decrypt_roundtrip()       : encrypt rồi decrypt phải ra nguyên bản
    - test_different_iv_each_time()          : cùng plaintext, 2 lần encrypt → 2 ciphertext khác nhau
    - test_wrong_key_fails()                 : decrypt với key sai → exception
    - test_empty_input()                     : edge case
    - test_max_message_size()                : MAX_MESSAGE_LEN bytes

  RSA-2048:
    - test_key_generation()                  : sinh key, serialize/deserialize
    - test_encrypt_decrypt_small_data()      : < 200 bytes (RSA limit)
    - test_oaep_padding()                    : verify dùng OAEP

  HMAC-SHA256:
    - test_hmac_correct_key()               : verify pass
    - test_hmac_wrong_key_fails()           : verify fail
    - test_hmac_tampered_data_fails()       : thay 1 byte → fail
    - test_constant_time_comparison()       : timing variance < 5% (anti-timing attack)

  PBKDF2:
    - test_same_password_different_salt()   : kết quả khác nhau
    - test_iteration_count()               : 100.000 iterations
    - test_hash_length()                   : 32 bytes output

  CSPRNG:
    - test_randomness_distribution()       : chi-square test
    - test_no_repeats_in_1000_nonces()    : 1000 nonces không trùng

Framework: simple custom test runner (không cần gtest để tránh dependency phức tạp)
```

---

### `tests/benchmark_load.cpp`

**Mục đích:** Load test — spawn N client giả lập, đo throughput và latency

**Nội dung quan trọng:**
```
BenchmarkClient class:
  - connect tới server
  - thực hiện full crypto handshake
  - gửi N tin nhắn trong M giây
  - đo RTT (round-trip time) từng message
  - báo cáo: messages_sent, messages_received, latency_avg, latency_p99

BenchmarkRunner class:
  - spawn N threads, mỗi thread là 1 BenchmarkClient
  - đo: total_throughput (msg/s), peak_throughput, latency distribution
  - in kết quả ra bảng ASCII đẹp

Scenarios:
  Scenario 1 - Baseline:      10 clients, 60 giây, measure throughput
  Scenario 2 - Load test:     50 clients, 60 giây, measure throughput + latency
  Scenario 3 - Stress test:  100 clients, 60 giây, measure degradation
  Scenario 4 - Burst test:    10 clients, burst 100 msg trong 1 giây (test rate limiter)

Output mẫu:
  ╔══════════════════════════════════════════════════════╗
  ║        VCS SecureChat — Load Test Results            ║
  ╠══════════════════════════════════════════════════════╣
  ║  Clients: 50  │  Duration: 60s  │  Server: localhost ║
  ╠══════════════════════════════════════════════════════╣
  ║  Messages sent:      150,342                        ║
  ║  Messages received:  150,340  (99.998% delivery)    ║
  ║  Throughput avg:     2,505 msg/s                    ║
  ║  Throughput peak:    3,120 msg/s                    ║
  ║  Latency avg:        2.1 ms                         ║
  ║  Latency P50:        1.8 ms                         ║
  ║  Latency P99:        7.2 ms                         ║
  ║  Latency P99.9:     18.4 ms                         ║
  ║  Memory usage:      ~45 MB (50 sessions)            ║
  ╚══════════════════════════════════════════════════════╝
```

---

### `docs/THREAT_MODEL.md`

**Mục đích:** Tài liệu phân tích mối đe doạ — cực kỳ ấn tượng với VCS (họ làm cybersec)

**Nội dung quan trọng:**
```
Cấu trúc theo STRIDE model (Microsoft):

1. Spoofing Identity
   Threat: Giả mạo nickname của người khác
   Mitigation: Session token unique, authenticated trước khi gửi bất kỳ tin nào

2. Tampering with Data
   Threat: Sửa nội dung packet trên đường truyền
   Mitigation: HMAC-SHA256 mỗi packet, server drop packet HMAC fail

3. Repudiation
   Threat: User phủ nhận đã gửi tin nhắn
   Mitigation: Audit log với chain hash, tamper-evident

4. Information Disclosure
   Threat: Nghe lén traffic (Wireshark, tcpdump)
   Mitigation: AES-256-CBC encryption, key exchange qua RSA-2048

5. Denial of Service
   Threat: Flood server với kết nối / tin nhắn
   Mitigation: Rate limiter (token bucket), max connection limit, IDS auto-ban

6. Elevation of Privilege
   Threat: User thường cố thực thi admin commands
   Mitigation: Role-based access control, server check role mỗi command

Attack scenarios được phân tích:
   - Man-in-the-Middle (MITM): ngặn bởi certificate pinning + RSA handshake
   - Replay Attack: ngăn bởi sequence number + nonce
   - Brute Force Login: ngăn bởi account lockout + IP rate limit
   - SQL Injection: ngăn bởi message filter + không dùng SQL
   - Buffer Overflow: ngăn bởi length-prefix protocol + bounds checking
   - Insider Threat: audit log tamper-evident

Residual risks (thành thật với reviewer):
   - Không có perfect forward secrecy (cần DH key exchange — future work)
   - RSA key không rotate (restart server là rotate)
   - Chat history lưu plaintext trên server (trade-off: searchability)
```

---

### `docs/SECURITY_DESIGN.md`

**Mục đích:** Mô tả chi tiết các quyết định thiết kế bảo mật và lý do

**Nội dung quan trọng:**
```
Sections:
  1. Cryptographic Primitives
     - Tại sao AES-256-CBC thay vì AES-128-GCM?
       → 128-GCM mạnh hơn nhưng phức tạp hơn; 256-CBC đủ cho demo, dễ audit
       → Future: migrate sang GCM để có AEAD (authenticate-then-encrypt tích hợp)
     - Tại sao RSA-2048 thay vì ECDH/ECDSA?
       → Phổ biến hơn, dễ giải thích hơn trong interview
       → Future: ECDH P-256 cho Perfect Forward Secrecy

  2. Authentication Design
     - Tại sao PBKDF2 thay vì bcrypt/Argon2?
       → OpenSSL có sẵn PBKDF2, không cần thêm dependency
       → bcrypt sẽ tốt hơn cho production

  3. Network Security
     - TCP thay vì UDP: độ tin cậy quan trọng hơn latency cho chat
     - Không dùng TLS/SSL thư viện: tự implement để học + demonstrate knowledge

  4. Audit Trail Design
     - Hash chain cho tamper-evidence: giải thích cơ chế
     - Trade-off: sync vs async logging

  5. Concurrency Model
     - Thread-per-client vs. event-driven (epoll): tại sao chọn thread-per-client
     - Mutex strategy: tránh deadlock, lock ordering

  6. Defense in Depth
     - Mỗi layer có bảo vệ riêng (không tin tưởng tầng dưới)
```

---

### `docs/PROTOCOL_SPEC.md`

**Mục đích:** Đặc tả đầy đủ binary protocol — như RFC thu nhỏ

**Nội dung quan trọng:**
```
Sections:
  1. Overview & Design Goals
  2. Packet Format (byte-level diagram, mỗi field giải thích)
  3. Message Types (mỗi type: direction, payload format, response)
  4. Handshake Sequence (flow diagram ASCII)
  5. Error Handling
  6. Versioning Strategy
  7. Examples (hex dump của actual packets)

Ví dụ hex dump trong spec:
  MSG_CONNECT_REQUEST packet (after encryption):
  Offset  Bytes    Description
  0x00    VC 53    Magic bytes (VCS signature)
  0x02    01       Protocol version
  0x03    01       Message type (CONNECT_REQUEST)
  0x04    01       Flags (ENCRYPTED bit set)
  0x05    00000001 Sequence number = 1
  0x09    000000xx Payload length
  0x0D    xxxxxxxx CRC32 checksum
  0x11    [16B IV] AES IV
  0x21    [...]    Encrypted payload
  [...] [32B HMAC] HMAC-SHA256 signature
```

---

### `scripts/security_check.sh`

**Mục đích:** Tự động kiểm tra một số điều kiện bảo mật trước khi demo

**Nội dung quan trọng:**
```bash
#!/bin/bash
# VCS SecureChat — Pre-flight security check

echo "=== VCS SecureChat Security Check ==="

# 1. Check binaries không chứa debug symbols (strip)
# 2. Check file permissions: logs/ phải 700, config phải 600
# 3. Check không có hardcoded credentials trong source (grep)
# 4. Check valgrind (nếu có)
# 5. Verify ban_list.json format hợp lệ
# 6. Check OpenSSL version >= 1.1.1
# 7. Verify audit log chain integrity

echo "[PASS/FAIL] Binary stripped"
echo "[PASS/FAIL] Log permissions"
echo "[PASS/FAIL] No hardcoded credentials"
echo "[PASS/FAIL] OpenSSL version"
echo "[PASS/FAIL] Audit chain integrity"
```

---

### `README.md` (cập nhật hoàn chỉnh tuần 4)

**Mục đích:** README là mặt tiền của project — phải ấn tượng ngay từ đầu

**Cấu trúc:**
```markdown
# VCS SecureChat — Encrypted Group Chat System

> A production-grade, multi-room group chat system built in C++17.
> Designed with a security-first mindset for enterprise environments.

## Security Features
  [bảng tổng hợp tất cả tính năng bảo mật]

## Architecture
  [diagram ASCII]

## Quick Start
  [5 lệnh để build và chạy]

## Technical Decisions
  [giải thích ngắn gọn các quyết định kỹ thuật quan trọng]

## Benchmark Results
  [paste kết quả từ benchmark_load.cpp]

## Security Notes
  [threat model tóm tắt, known limitations]

## Future Improvements
  - Perfect Forward Secrecy (ECDH)
  - AES-GCM thay AES-CBC
  - TLS 1.3 integration
  - Distributed server (multiple nodes)
  - End-to-end encryption (server không giải mã được)
```

---

## Điểm nhấn khi trình bày với VCS

**Nêu rõ từng quyết định bảo mật và lý do:**

1. *"Em không dùng TLS thư viện mà tự implement handshake để demonstrate rõ ràng các khái niệm crypto — trong production thực tế sẽ dùng OpenSSL TLS."*

2. *"Audit log có hash chain như blockchain mini — nếu ai sửa log entry thứ 50, tất cả entry từ 51 trở đi sẽ có hash sai, phát hiện ngay."*

3. *"IDS của em export events theo format CEF — Common Event Format của ArcSight — để có thể tích hợp vào hệ thống SIEM thực tế của VCS."*

4. *"Benchmark cho thấy 50 clients đồng thời, P99 latency < 10ms — đủ cho internal enterprise chat."*

5. *"Threat model theo STRIDE của Microsoft — cùng framework mà VCS và các tổ chức security chuyên nghiệp dùng."*

---

## Kết quả kiểm thử cuối tuần 4

```bash
# Run full benchmark
./scripts/benchmark.sh
# → In bảng kết quả, lưu vào docs/BENCHMARK_RESULTS.md

# Run security checks
./scripts/security_check.sh
# → Tất cả checks PASS

# Run unit tests
cd build && ctest --verbose
# → test_crypto: 18/18 passed
# → test_protocol: 12/12 passed
# → test_auth: 10/10 passed
# → test_ratelimit: 8/8 passed

# Kiểm tra memory leak
valgrind --leak-check=full ./vcs_server
# → 0 definitely lost, 0 indirectly lost

# Kiểm tra audit log integrity
./vcs_server --verify-audit-log
# → "Audit chain verified: 1,247 events from database, all valid"

# Demo Wireshark: không thấy plaintext sau handshake
tcpdump -i lo -X port 9000 | grep -E "(Alice|Bob|Hello)" 
# → 0 matches (tất cả đều encrypted)
```
