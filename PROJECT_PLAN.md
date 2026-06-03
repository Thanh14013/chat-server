# VCS SecureChat — Kế hoạch Dự án 4 Tuần

> **Mục tiêu:** Xây dựng hệ thống Group Chat Client-Server bằng C++ với trọng tâm **bảo mật đa lớp**, phù hợp tiêu chuẩn kỹ thuật của VCS (Viettel Cyber Security / Vietnam Communications Corporation).

---

## Tổng quan kiến trúc

```
VCS SecureChat
├── Transport Layer   — TCP socket, custom binary protocol, TLS-like handshake
├── Crypto Layer      — AES-256-CBC, RSA-2048 key exchange, HMAC-SHA256 integrity
├── Auth Layer        — JWT-style tokens, bcrypt password hash, session management
├── Application Layer — Multi-room chat, file transfer, admin system
└── Audit Layer       — Tamper-proof logging, rate limiting, intrusion detection
```

---

## Tóm tắt 4 tuần

| Tuần | Tên giai đoạn            | Trọng tâm                                        | Deliverable chính                    |
|------|--------------------------|--------------------------------------------------|--------------------------------------|
| 1    | **Core Foundation**      | Socket server, thread pool, binary protocol      | Server + Client hoạt động cơ bản    |
| 2    | **Security Core**        | AES-256, RSA handshake, HMAC, auth               | Mọi kết nối đều được mã hoá         |
| 3    | **Advanced Features**    | Multi-room, file transfer, TUI, chat history     | UX hoàn chỉnh, lưu trữ bền vững     |
| 4    | **Hardening & Ops**      | Rate limit, IDS, audit log, benchmark, README    | Production-ready, có số liệu đo đạc |

---

## Cấu trúc thư mục tổng thể (thống nhất từ đầu)

```
vcs-securechat/
├── CMakeLists.txt
├── README.md
├── PROJECT_PLAN.md
│
├── server/
│   ├── main.cpp
│   ├── core/
│   │   ├── TcpServer.h / .cpp
│   │   ├── ThreadPool.h / .cpp
│   │   ├── ClientSession.h / .cpp
│   │   └── EventLoop.h / .cpp
│   ├── protocol/
│   │   ├── Packet.h / .cpp
│   │   ├── PacketParser.h / .cpp
│   │   └── PacketBuilder.h / .cpp
│   ├── security/
│   │   ├── CryptoEngine.h / .cpp
│   │   ├── KeyExchange.h / .cpp
│   │   ├── AuthManager.h / .cpp
│   │   ├── SessionToken.h / .cpp
│   │   ├── RateLimiter.h / .cpp
│   │   ├── IntrusionDetector.h / .cpp
│   │   └── AuditLogger.h / .cpp
│   ├── rooms/
│   │   ├── RoomManager.h / .cpp
│   │   ├── Room.h / .cpp
│   │   └── ChatHistory.h / .cpp
│   ├── features/
│   │   ├── FileTransfer.h / .cpp
│   │   ├── AdminCommands.h / .cpp
│   │   └── MessageFilter.h / .cpp
│   └── utils/
│       ├── Logger.h / .cpp
│       ├── Config.h / .cpp
│       └── Utils.h / .cpp
│
├── client/
│   ├── main.cpp
│   ├── core/
│   │   ├── TcpClient.h / .cpp
│   │   ├── ConnectionManager.h / .cpp
│   │   └── MessageQueue.h / .cpp
│   ├── security/
│   │   ├── ClientCrypto.h / .cpp
│   │   └── CertVerifier.h / .cpp
│   ├── ui/
│   │   ├── TuiManager.h / .cpp
│   │   ├── ChatWindow.h / .cpp
│   │   ├── InputHandler.h / .cpp
│   │   └── Notifier.h / .cpp
│   └── commands/
│       ├── CommandParser.h / .cpp
│       └── CommandHandler.h / .cpp
│
├── common/
│   ├── Protocol.h          ← định nghĩa packet types dùng chung
│   ├── Constants.h         ← magic bytes, version, limits
│   ├── MessageTypes.h      ← enum tất cả loại message
│   └── ErrorCodes.h        ← mã lỗi chuẩn hoá
│
├── crypto/
│   ├── aes.h / .cpp        ← AES-256-CBC thuần C++ (không phụ thuộc ngoài)
│   ├── rsa.h / .cpp        ← RSA-2048 key gen + encrypt/decrypt
│   ├── hmac.h / .cpp       ← HMAC-SHA256 integrity check
│   ├── sha256.h / .cpp     ← SHA-256 hash
│   └── random.h / .cpp     ← CSPRNG (Cryptographically Secure PRNG)
│
├── tests/
│   ├── test_crypto.cpp
│   ├── test_protocol.cpp
│   ├── test_auth.cpp
│   ├── test_ratelimit.cpp
│   └── benchmark_load.cpp
│
├── scripts/
│   ├── build.sh
│   ├── run_server.sh
│   ├── run_client.sh
│   └── benchmark.sh
│
├── docs/
│   ├── PROTOCOL_SPEC.md    ← đặc tả binary protocol
│   ├── SECURITY_DESIGN.md  ← mô hình bảo mật
│   ├── API_COMMANDS.md     ← tất cả lệnh client
│   └── THREAT_MODEL.md     ← phân tích mối đe doạ
│
└── logs/                   ← sinh ra lúc runtime (gitignore)
    ├── audit/
    ├── chat_history/
    └── error/
```

---

## Dependency

| Thư viện       | Mục đích                         | Bắt buộc |
|----------------|----------------------------------|----------|
| `OpenSSL`      | AES, RSA, HMAC, SHA256           | ✅        |
| `ncurses`      | Terminal UI cho client           | ✅        |
| `pthread`      | Threading (POSIX)                | ✅        |
| `nlohmann/json`| Cấu hình JSON, audit log         | ✅        |
| `CMake 3.15+`  | Build system                     | ✅        |

---

## Mục tiêu hiệu năng (có thể đưa vào benchmark)

| Chỉ số                           | Mục tiêu          |
|----------------------------------|-------------------|
| Concurrent clients               | ≥ 100             |
| Message throughput (localhost)   | ≥ 5.000 msg/s     |
| Latency P99 (localhost)          | < 10 ms           |
| Startup time server              | < 500 ms          |
| Memory per client session        | < 2 MB            |

---

## Tính năng bảo mật — tổng hợp

| Tính năng                         | Layer      | Tuần triển khai |
|-----------------------------------|------------|-----------------|
| AES-256-CBC session encryption    | Crypto     | Tuần 2          |
| RSA-2048 key exchange             | Crypto     | Tuần 2          |
| HMAC-SHA256 packet integrity      | Protocol   | Tuần 2          |
| Password hashing (bcrypt/PBKDF2)  | Auth       | Tuần 2          |
| JWT-style session token           | Auth       | Tuần 2          |
| Replay attack prevention (nonce)  | Protocol   | Tuần 2          |
| Token bucket rate limiter         | Security   | Tuần 4          |
| Intrusion detection (brute force) | Security   | Tuần 4          |
| Tamper-proof audit logging        | Audit      | Tuần 4          |
| IP ban / blacklist                | Security   | Tuần 4          |
| Message content filtering         | App        | Tuần 3          |
| Privilege separation (admin/user) | Auth       | Tuần 3          |
| Secure file transfer + checksum   | Features   | Tuần 3          |
| Graceful shutdown (no data leak)  | Core       | Tuần 1          |
| Certificate pinning concept       | Crypto     | Tuần 2          |

---

## Liên kết chi tiết từng tuần

- [Week 1 — Core Foundation](./week_01_core_foundation.md)
- [Week 2 — Security Core](./week_02_security_core.md)
- [Week 3 — Advanced Features](./week_03_advanced_features.md)
- [Week 4 — Hardening & Ops](./week_04_hardening_ops.md)
