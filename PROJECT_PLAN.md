# VCS SecureChat — Kế hoạch Dự án 4 Tuần (Phiên bản Tối ưu)

> **Mục tiêu:** Xây dựng hệ thống Group Chat Client-Server bằng C++ với trọng tâm **bảo mật đa lớp**, phù hợp tiêu chuẩn kỹ thuật của VCS (Viettel Cyber Security).

---

## Tổng quan kiến trúc
VCS SecureChat
├── Transport Layer   — TCP socket, custom binary protocol, TLS-like handshake
├── Crypto Layer      — OpenSSL (AES-256-GCM, RSA-2048, HMAC-SHA256)
├── Auth Layer        — Session tokens, bcrypt/PBKDF2, privilege separation
├── Application Layer — Multi-room chat, file transfer, TUI, admin system
└── Audit & Ops Layer — Logging, rate limiting, basic IDS


---

## Tóm tắt 4 tuần (Phiên bản tối ưu)

| Tuần | Tên giai đoạn            | Trọng tâm                                              | Deliverable chính                          |
|------|--------------------------|--------------------------------------------------------|--------------------------------------------|
| 1    | **Core Foundation**      | Socket server, thread pool, binary protocol, SQLite    | Server + Client chat 1-1 cơ bản            |
| 2    | **Security Core**        | OpenSSL crypto, RSA handshake, HMAC, Auth + Session    | Mọi kết nối được mã hóa end-to-end         |
| 3    | **Advanced Features**    | Multi-room, TUI, file transfer, chat history           | UX hoàn chỉnh, lưu trữ bền vững            |
| 4    | **Hardening & Polish**   | Rate limit, audit log, admin, benchmark, docs          | Production-ready + tài liệu đầy đủ         |

---

## Cấu trúc thư mục tổng thể

vcs-securechat/
├── CMakeLists.txt
├── README.md
├── PROJECT_PLAN.md
│
├── server/
│   ├── main.cpp
│   ├── core/           (TcpServer, ThreadPool, ClientSession, EventLoop)
│   ├── protocol/       (Packet, Parser, Builder)
│   ├── security/       (CryptoEngine, KeyExchange, AuthManager, SessionToken, RateLimiter, AuditLogger)
│   ├── rooms/          (RoomManager, Room, ChatHistory)
│   ├── features/       (FileTransfer, AdminCommands, MessageFilter)
│   └── utils/          (Logger, Config, Utils)
│
├── client/
│   ├── main.cpp
│   ├── core/           (TcpClient, ConnectionManager, MessageQueue)
│   ├── security/       (ClientCrypto, CertVerifier)
│   ├── ui/             (TuiManager, ChatWindow, InputHandler, Notifier)
│   └── commands/       (CommandParser, CommandHandler)
│
├── common/
│   ├── Protocol.h
│   ├── Constants.h
│   ├── MessageTypes.h
│   └── ErrorCodes.h
│
├── tests/
│   ├── test_crypto.cpp
│   ├── test_protocol.cpp
│   ├── test_auth.cpp
│   └── benchmark_load.cpp
│
├── scripts/
│   ├── build.sh
│   ├── run_server.sh
│   ├── run_client.sh
│   └── benchmark.sh
│
├── docs/
│   ├── PROTOCOL_SPEC.md
│   ├── SECURITY_DESIGN.md
│   ├── API_COMMANDS.md
│   └── THREAT_MODEL.md
│
└── logs/ (gitignore)


---

## Dependencies

| Thư viện           | Mục đích                              | Bắt buộc |
|--------------------|---------------------------------------|----------|
| `OpenSSL`          | AES-GCM, RSA, HMAC, SHA256, random    | ✅        |
| `ncurses`          | Terminal UI cho client                | ✅        |
| `pthread`          | Threading                             | ✅        |
| `SQLite3`          | Chat history & user database          | ✅        |
| `nlohmann/json`    | Config, audit log                     | ✅        |
| `CMake 3.15+`      | Build system                          | ✅        |

---

## Mục tiêu hiệu năng

| Chỉ số                           | Mục tiêu          |
|----------------------------------|-------------------|
| Concurrent clients               | ≥ 100             |
| Message throughput (localhost)   | ≥ 4.000 msg/s     |
| Latency P99 (localhost)          | < 15 ms           |
| Startup time server              | < 500 ms          |
| Memory per client session        | < 2 MB            |

---

## Tính năng bảo mật — Tổng hợp

| Tính năng                          | Layer     | Tuần |
|------------------------------------|-----------|------|
| AES-256-GCM session encryption     | Crypto    | 2    |
| RSA-2048 key exchange + cert check | Crypto    | 2    |
| HMAC-SHA256 packet integrity       | Protocol  | 2    |
| Password hashing (bcrypt)          | Auth      | 2    |
| Secure session token               | Auth      | 2    |
| Replay attack prevention (nonce)   | Protocol  | 2    |
| Token bucket rate limiter          | Security  | 4    |
| Basic intrusion detection          | Security  | 4    |
| Audit logging (signed entries)     | Audit     | 4    |
| IP blacklist                       | Security  | 4    |
| Privilege separation (admin/user)  | Auth      | 3    |
| Secure file transfer + checksum    | Features  | 3    |
| Graceful shutdown                  | Core      | 1    |

---

## Ghi chú quan trọng

- **Crypto**: Sử dụng **OpenSSL hoàn toàn** (không implement lại AES/RSA/HMAC từ đầu).
- **Database**: Sử dụng **SQLite** để lưu user, chat history và audit log.
- **Scope**: Tập trung hoàn thành chất lượng cao thay vì dàn trải quá nhiều tính năng phức tạp.
- **Ưu tiên**: Bảo mật > Tính năng > Hiệu năng > Tính thẩm mỹ.

---

## Liên kết chi tiết từng tuần
- [Week 1 — Core Foundation](./week_01_core_foundation.md)
- [Week 2 — Security Core](./week_02_security_core.md)
- [Week 3 — Advanced Features](./week_03_advanced_features.md)
- [Week 4 — Hardening & Ops](./week_04_hardening_ops.md)