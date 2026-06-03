# Tuần 1 — Core Foundation

> **Mục tiêu tuần 1:** Dựng khung hệ thống hoàn chỉnh. Cuối tuần phải có server nhận nhiều kết nối đồng thời, tích hợp database SQLite và client gửi/nhận tin nhắn qua terminal.

---

## Checklist cuối tuần 1

- [x] Server lắng nghe TCP, chấp nhận nhiều client cùng lúc
- [x] Thread pool xử lý mỗi client trên 1 worker thread
- [x] Binary protocol với header chuẩn (không dùng raw string)
- [x] Client kết nối, đặt nickname, gửi/nhận tin nhắn
- [x] Broadcast: server phân phát tin đến tất cả client
- [x] Thông báo join/leave toàn phòng
- [x] Graceful shutdown: server nhận SIGINT, đóng sạch tất cả socket
- [x] Config file JSON: port, max clients, thread pool size
- [x] Khởi tạo database SQLite (`vcs_chat.db`) sẵn sàng cho lưu trữ

---

## Cấu trúc file tuần 1 (cần tạo)

```
vcs-securechat/
├── CMakeLists.txt
├── common/
│   ├── Protocol.h
│   ├── Constants.h
│   ├── MessageTypes.h
│   └── ErrorCodes.h
├── server/
│   ├── main.cpp
│   ├── core/
│   │   ├── TcpServer.h / .cpp
│   │   ├── ThreadPool.h / .cpp
│   │   ├── ClientSession.h / .cpp
│   │   └── EventLoop.h / .cpp
│   ├── protocol/
│   │   ├── Packet.h / .cpp
│   │   ├── Parser.h / .cpp
│   │   └── Builder.h / .cpp
│   └── utils/
│       ├── Logger.h / .cpp
│       ├── Config.h / .cpp
│       └── Database.h / .cpp
└── client/
    ├── main.cpp
    └── core/
        ├── TcpClient.h / .cpp
        └── MessageQueue.h / .cpp
```

---

## Chi tiết từng file

---

### `CMakeLists.txt`

**Mục đích:** Build system toàn dự án

**Nội dung quan trọng:**
- Khai báo `cmake_minimum_required(VERSION 3.15)`
- Hai target: `vcs_server` và `vcs_client`
- Compile flags: `-std=c++17 -Wall -Wextra -O2`
- Link: `pthread`, `ncurses`, `OpenSSL::SSL`, `OpenSSL::Crypto`
- Include directories: `common/`, `crypto/`
- Subdirectory: `server/`, `client/`, `tests/`

---

### `common/Protocol.h`

**Mục đích:** Định nghĩa cấu trúc packet dùng chung giữa server và client

**Nội dung quan trọng:**
```
PacketHeader struct:
  - magic[2]       : 0xVC 0x53  (VCS signature)
  - version        : uint8_t    (protocol version, hiện tại = 1)
  - msg_type       : uint8_t    (xem MessageTypes.h)
  - flags          : uint8_t    (ENCRYPTED, COMPRESSED, FRAGMENTED bits)
  - sequence_num   : uint32_t   (chống replay attack — tuần 2 dùng)
  - payload_length : uint32_t   (độ dài phần data sau header)
  - checksum       : uint32_t   (CRC32 của payload)

Packet struct:
  - header  : PacketHeader
  - payload : std::vector<uint8_t>

Tổng header size = 15 bytes (fixed)
```

**Lý do thiết kế:** Fixed-length header giúp parse không bị ambiguous. Magic bytes `0xVC53` là chữ ký nhận diện VCS.

---

### `common/Constants.h`

**Mục đích:** Tập trung tất cả hằng số — tránh magic number rải rác

**Nội dung quan trọng:**
```cpp
DEFAULT_PORT          = 9000
MAX_CLIENTS           = 256
THREAD_POOL_SIZE      = 32
MAX_NICKNAME_LEN      = 32
MAX_MESSAGE_LEN       = 4096
MAX_ROOM_NAME_LEN     = 64
MAX_ROOMS             = 32
SESSION_TIMEOUT_SEC   = 3600        // 1 giờ
RATE_LIMIT_MSG_PER_SEC = 10
MAGIC_BYTE_0          = 0xVC
MAGIC_BYTE_1          = 0x53
PROTOCOL_VERSION      = 1
MAX_FILE_SIZE_MB      = 10
HISTORY_BUFFER_SIZE   = 100         // 100 tin nhắn gần nhất
AUTH_MAX_ATTEMPTS     = 5           // chống brute force — tuần 4
NONCE_SIZE            = 16          // bytes, cho replay prevention
```

---

### `common/MessageTypes.h`

**Mục đích:** Enum toàn bộ loại message, cả hai chiều client↔server

**Nội dung quan trọng:**
```
Nhóm Connection:
  MSG_CONNECT_REQUEST     = 0x01  // client gửi nickname + password
  MSG_CONNECT_ACCEPT      = 0x02  // server chấp nhận, trả session token
  MSG_CONNECT_REJECT      = 0x03  // server từ chối (nick trùng, sai pass, v.v.)
  MSG_DISCONNECT          = 0x04  // báo thoát
  MSG_PING                = 0x05  // keepalive
  MSG_PONG                = 0x06

Nhóm Chat:
  MSG_CHAT_SEND           = 0x10  // client gửi tin nhắn
  MSG_CHAT_BROADCAST      = 0x11  // server broadcast tới room
  MSG_CHAT_PRIVATE        = 0x12  // tin nhắn riêng tư (DM)
  MSG_SYSTEM_NOTIFY       = 0x13  // thông báo hệ thống (join/leave)

Nhóm Room:
  MSG_ROOM_JOIN           = 0x20
  MSG_ROOM_LEAVE          = 0x21
  MSG_ROOM_LIST_REQUEST   = 0x22
  MSG_ROOM_LIST_RESPONSE  = 0x23
  MSG_ROOM_CREATE         = 0x24

Nhóm User:
  MSG_USER_LIST_REQUEST   = 0x30
  MSG_USER_LIST_RESPONSE  = 0x31

Nhóm Crypto (tuần 2):
  MSG_CRYPTO_HELLO        = 0x40  // bắt đầu key exchange
  MSG_CRYPTO_KEY_OFFER    = 0x41  // server gửi RSA public key
  MSG_CRYPTO_KEY_ACCEPT   = 0x42  // client gửi AES session key (RSA-encrypted)
  MSG_CRYPTO_HANDSHAKE_OK = 0x43  // xác nhận mã hoá đã thiết lập

Nhóm File (tuần 3):
  MSG_FILE_REQUEST        = 0x50
  MSG_FILE_ACCEPT         = 0x51
  MSG_FILE_REJECT         = 0x52
  MSG_FILE_CHUNK          = 0x53
  MSG_FILE_COMPLETE       = 0x54

Nhóm Admin (tuần 3):
  MSG_ADMIN_KICK          = 0x60
  MSG_ADMIN_MUTE          = 0x61
  MSG_ADMIN_BAN           = 0x62
  MSG_ADMIN_PROMOTE       = 0x63

Nhóm Error:
  MSG_ERROR               = 0xFF
```

---

### `common/ErrorCodes.h`

**Mục đích:** Mã lỗi chuẩn hoá trả về trong MSG_ERROR và MSG_CONNECT_REJECT

**Nội dung quan trọng:**
```
ERR_OK                    = 0x00
ERR_NICKNAME_TAKEN        = 0x01
ERR_NICKNAME_INVALID      = 0x02
ERR_ROOM_FULL             = 0x03
ERR_ROOM_NOT_FOUND        = 0x04
ERR_AUTH_FAILED           = 0x05
ERR_AUTH_TOO_MANY_ATTEMPTS= 0x06  // lockout
ERR_RATE_LIMITED          = 0x07
ERR_MESSAGE_TOO_LONG      = 0x08
ERR_FILE_TOO_LARGE        = 0x09
ERR_PERMISSION_DENIED     = 0x0A
ERR_CRYPTO_HANDSHAKE_FAIL = 0x0B
ERR_INVALID_TOKEN         = 0x0C
ERR_REPLAY_DETECTED       = 0x0D
ERR_SERVER_FULL           = 0x0E
ERR_INTERNAL              = 0xFF
```

---

### `server/core/TcpServer.h / .cpp`

**Mục đích:** TCP server nhận kết nối — trái tim của server

**Nội dung quan trọng:**
- `socket()`, `bind()`, `listen()`, `accept()` vòng lặp chính
- Mỗi connection mới → tạo `ClientSession` → đưa vào `ThreadPool`
- `setReuseAddr()` tránh "Address already in use" khi restart
- Lưu `std::unordered_map<int, ClientSession*>` — fd → session
- `shutdown()` method: đóng listening socket, gửi MSG_SYSTEM_NOTIFY "server shutting down" cho tất cả client, join tất cả threads
- Xử lý SIGINT/SIGTERM: register signal handler gọi `shutdown()`
- Giới hạn MAX_CLIENTS: Cần kiểm tra số lượng active connections ngay tại hàm `accept()`. Nếu hệ thống đã đạt MAX_CLIENTS, phải ngắt kết nối ngay (trả `ERR_SERVER_FULL` nếu kịp) để tránh cạn kiệt File Descriptor của hệ điều hành trước khi đưa vào Thread Pool.

---

### `server/core/ThreadPool.h / .cpp`

**Mục đích:** Quản lý pool cố định các worker threads xử lý I/O của clients

**Nội dung quan trọng:**
- Constructor: khởi tạo N threads (lấy từ config), mỗi thread chạy `workerLoop()`
- `submit(task)`: đẩy task (std::function) vào `std::queue`, dùng `condition_variable` để notify
- `workerLoop()`: vòng lặp vô hạn, `wait()` khi queue rỗng, `pop()` và thực thi task
- Destructor: set `stopping = true`, notify all, join tất cả threads
- Mutex bảo vệ queue — không dùng lock-free để giữ code đơn giản, dễ debug
- `pendingTasks()`: trả số task đang chờ — dùng cho monitoring

---

### `server/core/ClientSession.h / .cpp`

**Mục đích:** Đại diện cho một kết nối client, quản lý toàn bộ state của client đó

**Nội dung quan trọng:**
```
Fields:
  - fd              : int                 (socket file descriptor)
  - nickname        : std::string
  - ip_address      : std::string
  - current_room    : std::string         (room đang ở)
  - session_token   : std::string         (JWT-style — tuần 2)
  - aes_key         : std::vector<uint8_t> (session key — tuần 2)
  - is_authenticated: bool
  - is_muted        : bool
  - mute_until      : time_t
  - role            : enum {USER, ADMIN, OWNER}
  - connect_time    : time_t
  - last_active     : time_t
  - msg_count       : uint32_t            (cho rate limiter)

Methods:
  - receiveLoop()    : đọc dữ liệu từ socket, parse thành Packet
  - sendPacket(Packet): ghi packet ra socket (thread-safe với send_mutex)
  - disconnect()     : đóng socket, thông báo server
  - isTimedOut()     : kiểm tra SESSION_TIMEOUT_SEC
```

---

### `server/core/EventLoop.h / .cpp`

**Mục đích:** Loop chính điều phối events — keepalive, timeout, periodic tasks

**Nội dung quan trọng:**
- Chạy trên 1 thread riêng biệt (không phải worker thread)
- Mỗi 30 giây: gửi MSG_PING tới tất cả client, đánh dấu client không trả lời trong 60 giây là dead
- Mỗi 60 giây: dọn session đã timeout, giải phóng bộ nhớ
- Mỗi 5 phút: flush audit log buffer ra file
- Mỗi 1 giờ: rotate log file

---

### `server/utils/Logger.h / .cpp`

**Mục đích:** Logging hệ thống với nhiều level, thread-safe

**Nội dung quan trọng:**
- Levels: `DEBUG`, `INFO`, `WARN`, `ERROR`, `CRITICAL`
- Output: vừa stdout vừa file `logs/error/server_YYYYMMDD.log`
- Format: `[TIMESTAMP] [LEVEL] [THREAD_ID] message`
- Thread-safe: dùng `std::mutex` bảo vệ file write
- Log rotation: tự động tạo file mới theo ngày

---

### `server/utils/Config.h / .cpp`

**Mục đích:** Load và validate cấu hình từ `server_config.json`

**Nội dung quan trọng:**
```json
{
  "server": {
    "port": 9000,
    "max_clients": 256,
    "thread_pool_size": 32,
    "session_timeout_seconds": 3600
  },
  "security": {
    "require_auth": true,
    "max_auth_attempts": 5,
    "rate_limit_msg_per_sec": 10,
    "enable_encryption": true,
    "enable_audit_log": true
  },
  "rooms": {
    "default_room": "general",
    "max_rooms": 32,
    "history_size": 100
  },
  "admin": {
    "admin_password_hash": "..."
  }
}
```

---

### `server/protocol/Packet.h / .cpp`, `Parser.h / .cpp`, `Builder.h / .cpp`

**Mục đích:** Serialize/deserialize packet theo binary format đã định nghĩa ở `Protocol.h`

**Nội dung quan trọng:**
- `Packet`: Cấu trúc dữ liệu chứa header và payload
- `Builder::toBytes(Packet)`: chuyển Packet thành `std::vector<uint8_t>` để gửi qua socket
- `Parser::fromBytes(bytes)`: parse bytes nhận từ socket thành Packet, validate magic bytes, version
- Xử lý partial read: dùng length-prefix — đọc đủ 15 bytes header trước, rồi đọc đúng `payload_length` bytes
- `isValid()`: kiểm tra magic bytes + version + checksum

---

### `server/utils/Database.h / .cpp`

**Mục đích:** Quản lý kết nối tới SQLite database dùng chung trong hệ thống

**Nội dung quan trọng:**
- Wrapper xung quanh `sqlite3*` connection
- Tự động tạo các bảng nếu chưa có (Users, ChatHistory, AuditLog)
- Cung cấp thread-safe queries (sử dụng mutex để serialize write hoặc dùng WAL mode)
- Dùng cho tuần sau khi triển khai Auth và ChatHistory

---

### `client/core/TcpClient.h / .cpp`

**Mục đích:** Kết nối TCP tới server, quản lý socket phía client

**Nội dung quan trọng:**
- `connect(ip, port)`: tạo socket, `connect()`, xử lý lỗi
- `sendPacket(Packet)`: serialize và gửi, thread-safe
- `receiveThread()`: chạy trên background thread, đọc liên tục từ socket
- Callback `onPacketReceived(Packet)`: gọi khi nhận được packet hoàn chỉnh
- Callback `onDisconnected()`: gọi khi server đóng kết nối
- Reconnect logic: thử kết nối lại tối đa 3 lần với backoff 2s, 4s, 8s

---

### `client/core/MessageQueue.h / .cpp`

**Mục đích:** Thread-safe queue trung gian giữa receive thread và UI thread

**Nội dung quan trọng:**
- `push(Packet)`: thêm packet vào queue (gọi từ receive thread)
- `pop()`: lấy packet ra (gọi từ UI/display thread) — blocking với timeout
- `tryPop()`: non-blocking version
- Dùng `std::queue<Packet>` + `std::mutex` + `std::condition_variable`
- Max queue size = 1000 packets; nếu đầy → drop oldest (tránh memory leak)

---

### `client/main.cpp`

**Mục đích:** Entry point client — parse args, khởi tạo components, vào vòng lặp chính

**Nội dung quan trọng:**
```
Usage: ./vcs_client [--host IP] [--port PORT]
  Mặc định: host=127.0.0.1, port=9000

Flow tuần 1:
  1. Parse command line args
  2. Khởi tạo TcpClient, kết nối server
  3. Prompt nhập nickname
  4. Gửi MSG_CONNECT_REQUEST
  5. Nhận MSG_CONNECT_ACCEPT → vào vòng lặp chat
  6. Thread 1: đọc input từ stdin, gửi MSG_CHAT_SEND
  7. Thread 2: nhận packet từ socket, in ra stdout
  8. Xử lý lệnh /quit /list
```

---

### `server/main.cpp`

**Mục đích:** Entry point server

**Nội dung quan trọng:**
```
Usage: ./vcs_server [--config path/to/config.json] [--port PORT]

Flow:
  1. Load Config
  2. Khởi tạo Logger
  3. Khởi tạo ThreadPool
  4. Khởi tạo TcpServer
  5. Đăng ký SIGINT handler → gọi graceful_shutdown()
  6. server.start() — blocking
```

---

## Kết quả kiểm thử cuối tuần 1

```bash
# Terminal 1 — khởi động server
./vcs_server --config server_config.json
# Output mong đợi:
# [INFO] VCS SecureChat Server v1.0 starting...
# [INFO] Thread pool initialized: 32 workers
# [INFO] Listening on 0.0.0.0:9000
# [INFO] Press Ctrl+C to stop

# Terminal 2, 3, 4 — 3 client kết nối
./vcs_client --host 127.0.0.1 --port 9000
# Nhập nickname: Alice / Bob / Charlie

# Kiểm tra: Alice gửi tin → Bob và Charlie nhận
# Kiểm tra: /list → thấy danh sách 3 người
# Kiểm tra: Alice /quit → Bob và Charlie thấy "Alice has left"
# Kiểm tra: Ctrl+C server → tất cả client nhận thông báo
```
