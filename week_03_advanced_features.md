# Tuần 3 — Advanced Features

> **Mục tiêu tuần 3:** Nâng cấp từ "demo chat" lên "production-like system" với multi-room, TUI đẹp, file transfer có bảo mật, admin system, và chat history persistence.

---

## Checklist cuối tuần 3

- [x] ncurses TUI: chia màn hình chat / input area / sidebar user list
- [x] Multi-room: `/join`, `/leave`, `/rooms`, `/create`
- [x] Chat history: 100 tin nhắn gần nhất lưu xuống file, gửi cho client mới join
- [x] File transfer: `/send <user> <file>` với AES-encrypt + SHA256 checksum
- [x] Private message: `/msg <user> <text>`
- [x] Admin system: `/kick`, `/mute`, `/ban`, `/promote`
- [x] Message filtering: chặn nội dung độc hại, SQL injection attempt
- [x] Typing indicator: hiển thị "Alice is typing..."
- [x] Read receipt: server xác nhận đã nhận message
- [x] Online presence: trạng thái ONLINE / AWAY / BUSY

---

## Cấu trúc file tuần 3 (bổ sung)

```
vcs-securechat/
├── server/
│   ├── rooms/                       ← MỚI
│   │   ├── RoomManager.h / .cpp
│   │   ├── Room.h / .cpp
│   │   └── ChatHistory.h / .cpp
│   └── features/                    ← MỚI
│       ├── FileTransfer.h / .cpp
│       ├── AdminCommands.h / .cpp
│       └── MessageFilter.h / .cpp
└── client/
    ├── ui/                          ← MỚI (thay thế simple stdin/stdout)
    │   ├── TuiManager.h / .cpp
    │   ├── ChatWindow.h / .cpp
    │   ├── InputHandler.h / .cpp
    │   └── Notifier.h / .cpp
    └── commands/                    ← MỚI
        ├── CommandParser.h / .cpp
        └── CommandHandler.h / .cpp
```

---

## Chi tiết từng file

---

### `client/ui/TuiManager.h / .cpp`

**Mục đích:** Quản lý toàn bộ giao diện ncurses — khởi tạo, vẽ, cleanup

**Layout màn hình:**
```
┌─────────────────────────────────────────────────────────────┐
│  VCS SecureChat v1.0  │ Room: #general │ [🔒 Encrypted]     │  ← HEADER (1 line)
├──────────────────────────────────────────┬──────────────────┤
│                                          │  Online (3)      │
│  [10:32] Alice: Hello everyone!          │  ● Alice         │
│  [10:33] Bob: Hey Alice!                 │  ● Bob           │
│  [10:33] *** Charlie joined #general     │  ● Charlie       │  ← CHAT AREA
│  [10:34] Charlie: Hi all!                │                  │  (LINES-6 rows)
│  [10:35] Bob is typing...                │  ─────────────   │
│                                          │  Rooms (2)       │
│                                          │  # general       │
│                                          │  # random        │
├──────────────────────────────────────────┴──────────────────┤
│  #general > _                                               │  ← INPUT BAR (3 lines)
│  /help for commands                                         │
└─────────────────────────────────────────────────────────────┘
```

**Nội dung quan trọng:**
```
TuiManager class:
  Fields:
    - chat_win    : std::unique_ptr<WINDOW, decltype(&delwin)> (vùng hiển thị tin nhắn, quản lý chuẩn RAII)
    - input_win   : std::unique_ptr<WINDOW, decltype(&delwin)> (thanh nhập liệu)
    - sidebar_win : std::unique_ptr<WINDOW, decltype(&delwin)> (danh sách user + rooms)
    - header_win  : std::unique_ptr<WINDOW, decltype(&delwin)> (status bar)
    - scroll_pos  : int       (vị trí scroll)
    - msg_history : deque<string> (tin nhắn đã hiển thị, max 500)

  Methods:
    - initialize()           : initscr(), cbreak(), noecho(), keypad()
    - createWindows()        : tính toán kích thước terminal, tạo 4 windows
    - refresh()              : vẽ lại tất cả windows
    - addMessage(msg)        : thêm tin nhắn vào chat_win, auto-scroll
    - getInput() → string    : đọc input từ user (xử lý backspace, arrow keys)
    - updateSidebar(users, rooms) : vẽ lại sidebar
    - updateHeader(room, encrypted) : cập nhật status bar
    - showNotification(text) : flash notification 2 giây
    - onResize()             : xử lý SIGWINCH — terminal resize
    - cleanup()              : endwin()

  Color pairs (ncurses):
    - PAIR 1: Timestamp (cyan)
    - PAIR 2: Nickname (green for others, bold white for self)
    - PAIR 3: System message (yellow)
    - PAIR 4: Private message (magenta)
    - PAIR 5: Admin action (red)
    - PAIR 6: Header bar (blue background)
    - PAIR 7: Error (red bold)
    - PAIR 8: Encrypted indicator (green bold)
```

---

### `client/ui/InputHandler.h / .cpp`

**Mục đích:** Xử lý keyboard input với lịch sử lệnh và autocomplete nickname

**Nội dung quan trọng:**
```
InputHandler class:
  Features:
    - Command history: mũi tên ↑↓ xem lại lệnh đã gõ (max 50)
    - Tab completion: gõ /k[Tab] → /kick, hoặc gõ Al[Tab] → Alice
    - Ctrl+C: confirm quit (hỏi "Really quit? [y/n]")
    - Ctrl+L: clear chat window
    - PgUp/PgDn: scroll chat history
    - Ctrl+P/N: điều hướng giữa các rooms

  InputBuffer:
    - current_input : string
    - cursor_pos    : int      (cho insert mode)
    - history       : deque<string>
    - history_idx   : int

  Methods:
    - processKey(int ch) → {SUBMIT, CONTINUE, QUIT, SCROLL_UP, SCROLL_DOWN}
    - getBuffer() → string
    - clearBuffer()
    - addToHistory(cmd)
    - autoComplete()         : hoàn thành lệnh hoặc nickname
```

---

### `client/commands/CommandParser.h / .cpp`

**Mục đích:** Parse và validate user input — phân biệt lệnh vs tin nhắn thường

**Nội dung quan trọng:**
```
Tất cả lệnh được hỗ trợ:
  /quit                      → ngắt kết nối, thoát
  /list                      → danh sách user online trong room hiện tại
  /listall                   → danh sách tất cả user trên server
  /rooms                     → danh sách tất cả rooms
  /join #room_name            → vào room (tạo mới nếu chưa có)
  /leave                     → rời room hiện tại
  /create #room_name          → tạo room mới (explicit)
  /msg <nickname> <text>      → tin nhắn riêng
  /send <nickname> <filepath> → gửi file
  /away [message]             → set trạng thái AWAY
  /back                       → set trạng thái ONLINE
  /busy [message]             → set trạng thái BUSY
  /whois <nickname>           → xem info của user
  /help [command]             → hiển thị help

  Admin only:
  /kick <nickname> [reason]
  /mute <nickname> <seconds>
  /unmute <nickname>
  /ban <nickname> [reason]
  /unban <nickname>
  /promote <nickname>         → nâng lên ADMIN
  /demote <nickname>
  /broadcast <message>        → gửi tới tất cả rooms
  /shutdown [seconds]         → shutdown server sau N giây

CommandParser class:
  Methods:
    - parse(input_string) → Command
    - isCommand(string) → bool   (bắt đầu bằng '/')
    - validate(Command) → {VALID, INVALID, REQUIRES_ADMIN}

Command struct:
    - type    : CommandType enum
    - args    : vector<string>
    - raw     : string
```

---

### `server/rooms/Room.h / .cpp`

**Mục đích:** Đại diện một room chat với subscriber list và state riêng

**Nội dung quan trọng:**
```
Room class:
  Fields:
    - name        : string              (e.g. "general", "dev-team")
    - topic       : string              (mô tả room, do admin set)
    - members     : set<int>            (fd của các client trong room)
    - created_at  : time_t
    - creator     : string              (nickname người tạo)
    - is_private  : bool                (private room yêu cầu invite)
    - password    : string              (optional, PBKDF2 hashed)
    - max_members : int                 (mặc định 50)
    - room_mutex  : shared_mutex        (concurrent read/write members)

  Methods:
    - addMember(fd)
    - removeMember(fd)
    - broadcast(packet, exclude_fd=-1)  : gửi tới tất cả thành viên
    - isMember(fd) → bool
    - getMemberCount() → int
    - getMemberList() → vector<string>  (nicknames)
    - isFull() → bool
```

---

### `server/rooms/RoomManager.h / .cpp`

**Mục đích:** Quản lý tập hợp tất cả rooms, điều phối join/leave/create

**Nội dung quan trọng:**
```
RoomManager class (singleton):
  Fields:
    - rooms : map<string, Room*>
    - rooms_mutex : shared_mutex

  Methods:
    - initialize()       : tạo room "general" mặc định
    - createRoom(name, creator) → {room, ErrorCode}
    - deleteRoom(name, requester) → ErrorCode  (chỉ creator hoặc OWNER)
    - joinRoom(fd, nickname, room_name) → ErrorCode
        + kiểm tra room tồn tại
        + kiểm tra không đầy
        + nếu private → kiểm tra password / invite
        + gửi MSG_SYSTEM_NOTIFY "<nick> joined #room" cho tất cả thành viên
        + gửi chat history (100 tin gần nhất) cho client mới
    - leaveRoom(fd, nickname, room_name)
        + gửi MSG_SYSTEM_NOTIFY "<nick> left #room"
        + nếu room trống và không phải "general" → auto-delete
    - broadcastToRoom(room_name, packet, exclude_fd)
    - getRoomList() → vector<RoomInfo>
    - getUserRoom(fd) → string   (room hiện tại của fd)
    - moveUser(fd, from_room, to_room)
```

---

### `server/rooms/ChatHistory.h / .cpp`

**Mục đích:** Lưu lịch sử chat per-room, đọc lại khi user mới vào

**Nội dung quan trọng:**
```
HistoryEntry struct:
  - timestamp   : time_t
  - sender      : string
  - room        : string
  - message     : string         (PLAINTEXT — không lưu ciphertext)
  - msg_type    : MessageType    (CHAT, SYSTEM, FILE_NOTIFY)

ChatHistory class:
  Fields:
    - ring_buffer : deque<HistoryEntry>  (max HISTORY_BUFFER_SIZE = 100)
    (Sử dụng server/utils/Database để lưu trữ lâu dài)

  Methods:
    - append(entry)              : thêm vào ring buffer + INSERT vào bảng ChatHistory (SQLite)
    - getRecent(n=50) → vector   : lấy N tin gần nhất từ ring_buffer hoặc từ SQLite
    - serializeForClient(entries) → Packet : đóng gói lịch sử gửi cho client mới
    - cleanupOldHistory()        : tự động xoá tin nhắn quá 30 ngày trong db

  Database Table (ChatHistory trong SQLite):
    - id (INTEGER PRIMARY KEY AUTOINCREMENT)
    - timestamp (INTEGER)
    - sender (TEXT)
    - room (TEXT)
    - message (TEXT)
    - msg_type (TEXT)

  Bảo mật:
    - File db `vcs_chat.db` có permission 600 (chỉ owner đọc được)
    - Tự động cleanup data cũ để tối ưu query
    - Tên file/tables không rò rỉ dữ liệu nhạy cảm ra ngoài hệ thống
```

---

### `server/features/FileTransfer.h / .cpp`

**Mục đích:** Gửi file giữa 2 client qua server relay, với mã hoá và kiểm tra toàn vẹn

**Nội dung quan trọng:**
```
FileTransferSession struct:
  - transfer_id  : string           (UUID, unique per transfer)
  - sender_fd    : int
  - receiver_fd  : int
  - filename     : string
  - file_size    : uint64_t
  - sha256_hash  : string           (hash trước khi gửi, dùng để verify)
  - chunks_total : int
  - chunks_recv  : int
  - temp_path    : string           (server lưu tạm file đang nhận)
  - start_time   : time_t
  - status       : enum {PENDING, ACCEPTED, IN_PROGRESS, COMPLETE, FAILED}

FileTransfer class:
  Fields:
    - active_transfers : map<transfer_id, FileTransferSession>

  Protocol flow:
    Client A → Server: MSG_FILE_REQUEST
      { to: "Bob", filename: "design.pdf", size: 1024000, sha256: "abc..." }
    Server → Client B: MSG_FILE_REQUEST (relay)
    Client B → Server: MSG_FILE_ACCEPT / MSG_FILE_REJECT
    Server → Client A: forward accept/reject
    If accepted:
      Client A → Server: MSG_FILE_CHUNK x N
        { transfer_id: "...", chunk_num: 0, data: [4096 bytes AES-encrypted] }
      Server relay → Client B
      Client B verify: SHA256(reassembled) == original_hash
      Client B → Server: MSG_FILE_COMPLETE / MSG_ERROR

  Giới hạn:
    - MAX_FILE_SIZE = 10 MB (configurable)
    - CHUNK_SIZE = 4096 bytes
    - Transfer timeout = 120 giây
    - Chỉ cho phép extension: .txt .pdf .png .jpg .zip .cpp .h .md (whitelist)

  Bảo mật:
    - Filename được sanitize: loại bỏ path traversal (../, /etc/passwd, v.v.)
    - Server KHÔNG giải mã nội dung file — relay opaque bytes
    - Hash verify phía receiver để server không can thiệp được
    - Auto-delete temp file sau khi relay xong hoặc timeout
```

---

### `server/features/AdminCommands.h / .cpp`

**Mục đích:** Xử lý admin commands với kiểm tra quyền và audit trail

**Nội dung quan trọng:**
```
AdminCommands class:
  Tất cả methods đều ghi vào AuditLogger trước khi thực thi.

  kick(admin_fd, target_nickname, reason):
    + verify admin_fd có role ADMIN hoặc OWNER
    + gửi MSG_SYSTEM_NOTIFY "target was kicked by admin: reason"
    + gửi MSG_DISCONNECT tới target
    + đóng socket target
    + log: ADMIN_ACTION kick admin=Alice target=Bob reason="..." time=...

  mute(admin_fd, target_nickname, duration_seconds):
    + set ClientSession.is_muted = true, mute_until = now + duration
    + mọi MSG_CHAT_SEND từ target trong thời gian muted → server trả ERR_MUTED
    + gửi notification cho room: "Bob has been muted for 5 minutes"

  ban(admin_fd, target_nickname, reason):
    + thêm IP của target vào ban_list (lưu file ban_list.json)
    + kick target
    + mọi kết nối từ IP bị ban → server reject ngay lập tức

  unban(admin_fd, ip_or_nickname):
    + xoá khỏi ban_list

  promote(admin_fd, target_nickname):
    + chỉ OWNER mới có thể promote lên ADMIN
    + update role trong AuthManager

  broadcast(admin_fd, message):
    + gửi tới tất cả rooms với tag [SERVER BROADCAST]
    + highlight màu đặc biệt trên TUI

  Phân quyền:
    GUEST  : chỉ đọc (nếu room cho phép guests)
    USER   : gửi tin, join room, file transfer
    ADMIN  : kick, mute, ban user, broadcast
    OWNER  : toàn bộ ADMIN + promote/demote, shutdown server
```

---

### `server/features/MessageFilter.h / .cpp`

**Mục đích:** Lọc tin nhắn trước khi broadcast — bảo vệ hệ thống và người dùng

**Nội dung quan trọng:**
```
MessageFilter class:
  FilterResult enum:
    PASS
    BLOCKED_SPAM
    BLOCKED_INJECTION
    BLOCKED_PROFANITY      (optional)
    REDACTED               (một phần bị che)

  Methods:
    - filter(message, sender_fd) → {FilterResult, sanitized_message}

  Các kiểm tra:
    1. Length check: > MAX_MESSAGE_LEN → BLOCKED
    2. Rate check:   > RATE_LIMIT_MSG_PER_SEC → BLOCKED_SPAM
    3. SQL/Command injection detection:
          Regex patterns: DROP TABLE, SELECT * FROM, <script>, eval(, ../
          → BLOCKED_INJECTION + log cảnh báo
    4. Null byte injection: chứa \x00 → BLOCKED
    5. Unicode normalization: normalize NFC để tránh homograph attack
    6. URL filtering: log tất cả URL trong tin nhắn (cho audit)

  Lưu ý:
    - Các lần filter fail được log vào audit log
    - Không tự động block → log để admin review
    - Injection detection alert được escalate lên WARN level
```

---

### `server/security/AuditLogger.h / .cpp`

**Mục đích:** Ghi lại mọi hành động quan trọng — tamper-evident audit trail

**Nội dung quan trọng:**
```
AuditEvent struct:
  - event_id    : string   (UUID)
  - timestamp   : time_t
  - event_type  : enum {AUTH, CONNECT, DISCONNECT, MESSAGE, FILE, ADMIN, SECURITY}
  - actor       : string   (nickname hoặc IP)
  - target      : string   (nếu có)
  - action      : string
  - result      : enum {SUCCESS, FAILURE, BLOCKED}
  - ip_address  : string
  - details     : string   (JSON string cho context thêm)
  - prev_hash   : string   (SHA256 của event trước — chain integrity)

AuditLogger class (singleton):
  Fields:
    - prev_hash   : string    (SHA256 của event cuối, khởi tạo = "GENESIS")
    - buffer      : deque<AuditEvent> (flush 100 events hoặc 5 phút 1 lần)
    - log_mutex   : mutex
    (Sử dụng server/utils/Database để thao tác trực tiếp với bảng AuditLog)

  Methods:
    - log(event)             : thêm vào buffer, tính prev_hash chain
    - flush()                : INSERT buffer vào bảng AuditLog (SQLite)
    - verifyChain()          : truy vấn bảng AuditLog theo thứ tự, kiểm tra chain toàn vẹn
    - exportToCSV(filepath)  : xuất audit trail từ database sang CSV cho compliance

  Tamper-evident chain:
    event[0].hash = SHA256(event[0].data + "GENESIS")
    event[1].hash = SHA256(event[1].data + event[0].hash)
    event[n].hash = SHA256(event[n].data + event[n-1].hash)
    → Nếu ai trực tiếp sửa row `k` trong SQLite, tất cả hash từ `k+1` trở đi sẽ sai
    → verifyChain() phát hiện ngay

  Events được log:
    - Mỗi lần login thành công/thất bại
    - Mỗi lần connect/disconnect
    - Tất cả admin commands
    - Security alerts (replay attack, HMAC fail, injection attempt)
    - File transfer start/complete/fail
    - Server start/stop
```

---

## Kết quả kiểm thử cuối tuần 3

```bash
# Test TUI: chạy 2 client, kiểm tra:
# - Sidebar hiển thị đúng user list khi join/leave
# - Màu sắc phân biệt các loại tin nhắn
# - Arrow keys cuộn lịch sử chat
# - Tab completion hoạt động

# Test multi-room:
# Alice: /create #devteam → "Room #devteam created"
# Alice: /join #devteam
# Bob: /rooms → thấy #general và #devteam
# Bob: /join #devteam → nhận 50 tin gần nhất của room

# Test file transfer:
# Alice: /send Bob test_file.txt
# Bob thấy: "Alice wants to send test_file.txt (1.2 KB). /accept or /reject"
# Bob: /accept → file transfer, Bob nhận được và SHA256 khớp

# Test admin:
# Đăng nhập admin, thực hiện /kick Alice → Alice bị kick
# Kiểm tra audit log có ghi lại event

# Test message filter:
# Gửi "SELECT * FROM users" → bị block, audit log có cảnh báo
```
