# Kiến trúc và Luồng Xử Lý Của VCS SecureChat Server

Tài liệu này phân tích chi tiết luồng dữ liệu (Data Flow) và vai trò của từng module bên trong thư mục `/server` của hệ thống VCS SecureChat. Server được thiết kế theo mô hình **Event-Driven (epoll)** kết hợp **Thread Pool** để đảm bảo năng lực xử lý đồng thời (High Concurrency) với hiệu năng cao, cùng hệ thống bảo mật đa lớp.

---

## 1. Luồng Xử Lý Gói Tin (Packet Flow)

Luồng đi của một gói tin từ Client gửi đến Server và phản hồi lại diễn ra theo các bước sau:

1. **Nhận Dữ Liệu (Network I/O):**
   - Sự kiện `EPOLLIN` được kích hoạt tại luồng chính (`TcpServer::epollLoop`).
   - Hàm `recv` lấy raw bytes từ socket và đẩy vào `ClientSession::appendAndParseBytes`.
2. **Bóc Tách Khung (Packet Framing & Verification):**
   - `ClientSession` cắt bytes thành từng gói `Packet` dựa vào độ dài `payload_length`.
   - Kiểm tra `Magic Bytes`, `Version` và tính toán `CRC32 Checksum` để loại bỏ gói tin hỏng/nhiễu.
3. **Phân Luồng & Giải Mã (Concurrency & Decryption):**
   - Thay vì bắt luồng `epoll` đợi, `ClientSession` đẩy toàn bộ gói tin thô (raw packet) vào hàng đợi của `ThreadPool`.
   - Các Worker Threads lấy gói tin ra, thông qua `CryptoEngine` để giải mã **AES-256-GCM**.
4. **Định Tuyến & Xử Lý (Routing & Handling):**
   - Tại `TcpServer::handlePacket`, hệ thống kiểm tra `msg_type` và điều hướng tới các hàm xử lý tương ứng (ví dụ: `handleChatSend`, `handleConnectRequest`, tính năng Admin...).
   - Nếu là lệnh `/ban`, `/kick`, nó gọi sang `AdminCommands`. Nếu là mã hóa, gọi sang `KeyExchange`.
5. **Mã Hóa & Phản Hồi (Encryption & Sending):**
   - Các hàm xử lý tạo gói tin phản hồi thông qua `Builder`.
   - Khi gọi `sess->sendPacket(pkt)`, gói tin sẽ được `CryptoEngine` mã hóa ngược lại bằng AES và gửi trả Client qua hàm `send()` với cờ `MSG_NOSIGNAL`.

---

## 2. Chi Tiết Các Thành Phần Cốt Lõi (Modules)

Toàn bộ mã nguồn server được tổ chức thành các thư mục chuyên trách:

### 2.1. Lõi Mạng & Concurrency (`/server/core/`)
- **`TcpServer.cpp / .h`**: Trái tim của Server. Khởi tạo `epoll`, vòng lặp vô tận (Event Loop) chấp nhận kết nối (`accept`). Duy trì danh sách các Client (`m_sessions`). Đây cũng là nơi chứa thuật toán `O(1)` khi ngắt kết nối (xóa FD trực tiếp bằng `room_name`).
- **`ClientSession.cpp / .h`**: Đại diện cho một kết nối TCP từ Client. Quản lý trạng thái xác thực (authenticated), thông tin nick, phòng hiện tại, và bộ đệm nhị phân `m_readBuffer`.
- **`ThreadPool.cpp / .h`**: Cung cấp hàng đợi tác vụ đa luồng (Worker Queue). Nhiệm vụ nặng như Giải mã AES, Truy vấn Database (SQLite) được chuyển giao cho Pool này để không chặn đứng `epoll`.
- **`EventLoop.cpp / .h`**: Chứa logic xử lý các sự kiện hẹn giờ (Timers) hoặc lập lịch tác vụ ngầm định kì (nếu có mở rộng).

### 2.2. Giao Thức Nhị Phân (`/server/protocol/`)
- **`Packet.cpp / .h`**: Định nghĩa cấu trúc chuẩn của một gói tin (Header 16-byte: Magic, Version, Type, PayloadLength, CRC32) và dữ liệu (Payload).
- **`Builder.cpp / .h`**: Chuyên đóng gói các đối tượng/thông báo thành `Packet` (Ví dụ: `makeSystemNotify`, `makeConnectReject`).
- **`Parser.cpp / .h`**: Chuyên bóc tách dữ liệu JSON từ Payload của `Packet` an toàn (sử dụng try-catch bảo vệ Server khỏi các JSON dị dạng).

### 2.3. Bảo Mật & Phòng Chống Xâm Nhập (`/server/security/`)
- **`CryptoEngine.cpp / .h`**: Chịu trách nhiệm mã hóa và giải mã chuẩn AES-256-GCM. Quản lý các Secret Key của từng phiên `fd`.
- **`KeyExchange.cpp / .h`**: Xử lý bắt tay mã hóa lai (Hybrid Crypto). Dùng RSA-2048 để trao đổi an toàn khóa AES khi Client vừa kết nối.
- **`AuthManager.cpp / .h`**: Kết nối với `Database` SQLite. Quản lý việc Đăng ký, Đăng nhập (hashing mật khẩu), cấp Token phiên và quản lý danh sách `RoomBans` (danh sách đen của phòng).
- **`IntrusionDetector.cpp / .h` (IDS)**: Tường lửa tự động phân tích hành vi. Nó tính điểm rủi ro cho mỗi IP (Vd: Sai mật khẩu 10 lần, spam kết nối). Nếu vượt ngưỡng, tự động ban IP tạm thời hoặc vĩnh viễn.
- **`RateLimiter.cpp / .h`**: Thuật toán Token-Bucket giới hạn tốc độ (VD: 3 lần đăng nhập/giây, 5 tin nhắn/giây). Nếu Client spam, gói tin lập tức bị DROP.
- **`SessionToken.cpp / .h`**: Sinh mã Token HMAC (JWT-like) phục vụ tính năng Reconnect đứt kết nối.
- **`AuditLogger.cpp / .h`**: Lưu vết an ninh nghiêm ngặt (Tài khoản nào đăng nhập IP nào, bị đá lúc mấy giờ) ra file phục vụ điều tra.

### 2.4. Tính Năng Nghiệp Vụ (`/server/features/`)
- **`AdminCommands.cpp / .h`**: Giải quyết logic của các lệnh quản trị cao cấp (Ví dụ: `/kick`, `/ban`, `/mute`, `/promote`, `/rooms_admin`).
- **`FileTransfer.cpp / .h`**: Xử lý quá trình truyền tải file Peer-to-Server-to-Peer. Ràng buộc đuôi file hợp lệ, kích thước tối đa, tạo `transfer_id`, và chuyển tiếp các gói `MSG_FILE_DATA`.
- **`MessageFilter.cpp / .h`**: Lọc các từ ngữ tục tĩu (Profanity Filter) trước khi Broadcast tin nhắn.

### 2.5. Trạng Thái Phòng Chat (`/server/rooms/`)
- **`RoomManager.cpp / .h`**: Mặc dù `TcpServer` cũng quản lý danh sách thành viên các phòng, RoomManager sinh ra để quản lý logic phòng độc lập nếu hệ thống mở rộng đa luồng phức tạp hơn.
- **`Room.cpp / .h`**: Mô tả cấu trúc dữ liệu của một phòng, danh sách members, cấu hình phòng, mật khẩu.
- **`ChatHistory.cpp / .h`**: Lưu trữ tạm thời (In-memory buffer) một vài tin nhắn gần nhất của phòng để gửi cho user ngay khi họ `/join`.

### 2.6. Lõi Tiện Ích & Entry Point (`/server/utils/` & `main.cpp`)
- **`main.cpp`**: Điểm khởi đầu (Entry Point). Load Config -> Khởi tạo Log -> Mở Database -> Khởi động CryptoEngine -> Chạy TcpServer -> Đóng an toàn khi nhấn Ctrl+C.
- **`Database.cpp / .h`**: Wrapper bọc bộ thư viện `sqlite3`. Tạo Singleton với tính năng WAL (Write-Ahead Logging) giúp tối ưu cho môi trường đa luồng.
- **`Config.cpp / .h`**: Đọc cấu hình Server từ `server_config.json` (Số lượng thread, port, database path...).
- **`Logger.cpp / .h`**: Cung cấp các Macro ghi log `LOG_INFO`, `LOG_ERROR`, in màu ra console và lưu xuống file log, đồng thời tránh đụng độ (thread-safe).
