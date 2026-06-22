# Kiến trúc và Luồng Xử Lý Của VCS SecureChat Client

Tài liệu này phân tích chi tiết luồng dữ liệu (Data Flow) và vai trò của từng module bên trong thư mục `/client` của hệ thống VCS SecureChat. Khác với Server (xử lý đồng thời hàng vạn kết nối), Client được thiết kế tối giản, tập trung vào **Giao diện dòng lệnh (CLI)**, **Bảo mật đa lớp (Hybrid Encryption)** và **Đa luồng cơ bản** (một luồng nhận dữ liệu, một luồng đọc bàn phím).

---

## 1. Luồng Hoạt Động Cơ Bản (Client Flow)

Quá trình Client khởi động, kết nối và gửi/nhận tin nhắn diễn ra qua các bước sau:

1. **Khởi chạy & Kết nối (Initialization & Connect):**
   - Chương trình bắt đầu từ `main.cpp`, phân tích tham số dòng lệnh (`--host`, `--port`).
   - `ConnectionManager` và `TcpClient` khởi tạo TCP Socket và kết nối tới Server.
2. **Bắt tay Mã hóa (Crypto Handshake):**
   - Ngay khi TCP được thiết lập, Client chưa được phép gửi mật khẩu.
   - `ClientCrypto` nhận RSA Public Key từ Server (và xác thực thông qua `CertVerifier`).
   - Nó sinh ra một khóa **AES-256-GCM** ngẫu nhiên (Session Key), mã hóa khóa này bằng RSA Public Key và gửi ngược lại Server (`MSG_CRYPTO_HELLO`).
3. **Đăng nhập (Authentication):**
   - Sau khi bắt tay mã hóa thành công, Client hỏi người dùng Username và Password.
   - Gói tin đăng nhập được mã hóa AES và gửi đi (`MSG_CONNECT_REQUEST`). Server trả về `MSG_CONNECT_ACCEPT` kèm Session Token.
4. **Vòng lặp tương tác (I/O Loop):**
   - Hệ thống tách làm hai luồng (Threads) hoạt động song song:
     - **Luồng nhận (Recv Thread)** trong `TcpClient`: Liên tục lắng nghe gói tin từ Server, cắt khung (Packet Framing), giải mã AES và hiển thị ra màn hình.
     - **Luồng gửi (Main/Input Thread)** trong `main.cpp`: Chờ người dùng gõ phím. Dữ liệu được đưa qua `CommandParser` để phân loại.
5. **Xử lý Lệnh (Command Handling):**
   - Nếu là tin nhắn thường, nó được mã hóa và gửi đi dưới dạng `MSG_CHAT_SEND`.
   - Nếu là lệnh (bắt đầu bằng `/`), `CommandHandler` sẽ dịch nó thành các loại gói tin đặc biệt (ví dụ `/join` -> `MSG_ROOM_JOIN`, `/kick` -> lệnh `Admin`).

---

## 2. Chi Tiết Các Thành Phần (Modules)

Mã nguồn Client được tổ chức thành các thư mục quản lý từng nhiệm vụ cụ thể:

### 2.1. Lõi Mạng & Kết Nối (`/client/core/`)
- **`TcpClient.cpp / .h`**: Trái tim của giao tiếp mạng phía Client.
  - Quản lý Socket TCP (`connect`, `send`, `recv`).
  - Chứa luồng đọc dữ liệu ngầm (`readLoop`). Luồng này liên tục kéo byte từ socket, bóc tách cấu trúc nhị phân của `Packet` (kiểm tra Magic Bytes, độ dài, CRC32).
  - Tự động gọi `ClientCrypto` để giải mã các gói tin nhận được và in trực tiếp ra màn hình console.
- **`ConnectionManager.cpp / .h`**: Tầng quản lý cấp cao hơn `TcpClient`. Chịu trách nhiệm theo dõi trạng thái kết nối, lưu trữ cấu hình mạng, và cung cấp cơ chế tự động kết nối lại (Auto-Reconnect) hoặc khôi phục phiên (Resume Session) bằng HMAC Token nếu mạng bị rớt.
- **`MessageQueue.cpp / .h`**: Cấu trúc hàng đợi Thread-Safe. Thường được sử dụng để đệm các gói tin nhị phân trước khi đẩy đi hoặc để trao đổi dữ liệu giữa luồng nhập bàn phím và luồng Network.

### 2.2. Xử Lý Lệnh Người Dùng (`/client/commands/`)
- **`CommandParser.cpp / .h`**: Đóng vai trò là cửa ngõ giao tiếp với người dùng.
  - Phân tích cú pháp chuỗi văn bản gõ vào từ bàn phím (`std::cin`).
  - Nhận diện các từ khóa (như `/rooms`, `/create`, `/join`, `/msg`, `/kick`, `/ban`).
- **`CommandHandler.cpp / .h`**: Thực thi các lệnh đã được phân tích.
  - Cấu trúc các yêu cầu này thành đối tượng `json`.
  - Yêu cầu `Protocol::Builder` đóng gói (Serialize) thành byte.
  - Sau cùng, đẩy qua `TcpClient` để mã hóa và gửi tới Server. Cung cấp cả logic gửi và nhận tập tin (File Transfer Flow).

### 2.3. Bảo Mật & Mã Hóa (`/client/security/`)
- **`ClientCrypto.cpp / .h`**: Đầu não bảo mật của Client.
  - Chịu trách nhiệm sinh ngẫu nhiên khóa `AES-256` bằng thư viện OpenSSL (`RAND_bytes`).
  - Dùng `EVP_PKEY` để mã hóa RSA cho bước bắt tay (Handshake).
  - Dùng thuật toán `AES-256-GCM` để mã hóa toàn bộ dữ liệu đi (Payload) và giải mã toàn bộ dữ liệu đến.
  - Quản lý `IV/Nonce` (Initialization Vector) để chống tấn công Replay Attack.
- **`CertVerifier.cpp / .h`**: (Tùy chọn cấu hình) Hệ thống ghim chứng chỉ (Certificate Pinning) hoặc xác minh chữ ký mã hóa của Server (Public Key Validation). Đảm bảo Client không kết nối nhầm vào một máy chủ giả mạo (Phòng chống tấn công Man-in-the-Middle).

### 2.4. Entry Point (`main.cpp`)
- **`main.cpp`**: Tệp thực thi gốc.
  - Đọc cấu hình Arguments (`--host`, `--port`).
  - Khởi tạo giao diện dòng lệnh (CLI). Hiển thị Banner ASCII chào mừng.
  - Hỏi người dùng thông tin (Nickname, Password).
  - Chặn luồng chính bằng một vòng lặp `while (running) { std::getline(...) }` vô tận để lấy input của người dùng và chuyển cho `CommandParser`. Mọi tác vụ mạng khác đều chạy ngầm.

---

## 3. Tổng kết

Nhờ thiết kế kiến trúc phân lớp, `Client` vô cùng nhẹ bén và dễ mở rộng. Toàn bộ logic giao diện (`commands`) hoàn toàn tách biệt khỏi logic truyền tải (`core`) và bảo mật (`security`). Điều này giúp cho việc sau này nếu cần nâng cấp Client CLI thành một Client có giao diện đồ họa (GUI) như Qt hay Electron, chúng ta chỉ cần đập bỏ `main.cpp` và `CommandParser`, phần `core` mạng và `security` mã hóa vẫn có thể được giữ nguyên 100%.
