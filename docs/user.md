# Hướng dẫn sử dụng VCS SecureChat Client

Chào mừng bạn đến với **VCS SecureChat**, hệ thống trò chuyện bảo mật sử dụng mã hóa AES-256-GCM và giao thức nhị phân siêu tốc. Tài liệu này cung cấp hướng dẫn toàn diện từ cách kết nối, đăng nhập đến toàn bộ các lệnh tương tác mà bạn có thể sử dụng (bao gồm quyền User và Admin).

---

## 1. Chuẩn bị & Kết nối vào Máy chủ (Server)

Vì bạn đang truy cập từ một máy tính khác (có thể là Windows, macOS hoặc Linux) vào hệ thống Server, bạn không cần toàn bộ mã nguồn hay các script khởi động. Bạn **chỉ cần duy nhất file thực thi Client** (`vcs_client` trên Linux/macOS hoặc `vcs_client.exe` trên Windows).

### Bước 1: Tải file Client
- Nhận file `vcs_client` (hoặc `vcs_client.exe`) đã được biên dịch sẵn từ Quản trị viên hệ thống (Admin), tải về và lưu vào một thư mục trên máy tính của bạn.

### Bước 2: Khởi chạy Client từ Terminal / Command Prompt
Bạn cần biết **Địa chỉ IP** và **Port** (Cổng) của máy chủ để kết nối.

**💻 Đối với Windows:**
1. Mở **Command Prompt** (cmd) hoặc **PowerShell**.
2. Dùng lệnh `cd` để di chuyển đến thư mục chứa file `vcs_client.exe`.
3. Chạy lệnh sau để kết nối:
```cmd
vcs_client.exe --host <SERVER_IP> --port <PORT>
```
*Ví dụ:* `vcs_client.exe --host 192.168.1.100 --port 9500`

**🐧 Đối với Linux / 🍏 macOS:**
1. Mở **Terminal**.
2. Dùng lệnh `cd` để di chuyển đến thư mục chứa file `vcs_client`.
3. Cấp quyền thực thi (nếu cần) và chạy lệnh:
```bash
chmod +x vcs_client
./vcs_client --host <SERVER_IP> --port <PORT>
```
*Ví dụ:* `./vcs_client --host 192.168.1.100 --port 9500`

### Quá trình Đăng nhập:
1. **Username**: Hệ thống sẽ yêu cầu bạn nhập tên đăng nhập (ví dụ: `Alice`).
2. **Password**: Bạn cần nhập mật khẩu của mình. 
   > [!IMPORTANT]
   > Nếu bạn nhập sai mật khẩu quá số lần quy định, địa chỉ IP của bạn sẽ bị hệ thống **IntrusionDetector** đưa vào danh sách đen (Ban IP) tự động để chống tấn công Bruteforce. Hãy nhập cẩn thận!
3. **Thành công**: Khi đăng nhập thành công, bạn sẽ nhận được thông báo `[SYSTEM] Đăng nhập thành công` và tự động được đưa vào phòng mặc định (thường là `#general`).

---

## 2. Giao tiếp Cơ bản (Text & Chat)

Mặc định, khi bạn gõ bất cứ văn bản nào không bắt đầu bằng dấu gạch chéo `/`, đó sẽ là **tin nhắn chat gửi vào phòng hiện tại** của bạn.

- **Gửi tin nhắn trong phòng**: Gõ `Xin chào mọi người!` và nhấn `Enter`.
- **Nhận tin nhắn**: Bạn sẽ thấy các dòng tin nhắn từ người khác với định dạng `[TênPhòng] TênNgườiDùng: Nội dung` hoặc chỉ `TênNgườiDùng: Nội dung` tùy theo giao diện.

---

## 3. Các Lệnh Dành Cho Người Dùng (User Commands)

Hệ thống hỗ trợ rất nhiều lệnh bằng cách bắt đầu với dấu `/`.

### Quản lý Phòng (Rooms)
- `/rooms`
  Liệt kê toàn bộ danh sách các phòng chat đang hoạt động trên hệ thống.
  
- `/create <room_name> [password]`
  Tạo một phòng chat mới, có thể thiết lập mật khẩu bảo vệ hoặc không. Ví dụ: `/create dev_team pass123`
  
- `/join <room_name> [password]`
  Tham gia vào một phòng chat. Nếu phòng có mật khẩu, bạn cần cung cấp. Ví dụ: `/join dev_team pass123`
  *(Lưu ý: Khi gia nhập phòng mới, bạn sẽ được tự động chuyển từ phòng cũ sang phòng mới. Một User chỉ ở trong 1 phòng tại một thời điểm)*
  
- `/leave`
  Rời khỏi phòng hiện tại và quay về phòng mặc định (`#general`).

- `/delete <room_name>`
  Xóa phòng chat. Lệnh này chỉ dành cho **Người tạo phòng (Creator)**, **Admin**, hoặc **Owner**. Khi phòng bị xóa, toàn bộ thành viên đang ở trong phòng đó sẽ bị chuyển về phòng `#general`.

### Khám phá Người dùng (Users)
- `/list`
  Hiển thị danh sách tất cả những người dùng đang trực tuyến **trong cùng phòng với bạn**.
  
- `/listall`
  Hiển thị danh sách toàn bộ các phòng (Hiện tại hoạt động tương tự lệnh `/rooms`).

- `/whois <username>`
  Xem thông tin chi tiết về một người dùng cụ thể (ví dụ: Quyền hạn, Thời gian online,...). Ví dụ: `/whois Bob`

### Nhắn tin Riêng Tư (Private Messaging)
- `/msg <username> <message>`
  Gửi tin nhắn bảo mật mã hóa trực tiếp đến một người dùng cụ thể mà không ai khác trong phòng có thể đọc được.
  Ví dụ: `/msg Charlie Chào bạn, dự án đến đâu rồi?`

### Truyền Tải File (File Transfer)
Hệ thống cho phép bạn gửi tập tin một cách bảo mật:
- `/send <username> <filepath>`
  Yêu cầu gửi tập tin đến một người dùng. Ví dụ: `/send Bob report.pdf`
- `/accept <transfer_id>`
  Đồng ý nhận tập tin đang được gửi tới thông qua ID giao dịch.
- `/reject <transfer_id>`
  Từ chối nhận tập tin.

### Lệnh Hệ Thống
- `/help`
  Hiển thị danh sách các lệnh bạn có thể sử dụng.
- `/quit`
  Ngắt kết nối an toàn, thoát khỏi hệ thống VCS SecureChat.

---

## 4. Các Lệnh Quản Trị Hệ Thống (Admin / Owner Commands)

Hệ thống có 3 cấp bậc quyền hạn: **USER**, **ADMIN**, và **OWNER**.
- **OWNER**: Là tài khoản ĐỘC TÔN duy nhất có tên đăng nhập là `thanh123` (Mật khẩu khởi tạo: `thanh123`). Tài khoản này luôn được Server tự động khởi tạo ngầm từ đầu. Owner có toàn quyền cao nhất, bao gồm quyền phong cấp / giáng cấp (Promote / Demote) các Admin khác.
- **ADMIN**: Được Owner chỉ định. Có quyền xử lý vi phạm, cấm chat, đuổi người dùng.

> [!WARNING]
> Mọi hành động của Admin/Owner đều được ghi log lưu vết trên Server. Vui lòng sử dụng các quyền xử phạt một cách thận trọng.

### Thông Tin & Giám sát
- `/rooms_admin`
  **(Chỉ dành cho Admin/Owner)** Xem toàn bộ danh sách phòng trên server, kèm theo thông tin Nickname của **người tạo phòng** và **tổng số User đang tham gia** phòng đó.

### Xử phạt & Kiểm soát
- `/mute <username> [seconds]`
  **(Chỉ dành cho Admin/Owner)** Cấm người dùng này gửi bất kỳ tin nhắn nào lên server trong thời gian nhất định. Nếu không nhập số giây, sẽ cấm vô thời hạn. Người dùng vẫn có thể đọc tin nhắn.
- `/unmute <username>`
  **(Chỉ dành cho Admin/Owner)** Hủy bỏ lệnh cấm chat, cho phép người dùng nhắn tin trở lại.
- `/kick <username> [reason]`
  **(Chỉ dành cho Admin/Owner)** Đuổi người dùng khỏi **phòng hiện tại** và cưỡng chế đưa họ về phòng `#general`. Người dùng này sẽ bị đưa vào danh sách đen của phòng đó và không thể `/join` lại.
- `/unkick <username> <room_name>`
  **(Chỉ dành cho Admin/Owner)** Gỡ lệnh cấm tham gia phòng cho một User đã bị kick trước đó.
- `/ban <username> [reason]`
  **(Chỉ dành cho Admin/Owner)** Cấm vĩnh viễn người dùng ở cấp độ **Toàn bộ Hệ thống**. Hệ thống sẽ khóa và lưu lại cả **Địa chỉ IP** lẫn **Nickname**, đảm bảo không thể dùng tài khoản đó hay IP đó kết nối lại. User sẽ lập tức bị ngắt kết nối.
- `/unban <username>`
  **(Chỉ dành cho Admin/Owner)** Gỡ bỏ lệnh cấm vĩnh viễn cho tài khoản và địa chỉ IP.

### Phân quyền & Quản lý
- `/promote <username>`
  **(Chỉ dành riêng cho OWNER)** Thăng cấp quyền quản trị (Admin) cho một người dùng.
- `/demote <username>`
  **(Chỉ dành riêng cho OWNER)** Hạ cấp một Admin trở về trạng thái User bình thường.

### Thông báo Khẩn cấp
- `/broadcast <message>`
  **(Chỉ dành cho Admin/Owner)** Gửi thông báo khẩn cấp màu đỏ / hệ thống đến **toàn bộ người dùng trên tất cả các phòng**. Thường dùng để thông báo bảo trì.
  Ví dụ: `/broadcast Server sẽ khởi động lại trong 5 phút nữa!`

---

## 5. Các Loại Tin Nhắn Bạn Có Thể Nhận Được

Trong quá trình sử dụng, trên màn hình Terminal của bạn sẽ xuất hiện nhiều luồng thông tin khác nhau. Hệ thống phân loại chúng như sau:

1. **Tin nhắn Chat thông thường:** `[Alice]: Xin chào`
2. **Tin nhắn riêng (Private):** `[Private từ Bob]: File cấu hình đây nhé`
3. **Thông báo Hệ thống (System Notify):**
   - *Tham gia/Rời đi:* `[SYSTEM]: Charlie đã tham gia #dev_team` hoặc `[SYSTEM]: Bob đã ngắt kết nối.`
   - *Phòng:* `[SYSTEM]: Bạn đã tham gia phòng #general`
4. **Thông báo Quản trị (Admin Broadcast):**
   - `[ADMIN BROADCAST]: Server sẽ bảo trì trong 5 phút.`
5. **Cảnh báo Lỗi (Error):**
   - `[ERROR]: Bạn gửi tin nhắn quá nhanh. Vui lòng chậm lại.` (Trigger Rate Limiter)
   - `[ERROR]: Lệnh không hợp lệ hoặc thiếu quyền hạn.`

> [!TIP]
> Hệ thống được trang bị bộ giới hạn tốc độ (Rate Limiter). Nếu bạn spam lệnh hoặc tin nhắn quá nhanh, hệ thống sẽ tạm thời từ chối lệnh của bạn và trả về cảnh báo `ERR_RATE_LIMITED`. Hãy chờ một vài giây rồi tiếp tục!
