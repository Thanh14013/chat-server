# KẾ HOẠCH BÀI THUYẾT TRÌNH DỰ ÁN SECURECHAT
**Thời lượng dự kiến:** 10 phút  
**Số lượng Slide:** 15 trang  
**Mục tiêu:** Trình bày ngắn gọn, súc tích, đi thẳng vào các công nghệ lõi (Concurrency, Security) và kết quả đạt được của hệ thống Client-Server. Đảm bảo toàn bộ các tính năng bảo mật, kiến trúc hệ thống và biểu đồ từ báo cáo được thể hiện chính xác.

Dưới đây là kịch bản chi tiết cho 15 trang Slide. Các hình ảnh minh hoạ được chỉ định trích xuất trực tiếp từ thư mục `baocao/Hinhve/` để đưa thẳng vào slide:

---

### Slide 1: Trang bìa (Cover Slide)
- **Nội dung:** 
  - Tên dự án: **SecureChat - Hệ thống Truyền thông Thời gian thực Đa lớp Bảo mật**
  - Tên sinh viên thực hiện, Mã số sinh viên.
  - Tên Giảng viên hướng dẫn.
- **Hình ảnh:** Logo trường hoặc hình minh họa một mạng lưới chat an toàn (tự chọn).

### Slide 2: Đặt vấn đề, Mục tiêu và Giải pháp
- **Nội dung:**
  - **Vấn đề:** Nhu cầu liên lạc thời gian thực ẩn danh, an toàn; thách thức về hiệu năng khi xử lý kết nối lớn (Bài toán C10K) và rủi ro tấn công mạng (DoS, XSS, Fuzzing).
  - **Mục tiêu:** Xây dựng hệ thống Client-Server bằng C++ tối ưu hiệu suất I/O, kết hợp bảo mật mật mã lai và các cơ chế phòng thủ chủ động (Tường lửa mềm).
  - **Giải pháp:** Áp dụng kiến trúc Event-driven với I/O Multiplexing (epoll), Thread pool xử lý đồng thời, kết hợp mã hoá lai (RSA+AES) để đảm bảo tốc độ và an toàn.
- **Trình bày:** Nhấn mạnh 2 từ khóa cốt lõi: **Hiệu năng cao (C10K)** và **Bảo mật đa lớp**.

### Slide 3: Kiến trúc tổng thể hệ thống
- **Nội dung:**
  - Mô hình Client - Server điều khiển bằng sự kiện (Event-driven).
  - Các phân hệ lõi: Mạng (Network I/O), Xử lý luồng (Thread Pool), Lưu trữ (SQLite) và Bảo mật (Security).
- **Hình ảnh bắt buộc:** Chèn hình `slide_3.PNG` (Sơ đồ kiến trúc tổng thể mức Module) từ thư mục `baocao/Hinhve/`.

### Slide 4: Cơ sở dữ liệu và Lưu trữ (Database Schema)
- **Nội dung:**
  - Thiết kế cấu trúc cơ sở dữ liệu để tối ưu tốc độ đọc/ghi đồng thời trong đa luồng.
  - Ứng dụng SQLite tích hợp cơ chế WAL (Write-Ahead Logging).
  - Đảm bảo tính toàn vẹn dữ liệu cho tin nhắn, thông tin người dùng và nhật ký (Audit Log).
- **Hình ảnh bắt buộc:** Chèn hình `hinh_2.2.png` (Sơ đồ Thực thể Liên kết ERD của hệ thống CSDL).

### Slide 5: Xử lý I/O & Giải quyết bài toán C10K
- **Nội dung:**
  - Sử dụng cơ chế giám sát mạng **I/O Multiplexing (epoll)** trên Linux giúp quản lý hàng chục ngàn socket với tài nguyên CPU/RAM tối thiểu.
  - Kết hợp với **Thread Pool** (Hồ chứa luồng) để xử lý bất đồng bộ các tác vụ nặng (Mã hóa/Giải mã, DB) mà không làm nghẽn luồng mạng chính.
- **Hình ảnh bắt buộc:** Chèn hình `slide_5.PNG` (Sơ đồ cơ chế hoạt động của epoll và Thread Pool) từ thư mục `baocao/Hinhve/`.

### Slide 6: Cơ chế Bảo mật và Mã hóa Lai (Hybrid Crypto)
- **Nội dung:**
  - **Trao đổi khóa (Handshake):** Dùng thuật toán bất đối xứng RSA-2048 để đảm bảo an toàn khi truyền khóa phiên bí mật.
  - **Mã hóa đường truyền:** Dùng thuật toán đối xứng AES-256-GCM để mã hóa Payload siêu tốc và chống giả mạo nội dung (Authenticated Encryption).
- **Hình ảnh bắt buộc:** Chèn hình `slide_6.PNG` (Sơ đồ Cơ chế Trao đổi Khóa và Mã hóa Lai) từ thư mục `baocao/Hinhve/`.

### Slide 7: Cơ chế Xác thực và Quản lý Phiên (Session Management)
- **Nội dung:**
  - **Bảo vệ Mật khẩu (Key Stretching):** Ứng dụng hàm băm `PBKDF2-HMAC-SHA256` kết hợp Salt ngẫu nhiên nhằm vô hiệu hóa các hình thức tấn công vét cạn (Brute-force) và từ điển (Rainbow Table), kết hợp cơ chế tự động khóa tài khoản (Account Lockout) để rào chắn rủi ro.
  - **Phiên Phi trạng thái (Stateless Session):** Cấp phát Token định danh chứa chữ ký số để quản lý phiên làm việc thay vì lưu trên bộ nhớ Server, tối ưu tài nguyên hệ thống.
  - **Khôi phục Kết nối Siêu tốc (Zero-DB Reconnect):** Client tái thiết lập kết nối thông qua Token. Server xác thực tính hợp lệ hoàn toàn dựa trên phép toán chữ ký số (CPU-bound) mà không cần truy vấn Cơ sở dữ liệu, triệt tiêu hoàn toàn độ trễ I/O.
- **Hình ảnh bắt buộc:** Chèn hình `slide_7.PNG` (Lược đồ Trình tự Xác thực và Quản lý Phiên) từ thư mục `baocao/Hinhve/`.

### Slide 8: Cơ chế Nhắn tin và Định tuyến An toàn (Message Routing)
- **Nội dung:**
  - **Kiểm soát Luồng Dữ liệu:** Mọi thông điệp đều phải đi qua chốt chặn Rate Limiter và Message Filter (ngăn chặn XSS/Spam) trước khi được xử lý, đảm bảo an toàn tuyệt đối cho Server.
  - **Định tuyến Đa luồng An toàn:** Quá trình tra cứu và truy xuất Socket Đích (FD) được bảo vệ bằng cơ chế khóa đọc/ghi (Read/Write Locks), loại bỏ hoàn toàn tình trạng xung đột dữ liệu (Race condition).
  - **Tối ưu Hóa Broadcast Nhóm:** Phân phối tin nhắn đồng thời tới toàn bộ thành viên trong phòng với độ trễ thấp nhất thông qua hệ thống Session Map hiệu năng cao.
- **Hình ảnh bắt buộc:** Chèn hình `slide_8.PNG` (Sơ đồ Cơ chế Định tuyến Thông điệp An toàn) từ thư mục `baocao/Hinhve/`.

### Slide 9: Tính năng Cốt lõi: Trung chuyển Tệp Ẩn danh (Proxy Funneling)
- **Nội dung:**
  - **Che giấu Danh tính (Proxy Funneling):** Máy chủ đóng vai trò Proxy trung gian ẩn danh. Người gửi và người nhận không bao giờ biết IP thực của nhau, triệt tiêu rủi ro lộ lọt thông tin định tuyến.
  - **Trung chuyển Siêu tốc (Zero-Disk I/O):** Áp dụng kỹ thuật phân mảnh dữ liệu (Chunking). Các gói tin được luân chuyển trực tiếp qua RAM máy chủ thay vì lưu xuống ổ cứng đĩa, đạt tốc độ truyền tải tối đa và bảo vệ quyền riêng tư tuyệt đối.
  - **Máy trạng thái Hữu hạn (FSM):** Quản lý nghiêm ngặt vòng đời truyền tệp thông qua mô hình FSM khép kín (Pending -> Accepted -> In Progress -> Complete), tích hợp cơ chế tự động dọn dẹp (Cleanup) chống tấn công cạn kiệt bộ nhớ.
- **Hình ảnh bắt buộc:** Chèn hình `slide_9.PNG` (Sơ đồ Máy trạng thái FSM luồng Truyền Tệp) từ thư mục `baocao/Hinhve/`.

### Slide 10: Phân quyền Quản trị (Role-Based Access Control - RBAC)
- **Nội dung:**
  - **Mô hình RBAC Chặt chẽ:** Triển khai cơ chế phân cấp quyền hạn rõ ràng với 3 tầng (USER, ADMIN, OWNER). Trạng thái cấp bậc được mã hóa an toàn và ký điện tử trực tiếp vào Session Token, vô hiệu hóa nguy cơ leo thang đặc quyền từ phía Client.
  - **Đặc quyền Tối thiểu (Least Privilege):** Mỗi người dùng chỉ được cấp phát chính xác các quyền hạn cần thiết để thực thi tác vụ (Ví dụ: USER chỉ có thể Chat/Truyền tệp), giúp thu hẹp tối đa bề mặt tấn công (Attack Surface).
  - **Quản trị Tức thời (Real-time Execution):** Cung cấp bộ công cụ dành riêng cho cấp quản lý để duy trì an ninh phòng thủ như: Ban/Unban, Kick, Mute, Promote/Demote. Mọi tác động đều có hiệu lực ngay lập tức lên Socket TCP đang chạy.
- **Hình ảnh bắt buộc:** Chèn hình `slide_10.PNG` (Sơ đồ Cơ chế Kiểm soát Truy cập Dựa trên Vai trò - RBAC) từ thư mục `baocao/Hinhve/`.

### Slide 11: Phòng thủ chủ động & Tường lửa mềm
- **Nội dung:**
  - **Kiểm soát Lưu lượng (Rate Limiter):** Áp dụng thuật toán **Token-Bucket** linh hoạt để giới hạn tốc độ yêu cầu (kết nối, nhắn tin), triệt tiêu các nguy cơ tấn công từ chối dịch vụ (DoS) lớp 7 và hành vi Spam.
  - **Phát hiện Xâm nhập (IDS):** Đánh giá bất thường dựa trên Điểm đe dọa (Threat Score). Tự động ra quyết định Cấm IP (Temp/Perm Ban) trước các hành vi dò quét cổng (Port Scan), giả mạo Token, hoặc tấn công phát lại (Replay Attack).
- **Hình ảnh bắt buộc:** Chèn hình `slide_11.PNG` (Lược đồ Hệ thống Tường lửa mềm - RateLimiter & IDS) từ thư mục `baocao/Hinhve/`.

### Slide 12: Môi trường Triển khai
- **Nội dung:**
  - **Server:** Biên dịch để chạy trên môi trường Linux (sử dụng epoll tối ưu nhất).
  - **Client:** Hỗ trợ đa nền tảng (Linux, Windows) qua giao diện CLI (Command Line Interface).
  - **Build System:** Tự động hóa quá trình biên dịch qua CMake và GCC/Clang/Mingw-w64.

### Slide 13: Đánh giá Hiệu năng & Chịu tải (Benchmark)
- **Nội dung:**
  - **Kịch bản kiểm thử Tự động (Automated Testing):** Khởi chạy bộ công cụ C++ mô phỏng hàng trăm Client kết nối và gửi nhận tin nhắn đồng thời, tập trung đánh giá 3 chỉ số cốt lõi: Độ trễ (Latency), Thông lượng (Throughput), và Tính ổn định.
  - **Kết quả Tối ưu (C10K Benchmark):** Hệ thống chứng minh khả năng chịu tải tuyệt vời nhờ kiến trúc `epoll` và `Thread Pool`. Ở kịch bản Stress Test cao nhất, máy chủ xử lý mượt mà **512,035 tin nhắn**, đạt thông lượng **8,533 tin nhắn/giây**, độ trễ trung bình siêu thấp chỉ **0.017ms**, và 99.9% lượng tin nhắn (P99.9) có độ trễ không vượt quá **1.03ms** - hoàn toàn không có thắt nút cổ chai (Bottleneck).
- **Hình ảnh bắt buộc:** Copy/Chụp màn hình đoạn Log kết quả thực tế dưới đây (từ công cụ Test) và chèn thẳng vào Slide để minh chứng rõ ràng bằng số liệu thực:

  ```text
  ╔══════════════════════════════════════════════════════╗
  ║        VCS SecureChat — Load Test Results            ║
  ╠══════════════════════════════════════════════════════╣
  ║  Scenario : Stress Test (100 clients)                ║
  ║  Clients  : 100/100                                  ║
  ║  Duration : 60s                                      ║
  ╠══════════════════════════════════════════════════════╣
  ║  Messages sent    : 512035                           ║
  ║  Throughput avg   : 8533 msg/s                       ║
  ║  Latency avg      : 0.0171897 ms                     ║
  ║  Latency P99      : 0.11 ms                          ║
  ║  Latency P99.9    : 1.03 ms                          ║
  ╚══════════════════════════════════════════════════════╝
  ```

### Slide 14: Đánh giá Khả năng phòng thủ (Security Tests)
- **Nội dung:**
  - Trình bày kết quả phòng thủ khi bị tấn công Từ chối dịch vụ (Flood Test) và tấn công Tiêm nhiễm (XSS/SQL Injection).
  - Cách ly rủi ro thành công: Mã độc bị bộ lọc (MessageFilter) chặn lại và ngắt kết nối những IP thực hiện hành vi xấu.
- **Lưu ý hình ảnh:** *Tương tự Slide 13, hãy chụp ảnh màn hình log Console (Audit Logger) của Server khi Server đang chặn đứng một hành vi Spam hoặc kết nối sai Token.*

### Slide 15: Kết luận và Hướng phát triển
- **Nội dung:**
  - **Kết luận:** Hệ thống đạt được tính năng thời gian thực (C10K) và cơ sở hạ tầng an ninh mạng đáng tin cậy.
  - **Hướng phát triển:** Xây dựng giao diện UI (GUI) cho Client, tích hợp Call Video/Voice (WebRTC), nâng cấp kiến trúc lên Microservices.
  - Gửi lời Cảm ơn và bắt đầu phần Hỏi Đáp (Q&A).

---
**💡 Mẹo Thuyết trình:**
- Slide 3, 6, 8, 9, 11 là các slide "ăn tiền" nhất (vì có sơ đồ kỹ thuật chi tiết), hãy phân bổ nhiều thời gian hơn để giải thích cách luồng dữ liệu chạy qua các khối.
- Đảm bảo các ảnh sơ đồ khi đưa vào Slide có kích thước đủ lớn, phông chữ rõ ràng. Bạn có thể sử dụng các file `.puml` (nếu có sẵn công cụ render như PlantUML) để xuất lại ảnh với độ phân giải cao hơn nếu ảnh `.png` bị mờ.
