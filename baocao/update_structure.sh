#!/bin/bash
set -e

# --- CHUONG 2 ---
cd /home/chat-server/baocao/Chuong/2_Nen_tang_ly_thuyet

# Đổi 2.3.tex thành 2.6.tex
mv 2.3.tex 2.6.tex
sed -i 's/2.3/2.6/g' 2.6.tex || true

# Tạo 2.3
mkdir -p 2.3
echo "\section{Công nghệ xử lý đồng thời và hiệu năng cao}
\input{Chuong/2_Nen_tang_ly_thuyet/2.3/2.3.1}
\input{Chuong/2_Nen_tang_ly_thuyet/2.3/2.3.2}" > 2.3/2.3.tex
echo "\subsection{I/O Multiplexing và mô hình epoll}" > 2.3/2.3.1.tex
echo "\subsection{Mô hình Thread Pool}" > 2.3/2.3.2.tex

# Tạo 2.4
mkdir -p 2.4
echo "\section{Lý thuyết phòng thủ và an ninh mạng}
\input{Chuong/2_Nen_tang_ly_thuyet/2.4/2.4.1}
\input{Chuong/2_Nen_tang_ly_thuyet/2.4/2.4.2}" > 2.4/2.4.tex
echo "\subsection{Hệ thống phát hiện xâm nhập (IDS)}" > 2.4/2.4.1.tex
echo "\subsection{Thuật toán Rate Limiting (Token-Bucket)}" > 2.4/2.4.2.tex

# Tạo 2.5
mkdir -p 2.5
echo "\section{Hệ thống lưu trữ và cơ sở dữ liệu}
\input{Chuong/2_Nen_tang_ly_thuyet/2.5/2.5.1}
\input{Chuong/2_Nen_tang_ly_thuyet/2.5/2.5.2}" > 2.5/2.5.tex
echo "\subsection{Cơ sở dữ liệu SQLite}" > 2.5/2.5.1.tex
echo "\subsection{Cơ chế Write-Ahead Logging (WAL)}" > 2.5/2.5.2.tex

# Cập nhật chuong2.tex
echo "\chapter{NỀN TẢNG LÝ THUYẾT VÀ CÔNG NGHỆ SỬ DỤNG}

\input{Chuong/2_Nen_tang_ly_thuyet/2.1/2.1}
\input{Chuong/2_Nen_tang_ly_thuyet/2.2/2.2}
\input{Chuong/2_Nen_tang_ly_thuyet/2.3/2.3}
\input{Chuong/2_Nen_tang_ly_thuyet/2.4/2.4}
\input{Chuong/2_Nen_tang_ly_thuyet/2.5/2.5}
\input{Chuong/2_Nen_tang_ly_thuyet/2.6}" > chuong2.tex

# --- CHUONG 3 ---
cd /home/chat-server/baocao/Chuong/3_Phan_tich_thiet_ke

# Đổi 3.4 thành 3.7
mv 3.4 3.7
mv 3.7/3.4.tex 3.7/3.7.tex
mv 3.7/3.4.1.tex 3.7/3.7.1.tex
mv 3.7/3.4.2.tex 3.7/3.7.2.tex
sed -i 's/3.4.1/3.7.1/g' 3.7/3.7.tex || true
sed -i 's/3.4.2/3.7.2/g' 3.7/3.7.tex || true

# Tạo 3.4
mkdir -p 3.4
echo "\section{Thiết kế hệ sinh thái an ninh mạng chủ động}
\input{Chuong/3_Phan_tich_thiet_ke/3.4/3.4.1}
\input{Chuong/3_Phan_tich_thiet_ke/3.4/3.4.2}
\input{Chuong/3_Phan_tich_thiet_ke/3.4/3.4.3}" > 3.4/3.4.tex
echo "\subsection{Hệ thống phát hiện xâm nhập (IDS)}" > 3.4/3.4.1.tex
echo "\subsection{Bộ định tuyến giới hạn tốc độ (Rate Limiter)}" > 3.4/3.4.2.tex
echo "\subsection{Nhật ký kiểm toán (Audit Logger)}" > 3.4/3.4.3.tex

# Tạo 3.5
mkdir -p 3.5
echo "\section{Thiết kế cơ sở dữ liệu}
\input{Chuong/3_Phan_tich_thiet_ke/3.5/3.5.1}
\input{Chuong/3_Phan_tich_thiet_ke/3.5/3.5.2}" > 3.5/3.5.tex
echo "\subsection{Sơ đồ thực thể liên kết (ERD)}" > 3.5/3.5.1.tex
echo "\subsection{Quản lý người dùng và trạng thái}" > 3.5/3.5.2.tex

# Tạo 3.6
mkdir -p 3.6
echo "\section{Thiết kế logic tính năng nghiệp vụ}
\input{Chuong/3_Phan_tich_thiet_ke/3.6/3.6.1}
\input{Chuong/3_Phan_tich_thiet_ke/3.6/3.6.2}
\input{Chuong/3_Phan_tich_thiet_ke/3.6/3.6.3}" > 3.6/3.6.tex
echo "\subsection{Quản lý phòng Chat nhóm (Rooms)}" > 3.6/3.6.1.tex
echo "\subsection{Cơ chế truyền tải tập tin (File Transfer)}" > 3.6/3.6.2.tex
echo "\subsection{Các tập lệnh quản trị hệ thống (Admin Commands)}" > 3.6/3.6.3.tex

# Cập nhật chuong3.tex
echo "\chapter{PHÂN TÍCH THIẾT KẾ, TRIỂN KHAI VÀ ĐÁNH GIÁ HỆ THỐNG}

\input{Chuong/3_Phan_tich_thiet_ke/3.1/3.1}
\input{Chuong/3_Phan_tich_thiet_ke/3.2/3.2}
\input{Chuong/3_Phan_tich_thiet_ke/3.3/3.3}
\input{Chuong/3_Phan_tich_thiet_ke/3.4/3.4}
\input{Chuong/3_Phan_tich_thiet_ke/3.5/3.5}
\input{Chuong/3_Phan_tich_thiet_ke/3.6/3.6}
\input{Chuong/3_Phan_tich_thiet_ke/3.7/3.7}" > chuong3.tex

# Compile thử
cd /home/chat-server/baocao
xelatex -interaction=nonstopmode baocao.tex
