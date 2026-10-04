# Hệ thống quản lý nhiều lớp Giáo lý

Vai trò: **sysadmin** (tạo lớp, tài khoản, đặt quy tắc tính điểm, xem và sửa mọi lớp), **giáo lý viên** (quản lý lớp của mình, mỗi lớp một người), **phụ lớp** (nhập điểm, điểm danh trong lớp của mình).

## Biến môi trường (Render > Environment)
| Biến | Ý nghĩa |
|---|---|
| SESSION_SECRET | Chuỗi ngẫu nhiên dài (bắt buộc) |
| TURSO_URL, TURSO_TOKEN | Cơ sở dữ liệu Turso |
| SYSADMIN_PASS | Mật khẩu sysadmin, tối thiểu 8 ký tự (bắt buộc ở lần chạy đầu) |
| SYSADMIN_USER | Tên đăng nhập sysadmin (mặc định `sysadmin`) |
| ADMIN_PASS, HELPER_PASS | Chỉ dùng MỘT LẦN khi nâng cấp từ bản cũ: tạo lại tài khoản `giaolyvien`, `phulop` (từ 8 ký tự trở lên). Sau đó có thể xóa |
| CLASS_NAME | Tên lớp cho dữ liệu cũ khi nâng cấp (mặc định `Sơ cấp 1 B`) |

Lần chạy đầu, hệ thống tự tạo bảng, tạo sysadmin và chuyển dữ liệu lớp cũ thành "lớp đầu tiên". Sau đó mật khẩu được lưu mã hóa trong cơ sở dữ liệu và quản lý ngay trên web (thẻ Quản trị).

## Chạy thử trên máy
```
npm install
SESSION_SECRET=chuoi-dai SYSADMIN_PASS=matkhau123 node server.js
```
(PowerShell: dùng `$env:SESSION_SECRET="..."` trước.) Không khai báo TURSO_URL thì dữ liệu lưu vào file `data.db` trên máy.
