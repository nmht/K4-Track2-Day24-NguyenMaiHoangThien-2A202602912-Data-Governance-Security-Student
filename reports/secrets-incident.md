# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1.
- Commit chứa token giả: `1bdd849` (SHA đầy đủ: `1bdd849922156c868a5ee9293d68f5b72e242d2c`).
- File, rule và kết quả quét lịch sử: File `lab-fake-secret.txt` tại dòng 1, phát hiện bởi Rule ID `lab24-synthetic-token`. Quét lịch sử qua `gitleaks git --config .gitleaks.toml --redact --verbose .` báo 1 leak dạng synthetic token (exit code 1).
- Kết quả quét file hiện tại: Sạch hoàn toàn (`no leaks found`, exit code 0) khi quét thư mục làm việc qua `gitleaks dir --config .gitleaks.toml .`.
- Nếu đây là credential thật, cần xử lý thế nào: Phải ngay lập tức thu hồi (revoke) và xoay vòng (rotate) credential trực tiếp trên hệ thống cung cấp danh tính/dịch vụ (API provider / Auth server); đồng thời rà soát access logs để phát hiện hành vi truy cập trái phép trong thời gian secret bị lộ.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  1. Xóa file khỏi commit hiện tại (HEAD) không xóa dữ liệu khỏi lịch sử Git. Secret vẫn tồn tại vĩnh viễn trong các commit cũ (`1bdd849`) và bất kỳ ai có quyền truy cập repo đều có thể trích xuất ra (`git show 1bdd849:lab-fake-secret.txt`).
  2. Pin dependency bằng hash lock (`requirements.lock`) và cài đặt pre-commit hook chỉ bảo vệ chuỗi cung ứng trước các gói phần mềm độc hại và ngăn chặn commit secret mới trong tương lai, chứ không thể vô hiệu hóa quyền hạn của một credential đã bị lọt ra ngoài. Chỉ có hành động thu hồi/rotate ở phía nhà phát hành mới thực sự ngăn chặn được rủi ro bị khai thác.

