# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
- Dữ liệu nội bộ (`internal`): Nội dung các ticket hỗ trợ trong `corpus/*.md` (mô tả yêu cầu, tiến độ xử lý, mã ticket).
- Dữ liệu nhạy cảm / PII (`restricted`): Dữ liệu khách hàng trong `data/customers.json` bao gồm Họ tên, Số căn cước công dân (CCCD 12 chữ số), Số điện thoại (SĐT 10 chữ số), Số tài khoản ngân hàng (STK 8–16 chữ số) và địa chỉ Email.

2. Mục đích xử lý và principal:
- Mục đích: Tổng hợp ticket định kỳ (`summarize-tickets`), xử lý phản hồi hỗ trợ (`support-reply`), đối soát giao dịch (`billing-reconciliation`) và kiểm toán dữ liệu (`privacy-audit`).
- Principal tham gia:
  + `support_l1`: Nhân sự hỗ trợ L1, chỉ được cấp quyền tra cứu tài liệu nghiệp vụ (`search_docs`), không được phép truy cập hồ sơ PII khách hàng (`read_customer`).
  + `dpo` (Data Protection Officer): Cán bộ bảo vệ dữ liệu, được phép đọc hồ sơ khách hàng (`read_customer`) cho mục đích hỗ trợ/kiểm toán hợp lệ, nhưng bị nghiêm cấm gửi dữ liệu PII ra môi trường bên ngoài (`http_post`).

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- Run A (Untrusted context): Nhận truy vấn người dùng, gọi `tools.search_docs`, làm sạch PII qua `agent/pii.py:redact()`. Ranh giới giữa 2 run chỉ truyền duy nhất danh sách ID số nguyên trích xuất từ tên file ticket (`ticket_ids: list[int]`), cô lập hoàn toàn văn bản tự do của người dùng/kẻ tấn công.
- Run B (Privileged context): Tiếp nhận `ticket_ids`, đối chiếu bảng ánh xạ tin cậy `data/customers.json` qua trường `related_tickets`. Thực hiện gọi `tools.read_customer` nếu PEP chấp thuận.
- Endpoint ngoại vi (Egress): `http://127.0.0.1:10024/reconcile` (đích đến của sink mô phỏng hành vi rò rỉ dữ liệu ngoài ý muốn).

4. Bằng chứng deny/allow và giới hạn của mock:
- Bằng chứng Allow:
  + `dpo` thực thi `read_customer` thành công: dòng ledger ghi nhận `decision: "allow"`, `reason: "ALLOW: Operation permitted for principal 'dpo' on tool 'read_customer'."`.
- Bằng chứng Deny:
  + `support_l1` bị chặn đọc PII: ledger ghi nhận `tool: "read_customer"`, `decision: "deny"`.
  + Lệnh gửi dữ liệu ra sink `http_post` bị chặn đứng: ledger ghi nhận `tool: "http_post"`, `decision: "deny"`, `reason: "DENY: Egress is strictly forbidden when handling restricted data."`.
  + File `reports/attack-after.log` hoàn toàn rỗng (0 bytes).
- Giới hạn của môi trường Mock:
  + Sử dụng hoàn toàn dữ liệu giả lập (synthetic data), không chứa PII thật.
  + Đánh giá qua Fake LLM deterministic dựa trên marker, không có tính bất định như mô hình ngôn ngữ lớn thương mại.
  + Tham số `--as` là fixture mô phỏng vai trò, không thay thế cơ chế xác thực danh tính và quản lý phiên production (OAuth2/OIDC/mTLS).

