# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa. Trong `agent/loop.py`, hàm `_naive_loop(message, llm)` không khởi tạo hay quản lý bất kỳ định danh phiên chạy nào (`run_id`, `agent_id`, `principal_id`, hay `on_behalf_of`). Mỗi lần thực thi hoàn toàn vô danh (anonymous) và không mang ngữ cảnh bảo mật.

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có cơ chế hoặc thành phần thẩm quyền (Policy Engine / PEP) nào cho phép. Trong `agent/loop.py`, hàm `_naive_loop()`, khi phát hiện chỉ thị tiêm nhập từ `llm.find_injection(combined_text)`, code đã trực tiếp gọi `tools.http_post(injected.target_url, {"records": collected})` mà không qua bất kỳ lớp kiểm tra chính sách (policy check) hay ủy quyền nào.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Bản thân agent không có cơ chế kiểm toán nội bộ hay audit ledger. Bằng chứng duy nhất nằm ở bên ngoài hệ thống agent: file `reports/sink.log` do server sink tại `sink/sink.py` ghi lại (hàm `SinkHandler.do_POST`) khi nhận payload chứa dữ liệu PII được POST đến `http://127.0.0.1:10024/reconcile`.
