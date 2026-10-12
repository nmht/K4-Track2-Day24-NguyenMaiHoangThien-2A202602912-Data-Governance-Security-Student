# Compliance mapping — điền trong checkpoint 5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 | PII Gate: nhận diện và che giấu dữ liệu định danh (CCCD, SĐT, STK, Email) trước khi chuyển qua ranh giới xử lý, tuân thủ nguyên tắc tối thiểu hóa dữ liệu. | `agent/pii.py:10-40`, `agent/runner.py:75-78` | Nhận diện bằng biểu thức chính quy (regex) trên tập dữ liệu tổng hợp (synthetic); chưa xác minh điều khoản cụ thể với văn bản gốc. |
| NĐ 356/2025/NĐ-CP | Phân loại dữ liệu (`restricted`, `internal`, `public`) và thực thi Policy Enforcement Point (PEP) chặn tuyệt đối việc truyền dữ liệu nhạy cảm ra ngoài (egress deny). | `agent/policy.py:53-56`, `agent/runner.py:120-136` | Mock môi trường cục bộ; chưa xác minh điều khoản cụ thể với văn bản gốc. |
| Luật AI 134/2025/QH15 | Kiểm soát an toàn hệ thống AI: Audit ledger chống chối bỏ dạng chuỗi băm (hash chain), lưu vết đầy đủ định danh tác nhân, quyền ủy quyền (OBO) và lý do cho mọi quyết định. | `agent/ledger.py:10-45`, `agent/runner.py:35-65` | Chuỗi băm lưu trên file cục bộ, chưa tích hợp máy chủ nhật ký bảo mật độc lập (WORM/PKI); chưa xác minh điều khoản cụ thể với văn bản gốc. |
| OWASP ASI01, ASI03, ASI04 | **ASI01 (Prompt Injection):** Trifecta Split tách Run A (untrusted docs) và Run B (chỉ nhận typed ticket ID từ tên file).<br>**ASI03 (Excessive Agency):** Phân quyền On-Behalf-Of (OBO), `support_l1` bị chặn `read_customer`.<br>**ASI04 (Insecure Egress & Supply Chain):** PEP chặn `http_post`, quét Gitleaks v8.30.1, pin pre-commit và dependency hash-lock. | `agent/runner.py:45-135`<br>`agent/policy.py:50-85`<br>`.pre-commit-config.yaml:1-6`<br>`requirements.lock:1-50` | Kiểm thử bằng fake LLM deterministic; `--as` là fixture mô phỏng vai trò, không thay thế hệ thống định danh sản xuất (IAM/OAuth2/OIDC). |

*Lưu ý: Bảng trên đối chiếu kiến trúc kỹ thuật với các chuẩn khung. Việc mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật đầy đủ trong môi trường sản xuất.*

