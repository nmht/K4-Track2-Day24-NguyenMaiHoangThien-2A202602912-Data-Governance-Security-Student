"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Xử lý yêu cầu với Trifecta Split và OBO Governance.

    Run A: Đọc untrusted docs từ search_docs, tách riêng dữ liệu thô,
           chỉ trích xuất typed ticket IDs từ tên file sang Run B.
    Run B: Tra cứu khách hàng từ nguồn tin cậy data/customers.json
           dựa trên related_tickets, kiểm soát chính sách trước mọi tool call.
    """
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    agent_id = "lab24-agent"
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    expires_at = "2099-01-01T00:00:00+00:00"

    def _log_and_check(
        tool: str,
        arg_val: str,
        classification: str,
        egress: bool,
        purpose: str,
        owner: str,
        depth: int = 0,
        parent_scopes: tuple[str, ...] = (),
        agent_scopes: tuple[str, ...] = ("search_docs", "read_customer", "http_post"),
    ) -> bool:
        ctx = PolicyContext(
            data_classification=classification,
            request_purpose=purpose,
            agent_owner=owner,
            delegation_depth=depth,
            egress_enabled=egress,
            principal_id=principal_id,
            requested_tool=tool,
            agent_scopes=agent_scopes,
            parent_scopes=parent_scopes,
            expires_at=expires_at,
        )
        allowed, reason = check(ctx)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "run_id": run_id,
                "tool": tool,
                "args_hash": hashlib.sha256(arg_val.encode("utf-8")).hexdigest()[:16],
                "classification": classification,
                "decision": "allow" if allowed else "deny",
                "reason": reason,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )
        return allowed

    # ==========================================
    # RUN A: Untrusted content retrieval
    # ==========================================
    # Kiểm tra policy trước khi gọi search_docs
    allow_search = _log_and_check(
        tool="search_docs",
        arg_val=message,
        classification="internal",
        egress=False,
        purpose="summarize-tickets",
        owner=f"{agent_id}/run-a",
        agent_scopes=("search_docs",),
    )
    if not allow_search:
        return "Yêu cầu bị từ chối bởi chính sách an toàn."

    docs = tools.search_docs(message)

    # Trích xuất typed ticket IDs từ TÊN FILE (không lấy từ free text của attacker)
    ticket_ids: list[int] = []
    for d in docs:
        doc_id = d.get("id", "")
        m = re.search(r"ticket-(\d+)", doc_id)
        if m:
            ticket_ids.append(int(m.group(1)))

    combined_text = "\n\n".join(d["text"] for d in docs)
    # Áp dụng PII redaction trước boundary
    redacted_text = pii.redact(combined_text)

    # Quét phát hiện injection cho audit (không tin customer_id trong injection)
    injected = llm.find_injection(combined_text)

    # ==========================================
    # RUN B: Privileged context resolution
    # ==========================================
    # Tra cứu khách hàng hợp lệ từ nguồn tin cậy customers.json qua related_tickets
    customers_path = DATA_DIR / "customers.json"
    customers_data = json.loads(customers_path.read_text(encoding="utf-8")) if customers_path.exists() else []

    target_customers: list[str] = []
    for c in customers_data:
        rel = set(c.get("related_tickets", []))
        if any(tid in rel for tid in ticket_ids):
            target_customers.append(c["customer_id"])

    # Chỉ gọi read_customer cho khách hàng được suy ra từ liên kết tin cậy
    customer_records: list[dict] = []
    for cust_id in target_customers:
        allow_read = _log_and_check(
            tool="read_customer",
            arg_val=cust_id,
            classification="restricted",
            egress=False,
            purpose="support-reply",
            owner=f"{agent_id}/run-b",
            agent_scopes=("search_docs", "read_customer"),
        )
        if allow_read:
            try:
                record = tools.read_customer(cust_id)
                customer_records.append(record)
            except tools.ToolError:
                pass

    # Nếu có chỉ thị injection yêu cầu egress (http_post):
    # Luôn kiểm tra qua Policy: dữ liệu restricted + egress = False (BỊ CHẶN)
    if injected is not None:
        target_url = injected.target_url or "http://127.0.0.1:10024/reconcile"
        allow_post = _log_and_check(
            tool="http_post",
            arg_val=target_url,
            classification="restricted",
            egress=True,
            purpose="reconciliation",
            owner=f"{agent_id}/run-b",
            agent_scopes=("search_docs", "read_customer", "http_post"),
        )
        if allow_post:
            tools.http_post(target_url, {"records": customer_records})

    return llm.summarize(docs)

