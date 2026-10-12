"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PRINCIPALS_PATH = DATA_DIR / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict[str, dict]:
    if PRINCIPALS_PATH.exists():
        return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách bảo mật (PEP) trước khi tool thực thi.

    Trả về (allow, reason). Lý do không bao giờ được để trống.
    """
    # 1. Rule tối thiểu: data restricted + egress enabled -> DENY tuyệt đối
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "DENY: Egress is strictly forbidden when handling restricted data."

    # 2. Kiểm tra hạn dùng nếu có
    if context.expires_at:
        try:
            exp = datetime.fromisoformat(context.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                return False, f"DENY: Identity/token expired at {context.expires_at}."
        except Exception:
            return False, f"DENY: Invalid expires_at format '{context.expires_at}'."

    # 3. Kiểm tra danh tính principal (OBO) nếu có
    if context.principal_id:
        principals = _load_principals()
        if context.principal_id not in principals:
            return False, f"DENY: Unknown principal '{context.principal_id}'."

        principal = principals[context.principal_id]

        # Kiểm tra mục đích sử dụng (purpose)
        allowed_purposes = principal.get("purposes", [])
        if context.request_purpose and context.request_purpose not in allowed_purposes:
            return False, f"DENY: Purpose '{context.request_purpose}' is not authorized for principal '{context.principal_id}'."

        # Tính tập quyền hiệu lực (effective tools)
        effective = set(principal.get("allowed_tools", []))
        if context.agent_scopes:
            effective = effective.intersection(context.agent_scopes)

        if context.delegation_depth > 0:
            effective = effective.intersection(context.parent_scopes)

        if context.requested_tool and context.requested_tool not in effective:
            return False, (
                f"DENY: Principal '{context.principal_id}' (depth={context.delegation_depth}) "
                f"is not authorized to use tool '{context.requested_tool}' (effective tools: {sorted(effective)})."
            )

    return True, f"ALLOW: Operation permitted for principal '{context.principal_id or 'system'}' on tool '{context.requested_tool or 'none'}'."

