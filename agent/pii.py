"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
import re


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII tiếng Việt: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL."""
    entities: list[dict] = []

    # 1. EMAIL
    for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. VN_BANK_ACCOUNT (thường đi sau STK hoặc số tài khoản)
    for m in re.finditer(r"(?<=\bSTK\s)\d{8,16}\b", text):
        entities.append({"type": "VN_BANK_ACCOUNT", "start": m.start(), "end": m.end()})

    bank_spans = {(e["start"], e["end"]) for e in entities}

    # 3. VN_CCCD (12 chữ số liên tiếp, không trùng với STK đã nhận diện)
    for m in re.finditer(r"\b\d{12}\b", text):
        if (m.start(), m.end()) not in bank_spans:
            entities.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})

    # 4. VN_PHONE (10 chữ số bắt đầu bằng 0, không trùng với STK)
    for m in re.finditer(r"\b0\d{9}\b", text):
        if (m.start(), m.end()) not in bank_spans:
            entities.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})

    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế mọi thực thể PII bằng [REDACTED_<TYPE>] theo thứ tự từ cuối về đầu."""
    entities = detect(text)
    # Sắp xếp giảm dần theo start để thay thế từ cuối về đầu, không làm lệch offset
    for entity in sorted(entities, key=lambda x: x["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        text = text[: entity["start"]] + replacement + text[entity["end"] :]
    return text

