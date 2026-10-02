"""
api/alert_adapter.py — B1 (AegisSOC)

Hai việc:
  1. `Alert`: khuôn hợp đồng alert giữa Splunk bridge và Agent (xem AegisSOC_02_splunk.md mục 4).
     Alert sai khuôn bị từ chối ngay ở cửa /ingest/alerts, không lọt vào graph.
  2. `to_legacy_raw_log()`: GIÀN GIÁO TẠM — đổi tên trường của alert cho vừa ô `raw_log`
     mà các node cũ (Extractor, Correlator, Analyzer, Reflection) đang đọc.

Bản alert gốc, nguyên vẹn, được đưa vào graph song song qua `state["alert"]`.
Node làm giàu (Ngày 2) và bộ dựng ticket (B5, core/ticket.py) đọc `state["alert"]`, KHÔNG đọc raw_log.
B5: Analyzer/Reflection đã chuyển sang đọc ticket. `to_legacy_raw_log` còn giữ cho Extractor + Correlator
(2 trạm tất định cũ, dò regex và xếp giai đoạn trên raw_log) — không có gì từ đây đi thẳng vào LLM nữa.
"""
import ipaddress
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.fields import canonical_fields   # B5.1: tên trường tương đương (IIS/Sigma/Splunk → tên chuẩn)

# ==========================================
# 1. KHUÔN HỢP ĐỒNG ALERT
# ==========================================
Level = Literal["low", "medium", "high", "critical"]
Surface = Literal["web", "endpoint", "network"]


class Alert(BaseModel):
    """Một alert do Splunk sinh ra, đã qua splunk_bridge.py (hoặc phát lại từ file JSON)."""

    # Thừa trường ngoài hợp đồng → báo lỗi, để hai bên phát hiện lệch hợp đồng sớm.
    # Các trường gốc của sự kiện (User-Agent, URI, CommandLine...) phải nằm trong `fields`.
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(..., min_length=1, max_length=200)
    rule_name: str = Field(..., min_length=1, max_length=300)
    rule_level: Level
    attack_ids: List[str] = Field(default_factory=list)
    surface: Surface
    timestamp: str                       # ISO 8601 UTC, ví dụ 2026-09-28T03:05:00Z
    src_ip: str = ""                     # alert endpoint (Sysmon) có thể không có IP → để rỗng
    dest_ip: str = ""
    dest_port: Optional[int] = Field(default=None, ge=0, le=65535)
    host: str = ""
    fields: Dict[str, Any] = Field(default_factory=dict)   # giá trị gốc — KHÔNG cắt, KHÔNG làm sạch
    summary: str = ""

    @field_validator("rule_level", "surface", mode="before")
    @classmethod
    def _lowercase(cls, v):
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("attack_ids", mode="before")
    @classmethod
    def _split_attack_ids(cls, v):
        # Chấp nhận cả mảng lẫn chuỗi "T1190,T1059"
        if v is None:
            return []
        if isinstance(v, str):
            v = v.split(",")
        return [str(x).strip().upper() for x in v if str(x).strip()]

    @field_validator("timestamp")
    @classmethod
    def _check_timestamp(cls, v: str):
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("timestamp phải là ISO 8601, ví dụ 2026-09-28T03:05:00Z")
        return v

    @field_validator("src_ip", "dest_ip")
    @classmethod
    def _check_ip(cls, v: str):
        v = (v or "").strip()
        if v:
            ipaddress.ip_address(v)  # sai định dạng → ValueError → 422
        return v


# ==========================================
# 2. SINH event_type TỪ MÃ ATT&CK (cho Correlator / Extractor cũ)
# ==========================================
# Correlator cũ xếp giai đoạn kill-chain bằng cách dò chuỗi con trong event_type
# (ATTACK_STAGE_MAP trong agent/nodes/correlator.py). Bảng dưới chọn tên event_type
# sao cho khớp đúng giai đoạn. Tra theo tiền tố: "T1059.001" khớp "T1059".
_ATTACK_TO_EVENT_TYPE = [
    ("T1595", "port_scan"),        # Correlator: "scan" → reconnaissance; Extractor: port_scan → network_scan
    ("T1046", "port_scan"),
    ("T1190", "web_attack"),       # "web_attack" → exploitation
    ("T1505", "webshell_exec"),    # "shell" → execution
    ("T1059", "command_exec"),     # "exec" → execution
    ("T1071", "c2_beacon"),        # B4.3c: C2 ≠ tuồn dữ liệu — "c2" → command_and_control (trước: exfiltration → CRITICAL)
    ("T1041", "c2_exfil"),         # "exfil" → exfiltration
    ("T1048", "c2_exfil"),
    # Chưa có giai đoạn tương ứng trong bảng cũ → Correlator ra "unknown".
    # Để phần làm giàu (Ngày 2) xử lý, không sửa Correlator ở B1.
    ("T1053", "persistence"),
    ("T1547", "persistence"),
    ("T1033", "discovery"),
    ("T1082", "discovery"),
]


def derive_event_type(alert: Alert) -> str:
    for attack_id in alert.attack_ids:
        for prefix, event_type in _ATTACK_TO_EVENT_TYPE:
            if attack_id == prefix or attack_id.startswith(prefix + "."):
                return event_type
    return f"{alert.surface}_alert"


def build_summary(alert: Alert) -> str:
    """Tóm tắt ghép theo mẫu cố định (giống bridge), KHÔNG dùng LLM."""
    if alert.summary:
        return alert.summary
    port = alert.dest_port if alert.dest_port is not None else "-"
    return (f"{alert.rule_name} | {alert.src_ip or '-'} -> "
            f"{alert.dest_ip or '-'}:{port} | host={alert.host or '-'}")


# ==========================================
# 3. GIÀN GIÁO: ALERT → raw_log CHO LÕI CŨ
# ==========================================
_CONTRACT_KEYS_IN_RAW = {
    "timestamp", "source_ip", "destination_ip", "dest_port", "event_type", "message",
    "alert_id", "rule_name", "rule_level", "attack_ids", "surface", "host",
}


def to_legacy_raw_log(alert: Alert) -> Dict[str, Any]:
    """
    Đổi tên trường cho vừa ô raw_log của lõi cũ. Chỉ đổi tên, không diễn giải.

    Các trường gốc trong `fields` được trải phẳng ra ngoài vì Extractor đọc thẳng
    raw_log["body"], raw_log["query"]... Nếu tên trường gốc trùng với trường hợp đồng
    thì giá trị gốc được giữ lại dưới tên "orig_<tên>" — không làm mất dữ liệu.
    """
    raw: Dict[str, Any] = {}
    for key, value in alert.fields.items():
        raw[f"orig_{key}" if key in _CONTRACT_KEYS_IN_RAW else key] = value
    # B5.1: thêm khoá chuẩn còn thiếu (vd. cs-uri-stem + cs-uri-query → request_uri, cs(User-Agent) →
    # http_user_agent) để Extractor/Retriever đọc được mọi kiểu đặt tên. Không ghi đè khoá gốc; ticket
    # (thứ LLM đọc) vẫn dùng alert.fields nguyên văn nên KHÔNG thấy các khoá thêm này.
    for key, value in canonical_fields(alert.fields).items():
        if key not in raw and key not in _CONTRACT_KEYS_IN_RAW:
            raw[key] = value

    raw.update({
        "timestamp": alert.timestamp,
        "source_ip": alert.src_ip,
        "destination_ip": alert.dest_ip,
        "event_type": derive_event_type(alert),
        "message": build_summary(alert),
        "alert_id": alert.alert_id,
        "rule_name": alert.rule_name,
        "rule_level": alert.rule_level,
        "attack_ids": list(alert.attack_ids),
        "surface": alert.surface,
        "host": alert.host,
    })
    if alert.dest_port is not None:
        raw["dest_port"] = alert.dest_port
    return raw
