import ipaddress
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

# ==========================================
# CẤU HÌNH THAM SỐ
# ==========================================
CORRELATION_WINDOW_MINUTES = 15

ATTACK_STAGE_MAP = {
    "scan": "reconnaissance",
    "ping": "reconnaissance",
    "web_access": "reconnaissance",
    "web_attack": "exploitation",
    "login": "initial_access",
    "brute": "initial_access",
    "auth": "initial_access",
    "sql": "exploitation",
    "shell": "execution",
    "exec": "execution",
    "cmd": "execution",
    "dump": "exfiltration",
    "exfil": "exfiltration",
    "normal_traffic": "unknown",
    "dns_query": "exfiltration",
    "rce_attempt": "execution",
    "bola_attempt": "exploitation",
    "privilege_escalation": "privilege_escalation",
    "c2": "command_and_control",   # B4.3c: beacon/C2 (alert_adapter: T1071 → c2_beacon)
}

# ==========================================
# B5.1: TƯƠNG QUAN THEO THỰC THỂ (trước: chỉ theo IP nguồn)
# ==========================================
# Trước B5.1 Correlator chỉ gộp các alert CÙNG IP NGUỒN. Alert endpoint (Sysmon) không có IP → mọi alert endpoint
# trong 15 phút, dù ở máy khác nhau, dồn chung một thùng "unknown_ip"; còn chuỗi xuyên bề mặt
# (web từ IP ngoài → tiến trình trên máy web → máy web gọi C2 ra ngoài) bị cắt làm 3 incident — ở bộ vàng v2,
# 6/24 chuỗi có alert cuối chỉ "thấy" chính nó.
# Nay mỗi alert có hai thực thể, quy về tên tài sản khi có trong kiểm kê (IP 192.168.56.20 ≡ máy web-win-01):
#   actor  — ai đang hành động: IP nguồn; alert endpoint thì là chính máy (trường host)
#   target — ai bị tác động: IP đích; alert endpoint thì là chính máy
# Luật gộp (trong cửa sổ 15 phút, lấy incident gần nhất):
#   (1) cùng actor với một alert trước  → cùng incident (bao gồm luật cũ "cùng IP nguồn")
#   (2) actor hiện tại là TARGET của một alert trước ở giai đoạn khai thác/thực thi → cùng incident
#       ("máy vừa bị khai thác nay tự hành động": tiến trình lạ trên máy web, máy web gọi ra ngoài).
#   Không gộp chỉ vì cùng target — nếu không, mọi alert nhắm vào máy web (kể cả health check của LB) dồn một chỗ.
#   Không xác định được actor → incident riêng (không còn thùng "unknown_ip" chung).
PIVOT_STAGES = {"exploitation", "execution", "initial_access", "privilege_escalation"}


def _asset_maps():
    try:
        from agent.nodes.enricher import _asset_index   # đọc assets/inventory.yaml (tất định, có cache)
        return _asset_index()
    except Exception:
        return {}, {}


def _entity_key(ip: str = "", host: str = "", maps=None) -> Optional[str]:
    by_ip, by_name = maps or ({}, {})
    ip = (ip or "").strip()
    if ip and ip != "unknown_ip":
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            ip = ""
        if ip:
            a = by_ip.get(ip)
            return f"asset:{a['name'].lower()}" if a and a.get("name") else f"ip:{ip}"
    host = (host or "").strip().lower()
    if host:
        return f"asset:{host}" if host in by_name else f"host:{host}"
    return None


def entities(raw: dict, src_ip: str) -> tuple:
    """(actor, target) của một sự kiện. Alert endpoint: máy (host) vừa là actor vừa là target."""
    maps = _asset_maps()
    surface = str(raw.get("surface") or "").lower()
    host = str(raw.get("host") or "") if surface == "endpoint" else ""
    actor = _entity_key(src_ip, "", maps) or _entity_key("", host, maps)
    target = _entity_key(str(raw.get("destination_ip") or ""), "", maps) or _entity_key("", host, maps)
    return actor, target


def parse_time_safe(ts_str: str) -> datetime:
    """Parse thời gian an toàn, chống lỗi crash offset-naive vs offset-aware."""
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except:
        return datetime.now(timezone.utc)

def node_correlator(state: dict) -> Dict[str, Any]:
    print("\n[Trạm 1 - Correlator] Đang tìm kiếm sự tương quan không gian - thời gian...")
    
    current_log = state.get("raw_log", {})
    extracted_ioc = state.get("extracted_ioc", {})
    timeline = state.get("attack_timeline", [])
    notes = [] 
    
    # 1. Trích xuất Định danh
    # 1. Trích xuất Định danh Tăng cường (Robust Extraction)
    src_ip = (
        extracted_ioc.get("source_ip") 
        or current_log.get("source_ip") 
        or current_log.get("client_ip") 
        or "unknown_ip"
    )
    event_type = (
        current_log.get("event_type") 
        or current_log.get("event") 
        or "unknown_event"
    )
    timestamp_str = current_log.get("timestamp", datetime.now(timezone.utc).isoformat())
    current_time = parse_time_safe(timestamp_str)
    
    # 2. Phân loại Giai đoạn tấn công
    stage = "unknown"
    event_str = str(event_type).lower()
    for key, mapped_stage in ATTACK_STAGE_MAP.items():
        if key in event_str:
            stage = mapped_stage
            break

    # 3. Logic Tương Quan (Time Window Filtering)
    correlation_id = None
    event_count = 1
    chain_summary = [stage] if stage != "unknown" else []

    # B5.1: gộp theo thực thể (xem đầu file). Sự kiện cũ chưa có actor_key (trước B5.1) → dùng source_ip như cũ.
    actor, target = entities(current_log, src_ip)
    window = timedelta(minutes=CORRELATION_WINDOW_MINUTES)

    def _in_window(e):
        return abs(current_time - parse_time_safe(e.get("event_timestamp", ""))) <= window

    def _actor_of(e):
        return e.get("actor_key", f"ip:{e.get('source_ip')}" if e.get("source_ip") not in (None, "", "unknown_ip") else None)

    match_how, match_event = None, None
    if actor:
        same_actor = [e for e in timeline if _actor_of(e) == actor and _in_window(e)]
        pivot = [e for e in timeline if e.get("target_key") == actor
                 and e.get("attack_chain_stage") in PIVOT_STAGES and _in_window(e)]
        for how, pool in (("cùng tác nhân", same_actor), ("máy vừa bị khai thác nay tự hành động", pivot)):
            if pool:
                match_how = how
                match_event = max(pool, key=lambda e: parse_time_safe(e.get("event_timestamp", "")))
                break
        if not match_event and any(_actor_of(e) == actor for e in timeline):
            notes.append(f"Correlator: Tác nhân quen nhưng quá {CORRELATION_WINDOW_MINUTES} phút. Khởi tạo Incident mới.")

    if match_event:
        correlation_id = match_event.get("correlation_id")
        related_events = [e for e in timeline if e.get("correlation_id") == correlation_id]
        event_count = len(related_events) + 1
        raw_summary = [e.get("attack_chain_stage") for e in related_events if e.get("attack_chain_stage") != "unknown"]
        if stage != "unknown":
            raw_summary.append(stage)
        chain_summary = list(dict.fromkeys(raw_summary))
        print(f"[+] Tái sử dụng Incident [{correlation_id}] ({match_how}, trong {CORRELATION_WINDOW_MINUTES} phút).")
        notes.append(f"Correlator: Gắn log vào Incident [{correlation_id}] ({match_how}: {actor}).")
    if not correlation_id:
        correlation_id = str(uuid.uuid4())[:8]
        print(f"[*] Phát hiện Tác nhân mới. Khởi tạo Incident [{correlation_id}]")
        notes.append(f"Correlator: Phát hiện tác nhân mới. Khởi tạo Incident [{correlation_id}].")

    # 4. INCIDENT SEVERITY AGGREGATION (Góp ý số 3)
    # Tự động leo thang mức độ nghiêm trọng dựa trên lộ trình tấn công
    incident_severity = "low"
    if "exfiltration" in chain_summary or "execution" in chain_summary:
        incident_severity = "critical"
    elif "privilege_escalation" in chain_summary or "initial_access" in chain_summary:
        incident_severity = "high"
    elif "exploitation" in chain_summary or "command_and_control" in chain_summary:
        incident_severity = "high"
    elif "reconnaissance" in chain_summary and event_count >= 3:
        incident_severity = "medium"

    # [GIỮ NGUYÊN CODE Ở TRÊN...]
    # 5. Ghi nhận Audit Trail
    chain_visual = " -> ".join(chain_summary) if chain_summary else "Đang xác định..."
    notes.append(f"Correlator: Attack Chain ({event_count} events). Lộ trình: {chain_visual} | Severity Hỗ trợ: {incident_severity.upper()}")

    # 6. Đóng gói Event Mới
    # Ngày 2 (AegisSOC): lưu thêm tên/mức luật Splunk — lấy từ alert gốc (state["alert"], chỉ có khi
    # đi qua /ingest/alerts có token). Node làm giàu dùng để ghép câu lịch sử tất định.
    # Đường /analyze cũ không có alert → hai trường này là None.
    _alert = state.get("alert") or {}
    new_event = {
        "correlation_id": correlation_id,
        "event_timestamp": timestamp_str,
        "source_ip": src_ip,
        "event_type": event_type,
        "attack_chain_stage": stage,
        "rule_name": _alert.get("rule_name"),
        "rule_level": _alert.get("rule_level"),
        "actor_key": actor,      # B5.1
        "target_key": target,
    }
    # 7. Trả về State — chỉ trả [new_event], operator.add trong state.py tự tích lũy
    return {
        "correlation_id": correlation_id,
        "source_ip": src_ip,
        "event_timestamp": timestamp_str,
        "event_type": event_type,
        "attack_chain_stage": stage,
        "incident_severity": incident_severity,
        "attack_chain_visual": chain_visual,
        "attack_timeline": [new_event],
        "investigation_notes": notes
    }