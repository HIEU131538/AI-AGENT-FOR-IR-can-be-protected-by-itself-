import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

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
}

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

    related_events = [e for e in timeline if e.get("source_ip") == src_ip]

    if related_events:
        # TÌM LOG MỚI NHẤT DỰA TRÊN THỜI GIAN THỰC TẾ (Chống lỗi Out-of-order log)
        last_event = max(
            related_events, 
            key=lambda e: parse_time_safe(e.get("event_timestamp", ""))
        )
        last_time = parse_time_safe(last_event.get("event_timestamp"))
        
        # SỬ DỤNG GIÁ TRỊ TUYỆT ĐỐI (Chống bug time_diff âm do log đến muộn)
        time_diff = abs(current_time - last_time)
        
        if time_diff <= timedelta(minutes=CORRELATION_WINDOW_MINUTES):
            correlation_id = last_event.get("correlation_id")
            event_count = len(related_events) + 1
            
            raw_summary = [e.get("attack_chain_stage") for e in related_events if e.get("attack_chain_stage") != "unknown"]
            if stage != "unknown":
                raw_summary.append(stage)
            
            chain_summary = list(dict.fromkeys(raw_summary))
            print(f"[+] Tái sử dụng Incident [{correlation_id}] (Cùng IP trong {CORRELATION_WINDOW_MINUTES} phút).")
            notes.append(f"Correlator: Gắn log vào Incident [{correlation_id}] (Khớp IP & Nằm trong Time Window).")
        else:
            print(f"[*] IP quen thuộc nhưng đã Timeout. Khởi tạo Chain mới.")
            notes.append(f"Correlator: IP Timeout (> {CORRELATION_WINDOW_MINUTES}m). Khởi tạo Incident mới.")
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
    elif "exploitation" in chain_summary:
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