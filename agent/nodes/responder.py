import json
import os
import subprocess
import logging
import requests
import ipaddress  
from agent.state import SOCAgentState
from core.profile import layer_enabled   # Ngày 4: Lớp 1 (Rule of Two) + Lớp 4 (sanitizer)
from tools.sanitizer import OutputSanitizer   # Lớp 4: khiên trên đường thực thi
from core import attack_kb                    # B10: khuyến nghị giảm thiểu theo mitigation ATT&CK

# Lấy cấu hình từ biến môi trường
ALLOW_LIVE_MODE = os.getenv("ALLOW_LIVE_MODE", "true").lower() == "true"

from dotenv import load_dotenv
load_dotenv()

_DASHBOARD_CONFIG = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "dashboard", "config.json"
)

def get_soar_mode() -> str:
    """Đọc file config 1 lần duy nhất để lấy công tắc LIVE/SIMULATION"""
    try:
        with open(_DASHBOARD_CONFIG, "r") as f:
            config = json.load(f)
            requested_mode = config.get("SOAR_MODE", "SIMULATION").upper()

            if requested_mode == "LIVE" and not ALLOW_LIVE_MODE:
                print("⚠️ [WARNING] Giao diện yêu cầu LIVE, nhưng ALLOW_LIVE_MODE đang tắt! Ép về SIMULATION.")
                return "SIMULATION"

            return requested_mode
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return "SIMULATION"

def is_valid_ip(ip: str) -> bool:
    """Hàm bảo mật: Xác thực định dạng IP để chống Command Injection"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# IP nội bộ / loopback — không bao giờ block bằng iptables
_PROTECTED_IPS = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}

# ==========================================
# CÁC HÀM THỰC CHIẾN SOAR (ACTION PLAYBOOKS)
# ==========================================

_IPT = ["sudo", "/usr/sbin/iptables"]

def execute_block_ip(ip_address: str, mode: str) -> str:
    if ip_address in _PROTECTED_IPS:
        return f"[PROTECTED] {ip_address} là địa chỉ nội bộ — bỏ qua block để bảo vệ hệ thống."
    if mode == "SIMULATION":
        return f"[SIMULATION] Đã giả lập chặn IP {ip_address}."
    try:
        # Dùng -I 1 (insert đầu chain) thay vì -A (append cuối)
        # → DROP có priority cao nhất, đè lên mọi throttle rule đã có trước
        add_cmd = _IPT + ["-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"]
        subprocess.run(add_cmd, capture_output=True, text=True, check=True)
        return f"[+] THỰC CHIẾN (LIVE): Đã chặn IP {ip_address} (DROP inserted tại vị trí #1 INPUT)."
    except Exception as e:
        return f"[-] LỖI BLOCK IP: {str(e)}"

def execute_network_block_full(ip_address: str, mode: str) -> str:
    """Cô lập hoàn toàn một IP ở cấp độ mạng — chặn cả INPUT, OUTPUT, FORWARD.
    Dùng -I 1 để DROP rule nằm đầu chain, đè lên throttle rule đã có."""
    if ip_address in _PROTECTED_IPS:
        return f"[PROTECTED] {ip_address} là địa chỉ nội bộ — bỏ qua Network Block Full để bảo vệ hệ thống."
    if mode == "SIMULATION":
        return f"[SIMULATION] Đã giả lập Network Block Full (INPUT+OUTPUT+FORWARD) cho IP {ip_address}."
    results = []
    for chain, flag in [("INPUT", "-s"), ("OUTPUT", "-d"), ("FORWARD", "-s")]:
        try:
            add = _IPT + ["-I", chain, "1", flag, ip_address, "-j", "DROP"]
            subprocess.run(add, capture_output=True, check=True)
            results.append(f"{chain}: DROP inserted #1.")
        except Exception as e:
            results.append(f"{chain}: LỖI — {e}")
    return f"[+] NETWORK_BLOCK_FULL (LIVE) IP {ip_address}: {' | '.join(results)}"

def execute_throttle_ip(ip_address: str, mode: str, rate_limit: str = "5/m") -> str:
    if ip_address in _PROTECTED_IPS:
        return f"[PROTECTED] {ip_address} là địa chỉ nội bộ — bỏ qua throttle để bảo vệ hệ thống."
    if mode == "SIMULATION":
        return f"[SIMULATION] Mô phỏng: Đã giả lập bóp băng thông IP {ip_address} xuống {rate_limit}."
    try:
        check_limit = _IPT + ["-C", "INPUT", "-s", ip_address, "-m", "limit", "--limit", rate_limit, "-j", "ACCEPT"]
        try:
            subprocess.run(check_limit, capture_output=True, check=True)
            return f"[*] THROTTLE (LIVE): IP {ip_address} đã bị bóp băng thông từ trước."
        except subprocess.CalledProcessError:
            subprocess.run(_IPT + ["-A", "INPUT", "-s", ip_address, "-m", "limit", "--limit", rate_limit, "-j", "ACCEPT"], check=True)
            subprocess.run(_IPT + ["-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            return f"[~] THROTTLE (LIVE): Đã bóp băng thông IP {ip_address} xuống mức {rate_limit}."
    except Exception as e:
        return f"[-] LỖI THROTTLE IP {ip_address}: {str(e)}"

def execute_monitor_ip(ip_address: str, mode: str) -> str:
    try:
        os.makedirs("watchlist", exist_ok=True)
        filepath = "watchlist/suspect_ips.txt"
        existing_ips = set()
        
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                existing_ips = set(line.strip() for line in f)
                
        if ip_address not in existing_ips:
            with open(filepath, "a") as f:
                f.write(f"{ip_address}\n")
            return f"[*] MONITOR: Đã thêm mới IP {ip_address} vào Watchlist."
        else:
            return f"[*] MONITOR: IP {ip_address} đã tồn tại trong Watchlist, bỏ qua."
    except Exception as e:
        return f"[-] LỖI MONITOR IP: {str(e)}"

def execute_alert_telegram(message: str, mode: str) -> str:
    if mode == "SIMULATION":
        return f"[SIMULATION] Mô phỏng Gửi Alert: {message}"
    
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    
    if not bot_token or not chat_id:
        return f"[-] LỖI TELEGRAM: Thiếu TELEGRAM_BOT_TOKEN hoặc TELEGRAM_CHAT_ID trong file .env"
        
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        from core.egress import guard as _egress_guard   # Lớp 4: danh sách trắng egress
        _egress_guard(url)
        resp = requests.post(url, json={"chat_id": chat_id, "text": message}, timeout=5)
        if resp.status_code == 200:
            return f"[!] ALERT (LIVE): Đã bắn thông báo Telegram thành công!"
        else:
            return f"[-] LỖI TELEGRAM API: {resp.text}"
    except Exception as e:
        return f"[-] LỖI KẾT NỐI TELEGRAM: {str(e)}"

# ==========================================
# TRẠM RESPONDER (NÃO BỘ ĐIỀU PHỐI)
# ==========================================
def node_responder(state: SOCAgentState):
    current_mode = get_soar_mode()
    print(f"\n[Trạm 4 - Responder] Đang đánh giá rủi ro... (MODE HIỆN TẠI: {current_mode})")
    
    severity = state.get("severity", "low").lower()
    evidence = state.get("evidence_strength", 0.0) 
    knowledge_conflict = state.get("knowledge_conflict", False)
    is_suspicious = state.get("is_suspicious", False)
    
    notes = []
    notes.append(f"Responder: Chế độ SOAR hiện tại là {current_mode}.")
    _mitigations, _mit_note = attack_kb.recommend(state)   # B10: tra tất định, không do LLM nghĩ ra
    notes.append(_mit_note)

    # BẢO MẬT: Validate IP trước khi xử lý
    source_ip = state.get("extracted_ioc", {}).get("source_ip", "")
    _ip_field_present = bool(str(source_ip or "").strip())
    if not source_ip or not is_valid_ip(source_ip):
        # Fallback xuống raw log
        raw_log = state.get("raw_log", {})
        if isinstance(raw_log, dict):
            temp_ip = raw_log.get("source_ip", "")
            _ip_field_present = _ip_field_present or bool(str(temp_ip or "").strip())
            source_ip = temp_ip if is_valid_ip(temp_ip) else "Unknown_IP"
        else:
            source_ip = "Unknown_IP"

    # B4.3c: alert endpoint (Sysmon) vốn KHÔNG có IP nguồn — đó không phải giả mạo log.
    # Chỉ báo "giả mạo" khi CÓ trường IP nhưng giá trị không hợp lệ.
    if source_ip == "Unknown_IP" and not _ip_field_present:
        notes.append("Responder: alert không có IP nguồn (thường là alert endpoint) — không có đích để chặn mạng.")
    elif source_ip == "Unknown_IP":
        print("⚠️ CẢNH BÁO: Không thể xác thực được Source IP (Có thể là tấn công chèn mã hoặc Log hỏng).")
        notes.append("Responder [CẢNH BÁO ĐỎ]: Source IP không hợp lệ — khả năng Log Injection/Tampering. Bắn cảnh báo khẩn.")
        notes.append(execute_alert_telegram(
            f"🚨 [LOG TAMPERING ALERT] Source IP không hợp lệ trong log!\n"
            f"Severity: {severity.upper()} | Incident payload có thể bị giả mạo.\n"
            f"Cần SOC Analyst điều tra ngay lập tức.",
            current_mode
        ))
    
    action = "ignore" 
    reason = "Không có mối đe dọa."
    
    # 1. MA TRẬN ỨNG PHÓ RỦI RO — B4.3d: theo quy ước của nhóm (low → không làm gì, medium → người xem,
    #    high/critical → chặn), bằng chứng yếu (< 0.5) thì chỉ báo người xem. Bản cũ đòi high + evidence ≥ 0.85
    #    mới hành động nên gần như mọi ca ra ALERT_OPERATOR. Ngày 4 (Lớp 1) quyết ca chặn nào phải chờ duyệt.
    if severity in ("critical", "high") and evidence < 0.5:
        action = "alert_operator"
        reason = f"Mức {severity.upper()} nhưng bằng chứng yếu (Evidence={evidence}). Cần SOC Analyst xác nhận."
    elif severity == "critical":
        if evidence >= 0.90:
            action = "network_block_full"
            reason = f"Mức Critical, bằng chứng rất mạnh (Evidence={evidence}). Cô lập hoàn toàn IP — chặn INPUT+OUTPUT+FORWARD."
        else:
            action = "block_ip"
            reason = f"Mức Critical (Evidence={evidence}). Chặn IP chiều vào (INPUT)."
    elif severity == "high":
        action = "block_ip"
        reason = f"Mức High, có bằng chứng (Evidence={evidence}). Chặn IP chiều vào (INPUT)."
    elif severity == "medium":
        action = "alert_operator"
        reason = "Mức Medium: đáng ngờ, cần SOC Analyst xem xét."
    elif severity == "low":
        if is_suspicious:
            action = "monitor"
            reason = "Mức Low nhưng có điểm bất thường (is_suspicious=True). Bật theo dõi."
        else:
            action = "ignore"
            reason = "Hoạt động hợp lệ hoặc không đáng kể."

    # 2. LỚP PHÒNG NGỰ KNOWLEDGE CONFLICT
    if knowledge_conflict:
        notes.append("Responder [SKEPTICISM]: CẢNH BÁO - AI phát hiện mâu thuẫn tri thức.")
        if action == "isolate_container" and evidence >= 0.90:
            notes.append(f"Responder [OVERRIDE]: Mâu thuẫn tri thức BỊ BỎ QUA do bằng chứng trực tiếp quá mạnh. Giữ lệnh PAUSE CONTAINER.")
        elif action in ["network_block_full", "block_ip"]:
            original_action = action
            action = "alert_operator"
            reason = f"Hạ cấp từ {original_action.upper()} xuống ALERT_OPERATOR vì hoài nghi tài liệu RAG."
            notes.append(f"Responder: Tước quyền tự động hóa để đảm bảo an toàn.")

    notes.append(f"Responder [Quyết định]: {action.upper()} - {reason}")
    print(f"[+] Quyết định hành động: {action.upper()} | Evidence: {evidence}")

    # ===== LỚP 1 — RULE OF TWO (Ngày 4, bật ở l1/l12/full) =====
    # Rule of Two (theo OWASP Agentic & hướng dẫn của Anthropic): một tác tử KHÔNG được đồng thời
    #   (A) đọc dữ liệu không tin cậy, (B) có quyền thực hiện hành động hệ trọng, (C) tự trị không giám sát.
    # Ở đây: Analyzer đọc dữ liệu (A) nhưng chỉ xuất NHÃN có cấu trúc (mức, mã, bằng chứng) — không chọn
    # hành động. Responder chọn hành động bằng BẢNG QUYẾT ĐỊNH TẤT ĐỊNH ở trên (dựa trên mức + bằng chứng,
    # KHÔNG đọc phần lý giải tự do của LLM). Và mọi LỆNH CHẶN bị tước quyền tự trị (C): phải qua người duyệt.
    _pending_block = False
    if layer_enabled(1) and action in ("block_ip", "network_block_full"):
        _pending_block = True
        notes.append(f"Responder [Lớp 1 - Rule of Two]: '{action.upper()}' là hành động hệ trọng → KHÔNG tự "
                     f"thực thi. Chuyển trạng thái BLOCK_PENDING chờ người duyệt (Agent chỉ ĐỀ XUẤT).")

    # ===== LỚP 4 — KHIÊN TRÊN ĐƯỜNG THỰC THI (OutputSanitizer) =====
    # Dù Analyzer bị ảo giác hay bị tiêm, lệnh SOAR vẫn phải qua danh sách trắng ngay trước khi chạm iptables:
    # hành động thuộc tập cho phép, IP đúng IPv4, không chứa ký tự thực thi (; & | ` $ ...). Sai → không thực thi.
    _sanitizer_block = False
    if layer_enabled(4) and not _pending_block and action not in ("ignore", "monitor"):
        _av = OutputSanitizer.validate_action(action)
        _iv = (OutputSanitizer.validate_ip(source_ip)
               if source_ip and source_ip != "Unknown_IP" else {"valid": True, "reason": "ok"})
        if not _av["valid"] or not _iv["valid"]:
            _sanitizer_block = True
            notes.append(f"Responder [Lớp 4 - Sanitizer]: CHẶN thực thi '{action}' trên IP '{source_ip}' "
                         f"(action={_av['reason']}, ip={_iv.get('reason')}). Nghi lệnh bị ảo giác/tiêm.")

    # 3. THỰC THI SOAR PLAYBOOK
    if _pending_block:
        notes.append("Responder [SOAR Execution]: Bỏ qua thực thi — đang chờ người duyệt (Lớp 1).")
    elif _sanitizer_block:
        notes.append("Responder [SOAR Execution]: Bỏ qua thực thi — bị OutputSanitizer chặn (Lớp 4).")
    else:
        notes.append(f"Responder [SOAR Execution]: Tiến hành xử lý IP {source_ip}...")
    
    if (not _pending_block) and (not _sanitizer_block) and source_ip and source_ip != "Unknown_IP":
        if action == "network_block_full":
            notes.append(execute_network_block_full(source_ip, current_mode))
            notes.append(execute_alert_telegram(f"🚨 [CRITICAL] NETWORK BLOCK FULL — IP {source_ip} bị cô lập hoàn toàn (INPUT+OUTPUT+FORWARD)", current_mode))
            
        elif action == "block_ip":
            notes.append(execute_block_ip(source_ip, current_mode))
            notes.append(execute_alert_telegram(f"🔥 [HIGH] Đã tự động Block IP: {source_ip}", current_mode))
            
        elif action == "throttle":
            notes.append(execute_throttle_ip(source_ip, current_mode))
            
        elif action == "alert" or action == "alert_operator":
            notes.append(execute_alert_telegram(f"⚠️ Cần SOC Analyst kiểm tra IP: {source_ip}. Lý do: {reason}", current_mode))
            
        elif action == "monitor":
            notes.append(execute_monitor_ip(source_ip, current_mode))
            
        elif action == "ignore":
            pass 
    else:
        notes.append("Responder [SOAR Execution]: Bỏ qua vì không có Source IP hợp lệ.")

    # 4. DATA COLLECTION ĐỂ REVIEW (CÓ INCIDENT ID CHỐNG TRÙNG LẶP)
    if severity in ["high", "critical"] and evidence >= 0.7:
        try:
            os.makedirs("training_data", exist_ok=True)
            log_file_path = "training_data/pending_review.jsonl" 
            
            # correlation_id là incident ID thật — fallback về timestamp nếu không có
            incident_id = (
                state.get("correlation_id")
                or state.get("incident_id")
                or f"INC_{__import__('time').strftime('%Y%m%d_%H%M%S')}"
            )

            raw_ai = state.get("raw_ai_verdict", {})
            training_sample = {
                "incident_id": incident_id,
                "instruction": f"Phân tích log sau và đánh giá mức độ nguy hiểm. Log: {state.get('raw_log')}",
                "input": "",
                "output": json.dumps({
                    "thought_process":   raw_ai.get("thought_process", ""),
                    "reasoning":         raw_ai.get("reasoning", ""),
                    "mitre_mapping":     state.get("mitre_mapping", []),
                    "severity":          severity.upper(),
                    "evidence_strength": state.get("evidence_strength", 0.0),
                    "attack_chain":      state.get("attack_chain_visual", "Unknown")
                }, ensure_ascii=False),
                "human_reviewed": False
            }
            with open(log_file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(training_sample, ensure_ascii=False) + "\n")
            notes.append(f"Responder [Dataset Candidate]: Đã lưu log (Incident ID: {incident_id}) vào file pending_review.jsonl chờ duyệt.")
        except Exception as e:
            notes.append(f"Responder [Auto-Save Error]: Lỗi lưu file -> {e}")

    # ===== KẾT QUẢ — Lớp 1 đổi nhãn + chế độ khi chờ duyệt =====
    if _pending_block:
        final_action = "block_pending"            # bộ đo quy đổi → "block" (đề xuất đúng, chỉ chờ con người)
        out_mode = "human_review_required"
        out_reason = f"[Chờ người duyệt] Đề xuất {action.upper()}: {reason}. Lớp 1 giữ lại cho con người quyết."
        notes.append(f"Responder [Kết quả]: BLOCK_PENDING ({action.upper()}) — chờ người duyệt, chưa thực thi gì.")
    else:
        final_action = action
        out_mode = "autonomous"
        out_reason = reason

    return {
        "action_taken": final_action,
        "agent_mode": out_mode,
        "final_response": final_action,
        "response_reason": out_reason,
        "mitigations": _mitigations,              # B10
        "investigation_notes": notes
    }