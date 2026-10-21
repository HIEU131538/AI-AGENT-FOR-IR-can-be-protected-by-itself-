"""
agent/nodes/enricher.py — Ngày 2 (AegisSOC): LÀM GIÀU TẤT ĐỊNH — KHÔNG DÙNG LLM

Trả lời sẵn 3 câu một analyst SOC luôn hỏi trước khi kết luận (kế hoạch mục 5):
  1. Tài sản  : máy đích / máy nguồn là máy gì, quan trọng cỡ nào?   → assets/inventory.yaml
  2. Tình báo : IP có tiền án không?  → threat_intel/local_iocs.yaml, rồi AbuseIPDB (chỉ IP công khai, cache 24h)
  3. Lịch sử  : trong cùng incident, trước đó đã xảy ra gì?           → attack_timeline của Correlator

Vị trí trong graph:  extractor → correlator → [enricher] → retriever → analyzer → reflection → responder
Đầu vào : state["alert"] (alert gốc, giữ từ B1). Rỗng (đường /analyze cũ) thì dùng raw_log.
Đầu ra  : state["enrichment"] — CHỈ chứa giá trị hệ thống tự tra ra (tài sản, IOC, tên/mức luật Splunk),
          không chứa chữ nào lấy từ phần dữ liệu tấn công (User-Agent, URI, CommandLine...).
          → Ngày 3 đưa nguyên khối này vào phần `trusted` của ticket; Ngày 4 Responder dùng trực tiếp.
Lỗi bất kỳ (thiếu file, YAML sai, mạng lỗi) → ghi vào enrichment["errors"], KHÔNG làm dừng pipeline.
"""
import ipaddress
import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml

# ==========================================
# CẤU HÌNH
# ==========================================
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INVENTORY_PATH = os.path.join(_ROOT, "assets", "inventory.yaml")
IOC_PATH = os.path.join(_ROOT, "threat_intel", "local_iocs.yaml")
ABUSE_CACHE_PATH = os.path.join(_ROOT, "threat_intel", ".cache", "abuseipdb.json")

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSE_TTL_SECONDS = 24 * 3600      # cache 24 giờ
ABUSE_TIMEOUT_SECONDS = 3          # mạng chậm thì bỏ qua, không bắt pipeline chờ
HISTORY_MAX_EVENTS = 8             # câu lịch sử hiện tối đa 8 sự kiện gần nhất

_STAGE_VI = {
    "reconnaissance": "trinh sát",
    "initial_access": "truy cập ban đầu",
    "exploitation": "khai thác",
    "execution": "thực thi",
    "privilege_escalation": "leo thang",
    "exfiltration": "điều khiển/rò rỉ",
    # B10: tên tactic ATT&CK (Correlator giờ lấy giai đoạn từ tactic) — chỉ để hiển thị trong ghi chú
    "resource_development": "chuẩn bị hạ tầng", "persistence": "duy trì truy cập", "stealth": "ẩn mình",
    "defense_impairment": "vô hiệu phòng thủ", "credential_access": "đánh cắp thông tin xác thực",
    "discovery": "khám phá hệ thống", "lateral_movement": "di chuyển ngang", "collection": "thu thập dữ liệu",
    "command_and_control": "điều khiển từ xa", "impact": "phá hoại",
}

_yaml_lock = threading.Lock()
_abuse_lock = threading.Lock()


# ==========================================
# 1. ĐỌC FILE YAML (tự nạp lại khi file đổi — sửa inventory lúc demo không cần restart)
# ==========================================
_yaml_cache: Dict[str, Tuple[float, dict]] = {}


def _load_yaml(path: str) -> dict:
    """Trả dict của file YAML. Thiếu file / sai cú pháp → ném lỗi để node ghi vào errors."""
    mtime = os.path.getmtime(path)          # FileNotFoundError nếu thiếu file
    with _yaml_lock:
        cached = _yaml_cache.get(path)
        if cached and cached[0] == mtime:
            return cached[1]
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{os.path.basename(path)} phải là một mapping YAML")
    with _yaml_lock:
        _yaml_cache[path] = (mtime, data)
    return data


def _asset_index() -> Tuple[Dict[str, dict], Dict[str, dict]]:
    """Chỉ mục tài sản theo IP và theo tên máy (không phân biệt hoa thường)."""
    by_ip: Dict[str, dict] = {}
    by_name: Dict[str, dict] = {}
    for a in _load_yaml(INVENTORY_PATH).get("assets") or []:
        if not isinstance(a, dict):
            continue
        rec = {
            "name": str(a.get("name") or ""),
            "ip": str(a.get("ip") or ""),
            "role": str(a.get("role") or "unknown"),
            "criticality": str(a.get("criticality") or "unknown").lower(),
            # Thiếu trường → mặc định KHÔNG cho tự chặn (an toàn hơn)
            "auto_block_allowed": a.get("auto_block_allowed") is True,
            "note": str(a.get("note") or ""),
        }
        if rec["ip"]:
            by_ip[rec["ip"]] = rec
        if rec["name"]:
            by_name[rec["name"].lower()] = rec
    return by_ip, by_name


def _account_lookup(user: str) -> Optional[dict]:
    """B4.3c: tra tài khoản (mục `accounts` của inventory). Khớp DOMAIN\\user hoặc chỉ phần user."""
    u = (user or "").strip().lower()
    if not u:
        return None
    short = u.split("\\")[-1]
    for a in _load_yaml(INVENTORY_PATH).get("accounts") or []:
        if not isinstance(a, dict) or not a.get("name"):
            continue
        name = str(a["name"]).strip().lower()
        if u == name or short == name.split("\\")[-1]:
            return {"name": str(a["name"]), "role": str(a.get("role") or "unknown"), "note": str(a.get("note") or "")}
    return None


def _ioc_index() -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for i in _load_yaml(IOC_PATH).get("iocs") or []:
        if isinstance(i, dict) and i.get("ip"):
            out[str(i["ip"]).strip()] = {
                "verdict": str(i.get("verdict") or "suspicious").lower(),
                "source": "local_iocs",
                "reason": str(i.get("reason") or ""),
            }
    return out


# ==========================================
# 2. TÌNH BÁO IP
# ==========================================
_abuse_mem: Dict[str, dict] = {}
_abuse_loaded = False


def _abuse_cache_load() -> None:
    global _abuse_loaded
    if _abuse_loaded:
        return
    _abuse_loaded = True
    try:
        with open(ABUSE_CACHE_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _abuse_mem.update(data)
    except (OSError, ValueError):
        pass


def _abuse_cache_save() -> None:
    try:
        os.makedirs(os.path.dirname(ABUSE_CACHE_PATH), exist_ok=True)
        tmp = ABUSE_CACHE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_abuse_mem, f, ensure_ascii=False, indent=1)
        os.replace(tmp, ABUSE_CACHE_PATH)
    except OSError:
        pass  # không ghi được cache thì thôi, lần sau tra lại


def _abuseipdb(ip: str, errors: List[str]) -> dict:
    with _abuse_lock:
        _abuse_cache_load()
        hit = _abuse_mem.get(ip)
        if hit and time.time() - float(hit.get("checked_at", 0)) < ABUSE_TTL_SECONDS:
            return {**hit["result"], "cached": True}

    key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not key:
        return {"verdict": "unknown", "source": "abuseipdb", "reason": "chưa cấu hình ABUSEIPDB_API_KEY"}
    try:
        from core.egress import guard as _egress_guard   # Lớp 4: chỉ cho gọi host trong danh sách trắng
        _egress_guard(ABUSE_URL)
        resp = requests.get(
            ABUSE_URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=ABUSE_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        d = resp.json().get("data", {}) or {}
        score = int(d.get("abuseConfidenceScore") or 0)
        verdict = "known_bad" if score >= 75 else "suspicious" if score >= 25 else "clean"
        result = {
            "verdict": verdict,
            "source": "abuseipdb",
            "abuse_score": score,
            "total_reports": int(d.get("totalReports") or 0),
            "country": str(d.get("countryCode") or ""),
        }
    except Exception as e:  # mạng lỗi, hết hạn mức, JSON lạ... → unknown, không dừng pipeline
        errors.append(f"AbuseIPDB lỗi khi tra {ip}: {type(e).__name__}")  # không ghi chi tiết (tránh lộ key/URL)
        return {"verdict": "unknown", "source": "abuseipdb", "reason": "lỗi khi tra AbuseIPDB"}

    with _abuse_lock:
        _abuse_mem[ip] = {"checked_at": time.time(), "result": result}
        _abuse_cache_save()
    return {**result, "cached": False}


def _threat_intel(ip: str, iocs: Dict[str, dict], errors: List[str]) -> dict:
    if not ip:
        return {"verdict": "no_ip", "source": None}
    if ip in iocs:
        return dict(iocs[ip])
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"verdict": "invalid_ip", "source": None}
    if not addr.is_global:
        return {"verdict": "no_record", "source": "local_iocs",
                "reason": "IP nội bộ, không có trong IOC nội bộ — AbuseIPDB không có dữ liệu cho IP này"}
    return _abuseipdb(ip, errors)


# ==========================================
# 3. LỊCH SỬ (ghép chuỗi bằng Python theo mẫu cố định)
# ==========================================
def _epoch(ts: Any) -> float:
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))  # Python 3.10 chưa hiểu hậu tố "Z"
    except ValueError:
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _hhmm(ts: Any) -> str:
    e = _epoch(ts)
    return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%H:%M") if e else "??:??"


def _clean(text: Any, limit: int = 80) -> str:
    return " ".join(str(text).split())[:limit]  # bỏ xuống dòng, cắt ngắn


def _history(state: dict) -> dict:
    cid = state.get("correlation_id", "")
    events = [e for e in (state.get("attack_timeline") or [])
              if isinstance(e, dict) and cid and e.get("correlation_id") == cid]
    events.sort(key=lambda e: _epoch(e.get("event_timestamp")))

    parts, stages = [], []
    for e in events:
        # rule_name/rule_level lấy từ alert gốc (Correlator ghi vào timeline) — KHÔNG dùng
        # severity do LLM phán, để phần lịch sử hoàn toàn tất định.
        label = _clean(e.get("rule_name") or e.get("event_type") or "sự kiện")
        level = e.get("rule_level")
        parts.append(f"{_hhmm(e.get('event_timestamp'))} {label}" + (f" ({level})" if level else ""))
        stage = e.get("attack_chain_stage")
        if stage and stage != "unknown" and stage not in stages:
            stages.append(stage)

    summary = " → ".join(parts[-HISTORY_MAX_EVENTS:])
    if len(parts) > HISTORY_MAX_EVENTS:
        summary = f"(+{len(parts) - HISTORY_MAX_EVENTS} sự kiện trước) " + summary
    return {
        "incident_id": cid,
        "event_count": len(events),
        "summary": summary,
        "stages": stages,
        "stages_vi": [_STAGE_VI.get(s, s) for s in stages],
    }


# ==========================================
# 4. NODE
# ==========================================
def _describe_asset(asset: Optional[dict]) -> str:
    if not asset:
        return "không có trong kiểm kê"
    block = "cho tự chặn" if asset["auto_block_allowed"] else "không tự chặn"
    return f"{asset['name']} ({asset['role']}, mức {asset['criticality']}, {block})"


def _describe_ti(ip: str, ti: dict) -> str:
    if ti.get("verdict") == "no_ip":
        return "không có IP"
    src = f" [{ti['source']}]" if ti.get("source") else ""
    score = f" điểm {ti['abuse_score']}" if "abuse_score" in ti else ""
    return f"{ip}: {ti.get('verdict')}{score}{src}"


def node_enricher(state: dict) -> Dict[str, Any]:
    print("\n[Trạm 1.5 - Enricher] Đang làm giàu: tài sản · tình báo IP · lịch sử (tất định, không LLM)...")

    alert = state.get("alert") or {}
    raw = state.get("raw_log") or {}
    errors: List[str] = []

    src_ip = str(alert.get("src_ip") or raw.get("source_ip") or "")
    dest_ip = str(alert.get("dest_ip") or raw.get("destination_ip") or "")
    surface = str(alert.get("surface") or raw.get("surface") or "")
    host = str(alert.get("host") or "")

    # --- 1. Tài sản ---
    dest_asset = src_asset = None
    dest_match = None
    try:
        by_ip, by_name = _asset_index()
        if dest_ip in by_ip:
            dest_asset, dest_match = by_ip[dest_ip], "ip"
        elif surface == "endpoint" and host.lower() in by_name:
            # Alert Sysmon thường không có dest_ip: máy xảy ra sự kiện chính là trường `host`
            dest_asset, dest_match = by_name[host.lower()], "host"
        src_asset = by_ip.get(src_ip)
    except Exception as e:
        errors.append(f"Không đọc được assets/inventory.yaml: {type(e).__name__}: {_clean(e, 120)}")

    # --- 2. Tình báo IP ---
    try:
        iocs = _ioc_index()
    except Exception as e:
        errors.append(f"Không đọc được threat_intel/local_iocs.yaml: {type(e).__name__}: {_clean(e, 120)}")
        iocs = {}
    ti_src = _threat_intel(src_ip, iocs, errors)
    ti_dest = _threat_intel(dest_ip, iocs, errors)

    # --- 3. Lịch sử ---
    try:
        history = _history(state)
    except Exception as e:
        errors.append(f"Lỗi ghép lịch sử: {type(e).__name__}")
        history = {"incident_id": state.get("correlation_id", ""), "event_count": 0,
                   "summary": "", "stages": [], "stages_vi": []}

    # --- 4. Tài khoản (B4.3c) — tiến trình chạy dưới tài khoản nào (trường User của Sysmon) ---
    fields = alert.get("fields") if isinstance(alert.get("fields"), dict) else {}
    user = str(fields.get("User") or raw.get("User") or raw.get("orig_User") or "")
    account = None
    try:
        account = _account_lookup(user)
    except Exception as e:
        errors.append(f"Không tra được tài khoản: {type(e).__name__}")

    # --- Tóm tắt 1 dòng (ghép theo mẫu cố định) ---
    dest_label = dest_ip or (host if dest_match == "host" else "") or "-"
    src_part = _describe_ti(src_ip, ti_src)
    if src_asset:
        src_part += f" = {src_asset['name']} ({src_asset['role']})"
    summary = (f"đích {dest_label}: {_describe_asset(dest_asset)} · nguồn {src_part} · "
               f"lịch sử {history['event_count']} sự kiện")
    if user:
        summary += f" · tài khoản {user}: " + (f"{account['role']}" if account else "không có trong danh mục")

    enrichment = {
        "version": 1,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "surface": surface,
        "dest_asset": dest_asset,
        "dest_asset_match": dest_match,
        "src_asset": src_asset,
        "user": user,
        "account": account,                                  # B4.3c
        "threat_intel": {"src_ip": ti_src, "dest_ip": ti_dest},
        "history": history,
        "summary": summary,
        "errors": errors,
    }

    notes = [
        f"Enricher [Tài sản]: đích {dest_label} → {_describe_asset(dest_asset)}"
        + (f"; nguồn {src_ip} → {_describe_asset(src_asset)}" if src_asset else ""),
        f"Enricher [Tình báo]: nguồn {src_part}"
        + (f"; đích {_describe_ti(dest_ip, ti_dest)}" if dest_ip else ""),
        f"Enricher [Lịch sử]: {history['summary'] or 'chưa có sự kiện trước'}",
    ]
    if errors:
        notes.append(f"Enricher [CẢNH BÁO]: {len(errors)} lỗi khi làm giàu (pipeline vẫn chạy): {errors[:3]}")

    print(f"[+] Làm giàu: {summary}")
    return {"enrichment": enrichment, "investigation_notes": notes}
