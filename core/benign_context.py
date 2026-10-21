"""core/benign_context.py — ALLOWLIST NGỮ CẢNH BENIGN cho R1/R2 (tất định, không LLM).

R1/R2 (core/attack_kb.escalation) chỉ nhìn tactic. Module này trả lời một câu hẹp:
  "MỌI sự kiện trong chuỗi có phải đều là hoạt động đã biết (đúng người, đúng tactic, đúng giờ) không?"
Có → R1/R2 bị bỏ qua cho sự cố đó (và ghi rõ lý do để người duyệt thấy). Không → R1/R2 áp dụng như cũ.

Nguyên tắc an toàn:
  - Chỉ BỎ QUA một lần NÂNG mức; không bao giờ HẠ mức nào (Analyzer vẫn chạy bình thường).
  - Fail-closed về phía bảo vệ: thiếu file / sai YAML / lỗi bất kỳ → không có mẫu → R1/R2 chạy nguyên vẹn.
  - Một sự kiện lạ trong chuỗi là đủ để R1/R2 áp lại (chuỗi được tính lại ở mỗi alert mới).
  - IP nguồn có trong threat_intel/local_iocs.yaml, hoặc luật mức critical → không bao giờ được giải thích.
Dữ liệu: assets/benign_context.yaml (xem chú thích trong file). Chỉ đọc dữ liệu hệ thống tự có (User của Sysmon,
máy phát động từ kiểm kê), không đọc chữ nào do kẻ tấn công viết (CommandLine, URI, User-Agent...).
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTEXT_PATH = os.path.join(_ROOT, "assets", "benign_context.yaml")
NEVER_WAIVE_LEVELS = {"critical"}


def enabled() -> bool:
    return os.getenv("BENIGN_CONTEXT_ENABLED", "1").strip().lower() not in ("0", "false", "no")


def _load() -> dict:
    try:
        from agent.nodes.enricher import _load_yaml        # cùng bộ nạp YAML tự làm mới khi file đổi
        d = _load_yaml(CONTEXT_PATH)
    except Exception:
        return {"tz": 7.0, "patterns": []}
    pats = [p for p in (d.get("patterns") or []) if isinstance(p, dict) and p.get("id")]
    try:
        tz = float(d.get("tz_offset_hours", 7))
    except (TypeError, ValueError):
        tz = 7.0
    return {"tz": tz, "patterns": pats}


def _iocs() -> set:
    try:
        from agent.nodes.enricher import _ioc_index
        return set(_ioc_index().keys())
    except Exception:
        return set()


def _same_account(user: str, name: str) -> bool:
    u, n = (user or "").strip().lower(), (name or "").strip().lower()
    if not u or not n:
        return False
    return u == n or u.split("\\")[-1] == n.split("\\")[-1]


def _minutes(hhmm: Any) -> Optional[int]:
    try:
        h, m = str(hhmm).split(":")
        return int(h) * 60 + int(m)
    except (ValueError, TypeError):
        return None


def _in_hours(ts: Any, window: Any, tz: float) -> bool:
    """True nếu giờ địa phương của sự kiện nằm trong [start, end). Hỗ trợ khung vắt qua nửa đêm. Không đọc được → False."""
    if not isinstance(window, (list, tuple)) or len(window) != 2:
        return False
    a, b = _minutes(window[0]), _minutes(window[1])
    if a is None or b is None:
        return False
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    loc = dt.astimezone(timezone(timedelta(hours=tz)))
    cur = loc.hour * 60 + loc.minute
    return (a <= cur < b) if a <= b else (cur >= a or cur < b)


def explain(event: Dict[str, Any], ctx: Optional[dict] = None, iocs: Optional[set] = None) -> Optional[str]:
    """Id mẫu giải thích sự kiện này, hoặc None."""
    ctx = ctx or _load()
    iocs = _iocs() if iocs is None else iocs
    if str(event.get("rule_level") or "").lower() in NEVER_WAIVE_LEVELS:
        return None
    if str(event.get("source_ip") or "") in iocs:
        return None
    tactic = str(event.get("tactic") or "")
    actor = str(event.get("actor_key") or "")
    asset = actor.split(":", 1)[1].lower() if actor.startswith("asset:") else ""
    user = str(event.get("user") or "")
    for p in ctx["patterns"]:
        accounts = [str(x) for x in (p.get("accounts") or [])]
        assets = [str(x).lower() for x in (p.get("assets") or [])]
        who = (user and any(_same_account(user, a) for a in accounts)) or (asset and asset in assets)
        if not who:
            continue
        if tactic not in [str(t) for t in (p.get("tactics") or [])]:
            continue
        if p.get("hours_local") and not _in_hours(event.get("event_timestamp"), p["hours_local"], ctx["tz"]):
            continue
        return str(p["id"])
    return None


def waiver(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Nếu MỌI sự kiện có tactic của sự cố đều được giải thích → {"pattern_ids","covered","why"}; ngược lại None."""
    try:
        if not enabled():
            return None
        ctx = _load()
        if not ctx["patterns"]:
            return None
        iocs = _iocs()
        evs = [e for e in events if e.get("tactic")]
        if not evs:
            return None
        ids: List[str] = []
        for e in evs:
            pid = explain(e, ctx, iocs)
            if not pid:
                return None
            if pid not in ids:
                ids.append(pid)
        return {"pattern_ids": ids, "covered": len(evs),
                "why": f"cả {len(evs)} sự kiện có tactic đều là hoạt động đã biết ({', '.join(ids)}): "
                       f"đúng danh tính, đúng tactic, đúng khung giờ"}
    except Exception:
        return None
