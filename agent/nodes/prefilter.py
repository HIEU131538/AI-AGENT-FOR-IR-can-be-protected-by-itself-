"""agent/nodes/prefilter.py — LÀN LỌC TRƯỚC (prefilter) đứng trước Agent.

Mục đích: Llama 8B chậm (~10-15s/alert). Prefilter là bộ gác nhanh (mili-giây) quyết định
mỗi alert CÓ đáng để Agent đọc không. Bộ điều hướng theo `surface`:
  - network (Suricata) → LÀN ML: Random Forest hiệu chuẩn (prefilter/model.py) trên 12 đặc trưng luồng.
  - web / endpoint     → LÀN LUẬT: Tier 0 (nhiễu kỹ thuật) theo assets/prefilter_rules.yaml; còn lại cho qua.
                         (Tier 1 — Extractor regex — KHÔNG chuyển sang đây: regex nhắm log web, alert endpoint từ
                          Sigma không khớp sẽ bị coi nhầm là "sạch". Tier 1 vẫn ở đường cũ /analyze/batch.)
  - MỌI bề mặt         → GỘP TRÙNG tất định trước cả hai làn (xem _dedup).

Trả verdict dict để _process_one_alert quyết định:
  {"lane","decision"∈{DROP,DUP,PASS_UNCERTAIN,PASS},"prob","reason","variant"}
  DROP           → KHÔNG đưa lên Agent (vẫn ghi lại để kiểm tra sau).
  DUP            → alert trùng (D1 cùng alert_id / D2 nội dung giống hệt trong cửa sổ ngắn): KHÔNG đưa lên Agent,
                   đếm vào `repeat_count` của alert gốc (`repeat_of`).
  PASS_UNCERTAIN → đưa lên Agent, ghi "prefilter không chắc" vào ngăn trusted của ticket.
  PASS           → đưa lên Agent bình thường.

An toàn: thiếu dữ liệu luồng / chưa train model → PASS (không bao giờ vì lỗi dữ liệu mà bỏ alert).
Chỉ QUYẾT ĐỊNH có vào Agent hay không — KHÔNG đụng 4 lớp phòng vệ, không đụng Analyzer.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core import flow_features as ff
from prefilter import model as pf

# Bật/tắt làn ML qua biến môi trường (mặc định bật nếu có model).
_ENABLED = os.getenv("PREFILTER_ENABLED", "1").strip().lower() not in ("0", "false", "no")
_VARIANT = os.getenv("PREFILTER_VARIANT", "subset_flow").strip()


# ──────────────────────────────────────────────────────────────────────────
# Cấu hình làn luật + gộp trùng (assets/prefilter_rules.yaml) — lỗi bất kỳ → fail-open
# ──────────────────────────────────────────────────────────────────────────
_RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                           "assets", "prefilter_rules.yaml")
_DEDUP_ON = os.getenv("PREFILTER_DEDUP", "1").strip().lower() not in ("0", "false", "no")
_LEVEL_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_DEDUP_MAX = 5000            # số khoá nhớ tối đa (xoá khoá cũ nhất khi đầy)


def _cfg() -> dict:
    try:
        from agent.nodes.enricher import _load_yaml     # cùng bộ nạp YAML tự làm mới khi file đổi
        c = _load_yaml(_RULES_PATH)
    except Exception:
        c = {}
    pats = []
    for r in (c.get("noise_rule_regex") or []):
        try:
            pats.append(re.compile(str(r)))
        except re.error:
            continue
    return {
        "noise": pats,
        "noise_max_rank": _LEVEL_RANK.get(str(c.get("noise_max_level") or "low").lower(), 0),
        "window": float(c.get("dedup_window_s", 10) or 0),
        "ttl": float(c.get("dedup_id_ttl_s", 60) or 0),
    }


_lock = threading.Lock()
_seen_ids: "OrderedDict[str, tuple]" = OrderedDict()       # alert_id → (thời gian thực, alert_id gốc)
_seen_content: "OrderedDict[str, dict]" = OrderedDict()    # băm nội dung → {first, wall, event, count}


def reset_state() -> None:
    """Gọi từ /reset: mỗi ca đo là một ca độc lập, không nhớ alert của ca trước."""
    with _lock:
        _seen_ids.clear()
        _seen_content.clear()


def _event_epoch(ts: Any) -> float:
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _content_key(alert: Dict[str, Any]) -> str:
    body = {k: alert.get(k) for k in ("surface", "rule_name", "rule_level", "attack_ids", "src_ip", "dest_ip", "dest_port", "host", "fields")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")).hexdigest()


def _trim(d: "OrderedDict") -> None:
    while len(d) > _DEDUP_MAX:
        d.popitem(last=False)


def _dedup(alert: Dict[str, Any], cfg: dict) -> Optional[Dict[str, Any]]:
    """D1 (cùng alert_id) + D2 (nội dung giống hệt, sự kiện cách nhau <= window). Trả verdict DUP hoặc None."""
    if not _DEDUP_ON or cfg["ttl"] <= 0:
        return None
    aid = str(alert.get("alert_id") or "")
    now = time.time()
    ev = _event_epoch(alert.get("timestamp"))
    ckey = _content_key(alert)
    with _lock:
        hit = _seen_ids.get(aid) if aid else None
        if hit and now - hit[0] <= cfg["ttl"]:
            first = hit[1]
            c = _seen_content.get(ckey)
            if c and c["first"] == first:
                c["count"] += 1
            return {"lane": "dedup", "decision": "DUP", "prob": None, "variant": None, "repeat_of": first,
                    "reason": f"D1: cùng alert_id trong {cfg['ttl']:.0f}s (bridge gửi lại) → không phân tích lần hai"}
        c = _seen_content.get(ckey)
        if (c and cfg["window"] > 0 and now - c["wall"] <= cfg["ttl"]
                and ev and c["event"] and abs(ev - c["event"]) <= cfg["window"]):
            c["count"] += 1
            if aid:
                _seen_ids[aid] = (now, c["first"])
                _trim(_seen_ids)
            return {"lane": "dedup", "decision": "DUP", "prob": None, "variant": None,
                    "repeat_of": c["first"], "repeat_count": c["count"],
                    "reason": (f"D2: nội dung giống hệt {c['first']} cách {abs(ev - c['event']):.0f}s "
                               f"(<= {cfg['window']:.0f}s) → gộp, đếm lần lặp thứ {c['count']}")}
        # alert mới (hoặc đã quá cửa sổ): ghi nhớ làm "bản gốc"
        _seen_content[ckey] = {"first": aid, "wall": now, "event": ev, "count": 1}
        _seen_content.move_to_end(ckey)
        _trim(_seen_content)
        if aid:
            _seen_ids[aid] = (now, aid)
            _trim(_seen_ids)
    return None


def _noise(alert: Dict[str, Any], cfg: dict) -> Optional[Dict[str, Any]]:
    """Tier 0 trên đường alert: nhiễu kỹ thuật (xem assets/prefilter_rules.yaml). Chỉ DROP khi chắc chắn."""
    name = str(alert.get("rule_name") or "")
    level = str(alert.get("rule_level") or "").lower()
    if alert.get("attack_ids"):
        return None                                   # luật phát hiện tấn công, không phải nhiễu
    if _LEVEL_RANK.get(level, 99) > cfg["noise_max_rank"]:
        return None
    for pat in cfg["noise"]:
        if pat.search(name):
            return {"lane": "rule", "decision": "DROP", "prob": None, "variant": None,
                    "reason": f"Tier 0: nhiễu kỹ thuật (luật '{name[:60]}', mức {level}, không mã ATT&CK)"}
    return None


def run_prefilter(alert: Dict[str, Any]) -> Dict[str, Any]:
    surface = str(alert.get("surface") or "").strip().lower()

    # Gộp trùng + Tier 0: tất định, lỗi bất kỳ → bỏ qua bước (fail-open, không bao giờ vì lỗi mà bỏ alert).
    try:
        cfg = _cfg()
        v = _dedup(alert, cfg)
        if v:
            return v
        if surface != "network":
            v = _noise(alert, cfg)
            if v:
                return v
    except Exception:
        pass

    # Làn luật: web/endpoint — hết nhiễu thì cho qua.
    if surface != "network":
        return {"lane": "rule", "decision": "PASS", "prob": None,
                "reason": f"surface={surface or '?'} → làn luật", "variant": None}

    if not _ENABLED or not pf.available(_VARIANT):
        return {"lane": "ml", "decision": "PASS", "prob": None,
                "reason": "prefilter tắt hoặc chưa có model → cho qua", "variant": _VARIANT}

    feat = ff.from_suricata(alert)
    if feat is None:
        return {"lane": "ml", "decision": "PASS", "prob": None,
                "reason": "thiếu dữ liệu luồng → cho qua", "variant": _VARIANT}

    p = pf.prob(ff.to_row(feat), _VARIANT)
    verdict = pf.decide(p, _VARIANT)
    verdict.update({"lane": "ml", "variant": _VARIANT})
    return verdict
