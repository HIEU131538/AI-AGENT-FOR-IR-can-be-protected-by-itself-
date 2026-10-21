"""core/flow_features.py — Suricata flow.* → 12 đặc trưng UNSW-NB15 (làn ML của prefilter).

Alert mạng từ Suricata (qua Splunk bridge) có các trường `flow.*`, `proto`, `app_proto`.
Hàm ở đây đổi chúng thành ĐÚNG 12 cột mà model Random Forest học (bản subset_flow):
    dur, proto, service, spkts, dpkts, sbytes, dbytes, rate, sload, dload, smean, dmean

CÔNG THỨC (đã kiểm ngược từ chính dữ liệu UNSW-NB15, khớp tới sai số ~1e-8 — KHÁC với
bản nháp data_report.md ghi "rate = 1/dur"):
    smean = round(sbytes / spkts)           dmean = round(dbytes / dpkts)
    rate  = (spkts + dpkts - 1) / dur
    sload = (sbytes - smean) * 8 / dur       dload = (dbytes - dmean) * 8 / dur
    dur == 0  →  rate = sload = dload = 0

proto/service mã hoá số theo encoders.json của bạn dataset (ánh xạ app_proto qua service_mapping.json).
Thiếu/hỏng trường → trả None; prefilter coi None là "không đủ dữ liệu" và CHO QUA (an toàn,
không bao giờ vì thiếu dữ liệu mà bỏ alert).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

FEATURES = ["dur", "proto", "service", "spkts", "dpkts", "sbytes", "dbytes",
            "rate", "sload", "dload", "smean", "dmean"]

_ART = Path(__file__).resolve().parent.parent / "prefilter" / "artifacts"


def _load_json(name: str, fallback: dict) -> dict:
    # Ưu tiên bản bạn dataset bàn giao; nếu chưa có thì dùng fallback để vẫn chạy được.
    for p in (_ART / name,
              Path(os.getenv("PREFILTER_DATA_DIR", "")) / name if os.getenv("PREFILTER_DATA_DIR") else None):
        try:
            if p and Path(p).exists():
                return json.loads(Path(p).read_text(encoding="utf-8"))
        except Exception:
            pass
    return fallback


# Bảng mã PHẢI là bản prefilter/train_rf.py đã chép từ bạn dataset (cùng bảng model được train).
# Không có bản dự phòng cứng: bảng mã đổi giữa các lần xuất dữ liệu (vd 'ospf' 4→3), dùng bản cũ
# là mã hoá sai âm thầm. Thiếu bảng mã → from_suricata trả None → prefilter CHO QUA (an toàn).
_ENC = _load_json("encoders.json", {})
_SVC_MAP = _load_json("service_mapping.json", {})


def _enc(table: str, raw: str) -> int:
    m = _ENC.get(table, {})
    key = str(raw or "").strip().lower()
    if table == "service":
        key = _SVC_MAP.get(key, key)
    if key in m:
        return int(m[key])
    return int(m.get("__other__", m.get("none", 0)))


def _f(x) -> Optional[float]:
    try:
        if x is None or str(x).strip() == "":
            return None
        return float(x)
    except (TypeError, ValueError):
        return None


def _dig(fields: Dict[str, Any], *names):
    """Lấy giá trị đầu tiên có trong fields theo nhiều tên (có hỗ trợ khoá lồng kiểu 'flow.x')."""
    def _one(v):
        # Splunk có thể trả field bị nhân đôi dạng mảng ['UDP', 'UDP'] → lấy phần tử đầu.
        if isinstance(v, (list, tuple)):
            v = next((x for x in v if x not in (None, "", "-")), None)
        return v
    for n in names:
        if n in fields and _one(fields[n]) not in (None, "", "-"):
            return _one(fields[n])
    low = {str(k).lower(): v for k, v in fields.items()}
    for n in names:
        if n.lower() in low and _one(low[n.lower()]) not in (None, "", "-"):
            return _one(low[n.lower()])
    return None


def from_suricata(alert: Dict[str, Any]) -> Optional[Dict[str, float]]:
    """Trả dict 12 đặc trưng, hoặc None nếu không đủ dữ liệu luồng (thiếu dur/byte/pkt)."""
    fields = dict(alert.get("fields") or {})

    # dur: ưu tiên 'dur' có sẵn → flow.end - flow.start (chính xác tới µs)
    #   → alert chưa có flow.end (luồng còn mở): lấy timestamp sự kiện - flow.start (thời lượng tới lúc báo)
    #   → cuối cùng mới dùng flow.age (Suricata làm tròn xuống GIÂY NGUYÊN: luồng < 1 s ra 0 → rate/sload/dload = 0, lệch thang).
    dur = _f(_dig(fields, "dur", "flow.duration"))
    if dur is None:
        start = _dig(fields, "flow.start", "flow_start")
        end = _dig(fields, "flow.end", "flow_end") or _dig(fields, "timestamp")
        dur = _duration(start, end)
    if dur is None:
        dur = _f(_dig(fields, "flow.age"))
    spkts = _f(_dig(fields, "spkts", "flow.pkts_toserver", "pkts_toserver"))
    dpkts = _f(_dig(fields, "dpkts", "flow.pkts_toclient", "pkts_toclient"))
    sbytes = _f(_dig(fields, "sbytes", "flow.bytes_toserver", "bytes_toserver"))
    dbytes = _f(_dig(fields, "dbytes", "flow.bytes_toclient", "bytes_toclient"))

    if None in (dur, spkts, dpkts, sbytes, dbytes):
        return None   # không đủ số đo luồng → prefilter cho qua
    if not _ENC.get("proto") or not _ENC.get("service"):
        return None   # chưa có bảng mã đồng bộ với model → cho qua

    proto = _enc("proto", _dig(fields, "proto") or alert.get("proto") or "")
    service = _enc("service", _dig(fields, "app_proto", "service") or "")

    smean = round(sbytes / spkts) if spkts > 0 else 0.0
    dmean = round(dbytes / dpkts) if dpkts > 0 else 0.0
    if dur > 0:
        rate = (spkts + dpkts - 1) / dur
        sload = (sbytes - smean) * 8 / dur
        dload = (dbytes - dmean) * 8 / dur
    else:
        rate = sload = dload = 0.0

    return {"dur": dur, "proto": float(proto), "service": float(service),
            "spkts": spkts, "dpkts": dpkts, "sbytes": sbytes, "dbytes": dbytes,
            "rate": float(rate), "sload": float(sload), "dload": float(dload),
            "smean": float(smean), "dmean": float(dmean)}


def _duration(start, end) -> Optional[float]:
    from datetime import datetime

    def _parse(v):
        if v is None:
            return None
        s = str(v).strip()
        try:
            return float(s)                       # epoch giây
        except ValueError:
            pass
        s = s.replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", s):          # Suricata ghi '-0400' → '-04:00' cho mọi bản Python
            s = s[:-2] + ":" + s[-2:]
        try:
            return datetime.fromisoformat(s).timestamp()
        except ValueError:
            return None
    a, b = _parse(start), _parse(end)
    if a is None or b is None:
        return None
    d = b - a
    return d if d >= 0 else None


def to_row(feat: Dict[str, float]) -> list:
    """12 đặc trưng theo đúng thứ tự FEATURES — để đưa vào model."""
    return [float(feat[k]) for k in FEATURES]
