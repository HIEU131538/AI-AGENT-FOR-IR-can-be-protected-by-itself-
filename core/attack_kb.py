"""core/attack_kb.py — B10: tra cứu MITRE ATT&CK TẤT ĐỊNH (không dùng LLM).

Dùng ở ba chỗ:
  1. Correlator  — giai đoạn tấn công của mỗi alert = TACTIC ATT&CK của mã kỹ thuật mà luật gắn
                   (thay cho đoán bằng từ khoá); chuỗi sự cố = các tactic theo thứ tự ma trận Enterprise.
  2. Analyzer    — luật nâng mức theo tiến triển tactic (xem escalation()).
  3. Responder   — khuyến nghị giảm thiểu theo mitigation (M-code) ATT&CK của các kỹ thuật trong sự cố.

Nguồn: data/mitre_cti.json (STIX bundle chính thức của MITRE). Lần đầu chạy dựng chỉ mục gọn
data/attack_index.json (~vài trăm KB) để những lần sau nạp nhanh. Thiếu cả hai file → mọi hàm trả rỗng/None,
hệ thống quay về cách cũ (không bao giờ vì thiếu dữ liệu ATT&CK mà lỗi).

Quy ước "tactic chính" của một alert: tactic ĐẦU TIÊN mà ATT&CK liệt kê cho mã kỹ thuật ĐẦU TIÊN của luật.
Một kỹ thuật có thể thuộc nhiều tactic (vd T1053.005 Scheduled Task: Execution, Persistence, Privilege Escalation);
chỉ lấy một tactic/alert để một alert đơn lẻ không bao giờ tự "trải" nhiều tactic.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional

_REPO = Path(__file__).resolve().parent.parent
CTI_PATH = _REPO / "data" / "mitre_cti.json"
INDEX_PATH = _REPO / "data" / "attack_index.json"

# Nhóm tactic dùng cho luật nâng mức (định nghĩa TRƯỚC khi đo, theo ý nghĩa của ma trận ATT&CK):
#   ENTRY — kẻ tấn công vừa vào được / vừa thực thi được mã;
#   POST  — đã ở lại, leo quyền, đi ngang, điều khiển từ xa, lấy dữ liệu hoặc phá hoại (hậu khai thác).
ENTRY_TACTICS = {"initial-access", "execution"}
POST_TACTICS = {"persistence", "privilege-escalation", "credential-access", "lateral-movement",
                "collection", "command-and-control", "exfiltration", "impact"}
MULTI_TACTIC_THRESHOLD = 3          # R1: sự cố trải >= 3 tactic khác nhau → critical


def build_index(cti_path: Path = CTI_PATH) -> dict:
    """Đọc STIX bundle ATT&CK → chỉ mục gọn: tactic (theo thứ tự ma trận), kỹ thuật, mitigation."""
    objs = json.loads(Path(cti_path).read_text(encoding="utf-8"))["objects"]
    alive = lambda o: not (o.get("revoked") or o.get("x_mitre_deprecated"))
    ext = lambda o: next((r.get("external_id") for r in o.get("external_references", [])
                          if r.get("source_name") == "mitre-attack"), None)

    tac_by_ref = {o["id"]: o for o in objs if o.get("type") == "x-mitre-tactic"}
    matrix = next((o for o in objs if o.get("type") == "x-mitre-matrix"), None)
    refs = matrix.get("tactic_refs", []) if matrix else list(tac_by_ref)
    tactics = [{"short": tac_by_ref[r]["x_mitre_shortname"], "id": ext(tac_by_ref[r]), "name": tac_by_ref[r]["name"]}
               for r in refs if r in tac_by_ref]

    tech_by_ref, techniques = {}, {}
    for o in objs:
        if o.get("type") != "attack-pattern" or not alive(o):
            continue
        tid = ext(o)
        if not tid:
            continue
        tech_by_ref[o["id"]] = tid
        techniques[tid] = {"name": o.get("name", ""),
                           "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                                       if p.get("kill_chain_name") == "mitre-attack"]}

    coa = {o["id"]: (ext(o), o.get("name", "")) for o in objs if o.get("type") == "course-of-action" and alive(o)}
    mitig: Dict[str, List[dict]] = {}
    for r in objs:
        if r.get("type") == "relationship" and r.get("relationship_type") == "mitigates" and alive(r):
            m, t = coa.get(r.get("source_ref")), tech_by_ref.get(r.get("target_ref"))
            if m and m[0] and t:
                lst = mitig.setdefault(t, [])
                if all(x["id"] != m[0] for x in lst):
                    lst.append({"id": m[0], "name": m[1]})
    for lst in mitig.values():
        lst.sort(key=lambda x: x["id"])

    version = (matrix or {}).get("x_mitre_version") or next(
        (o.get("x_mitre_version") for o in objs if o.get("type") == "x-mitre-collection"), None)
    return {"source": "MITRE ATT&CK Enterprise (STIX)", "matrix_version": version,
            "built": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tactics": tactics, "techniques": techniques, "mitigations": mitig}


@lru_cache(maxsize=1)
def _kb() -> dict:
    try:
        if INDEX_PATH.exists():
            return json.loads(INDEX_PATH.read_text(encoding="utf-8"))
        if CTI_PATH.exists():
            idx = build_index(CTI_PATH)
            try:
                INDEX_PATH.write_text(json.dumps(idx, ensure_ascii=False), encoding="utf-8")
            except OSError:
                pass
            return idx
    except Exception as e:  # dữ liệu hỏng → chạy tiếp như không có ATT&CK
        print(f"[!] attack_kb: không nạp được chỉ mục ATT&CK ({type(e).__name__}) — tắt các tính năng B10.")
    return {"tactics": [], "techniques": {}, "mitigations": {}}


def available() -> bool:
    return bool(_kb().get("techniques"))


def _norm(tid) -> str:
    return str(tid or "").strip().upper()


def technique(tid) -> Optional[dict]:
    """Mục kỹ thuật; mã con không có thì lấy mã cha (T1059.001 → T1059)."""
    t = _norm(tid)
    techs = _kb()["techniques"]
    return techs.get(t) or (techs.get(t.split(".")[0]) if "." in t else None)


def tactics_of(tid) -> List[str]:
    t = technique(tid)
    return list(t["tactics"]) if t else []


def primary_tactic(attack_ids: Iterable) -> Optional[str]:
    """Tactic chính của một alert (xem quy ước ở đầu file)."""
    for tid in attack_ids or []:
        ts = tactics_of(tid)
        if ts:
            return ts[0]
    return None


@lru_cache(maxsize=1)
def _order() -> Dict[str, int]:
    return {t["short"]: i for i, t in enumerate(_kb()["tactics"])}


def tactic_order(short: str) -> int:
    return _order().get(short, 99)


def tactic_name(short: str) -> str:
    for t in _kb()["tactics"]:
        if t["short"] == short:
            return t["name"]
    return short


def tactic_id(short: str) -> Optional[str]:
    for t in _kb()["tactics"]:
        if t["short"] == short:
            return t["id"]
    return None


def chain(events: List[dict]) -> dict:
    """Chuỗi ATT&CK của một sự cố từ các sự kiện (mỗi sự kiện có 'tactic', 'technique_ids', 'event_timestamp').
    Trả: tactic theo thứ tự xuất hiện, tactic theo thứ tự ma trận, các kỹ thuật, số tactic khác nhau."""
    evs = [e for e in events if e.get("tactic")]
    evs.sort(key=lambda e: str(e.get("event_timestamp") or ""))
    seen, techs = [], []
    for e in evs:
        if e["tactic"] not in seen:
            seen.append(e["tactic"])
        for t in e.get("technique_ids") or []:
            if _norm(t) not in techs:
                techs.append(_norm(t))
    return {"tactics_observed": seen,
            "tactics_matrix_order": sorted(seen, key=tactic_order),
            "tactic_names": [tactic_name(s) for s in sorted(seen, key=tactic_order)],
            "techniques": techs,
            "distinct_tactics": len(seen),
            "events_with_tactic": len(evs)}


def escalation(events: List[dict]) -> Optional[dict]:
    """Luật nâng mức theo tiến triển tactic (tất định, định nghĩa trước khi đo):
      R1 — sự cố trải >= 3 tactic khác nhau → mức tối thiểu CRITICAL (xâm nhập nhiều giai đoạn đã xác nhận);
      R2 — có tactic hậu khai thác (POST) xảy ra SAU một tactic xâm nhập/thực thi (ENTRY) → mức tối thiểu HIGH.
    Chỉ NÂNG, không bao giờ hạ. Trả None nếu không luật nào kích hoạt."""
    ch = chain(events)
    if ch["distinct_tactics"] >= MULTI_TACTIC_THRESHOLD:
        return {"rule": "R1", "floor": "critical", "chain": ch,
                "why": f"sự cố trải {ch['distinct_tactics']} tactic ATT&CK: " + " → ".join(ch["tactic_names"])}
    evs = sorted([e for e in events if e.get("tactic")], key=lambda e: str(e.get("event_timestamp") or ""))
    entry_seen = False
    for e in evs:
        if e["tactic"] in POST_TACTICS and entry_seen:
            return {"rule": "R2", "floor": "high", "chain": ch,
                    "why": f"hậu khai thác ({tactic_name(e['tactic'])}) sau xâm nhập/thực thi"}
        if e["tactic"] in ENTRY_TACTICS:
            entry_seen = True
    return None


def escalation_ctx(events: List[dict]) -> tuple:
    """R1/R2 có xét ALLOWLIST NGỮ CẢNH BENIGN (core/benign_context.py).
    Trả (escalation, waived): escalation như escalation(); nếu R1/R2 đáng ra kích hoạt nhưng MỌI sự kiện của sự cố
    đều là hoạt động đã biết thì escalation=None và waived mô tả luật bị bỏ qua + lý do (để người duyệt thấy).
    Bỏ qua chỉ có nghĩa là KHÔNG nâng mức; không bao giờ hạ mức."""
    esc = escalation(events)
    if not esc:
        return None, None
    try:
        from core import benign_context
        w = benign_context.waiver(events)
    except Exception:
        w = None
    if w:
        return None, {"rule": esc["rule"], "would_floor": esc["floor"], "rule_why": esc["why"], **w}
    return esc, None


def mitigations_for(technique_ids: Iterable, limit: int = 6) -> List[dict]:
    """Mitigation ATT&CK cho các kỹ thuật của sự cố, xếp theo số kỹ thuật được che phủ (nhiều trước)."""
    acc: Dict[str, dict] = {}
    for tid in technique_ids or []:
        t = _norm(tid)
        lst = _kb()["mitigations"].get(t) or (_kb()["mitigations"].get(t.split(".")[0]) if "." in t else None) or []
        for m in lst:
            e = acc.setdefault(m["id"], {"id": m["id"], "name": m["name"], "techniques": []})
            if t not in e["techniques"]:
                e["techniques"].append(t)
    out = sorted(acc.values(), key=lambda m: (-len(m["techniques"]), m["id"]))
    return out[:limit]


def recommend(state: dict) -> tuple:
    """B10: (danh sách mitigation, dòng ghi chú) cho Responder / nhánh người duyệt.
    Kỹ thuật lấy từ chuỗi ATT&CK của sự cố; thiếu thì lấy mã của alert hiện tại."""
    techs = ((state.get("attack_chain") or {}).get("techniques")
             or [str(t).upper() for t in ((state.get("alert") or {}).get("attack_ids") or [])])
    mits = mitigations_for(techs)
    if not mits:
        return [], ("Responder [ATT&CK Mitigations]: không có mitigation ATT&CK cho "
                    + (", ".join(techs) if techs else "alert không có mã ATT&CK"))
    return mits, ("Responder [ATT&CK Mitigations]: " +
                  "; ".join(f"{m['id']} {m['name']} ({', '.join(m['techniques'])})" for m in mits))
