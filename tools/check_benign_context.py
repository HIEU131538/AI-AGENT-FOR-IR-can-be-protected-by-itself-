"""tools/check_benign_context.py — KIỂM TẤT ĐỊNH (không LLM, không Ollama) cho 3 thứ mới:
  1) allowlist ngữ cảnh benign (core/benign_context.py) trên golden/benign_chain_fixtures_v1.json;
  2) Tier 0 + gộp trùng của prefilter (agent/nodes/prefilter.py);
  3) allowlist không làm đổi R1/R2 của bộ vàng v2 (mọi ca tấn công vẫn nâng như cũ).
Chạy:  python tools/check_benign_context.py        (từ thư mục gốc repo)
Thoát mã 0 nếu mọi kiểm tra đạt.
"""
import contextlib
import io
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
os.chdir(REPO)

from api.alert_adapter import Alert, to_legacy_raw_log          # noqa: E402
from agent.nodes import correlator as C                          # noqa: E402
from core import benign_context as BC                            # noqa: E402

FAILS = []


def check(cond, msg):
    print(("  [OK]   " if cond else "  [FAIL] ") + msg)
    if not cond:
        FAILS.append(msg)


def run_chain(alerts, ctx_on):
    os.environ["BENIGN_CONTEXT_ENABLED"] = "1" if ctx_on else "0"
    tl, last = [], None
    for a in sorted(alerts, key=lambda x: x["timestamp"]):
        al = Alert(**a)
        st = {"raw_log": to_legacy_raw_log(al), "alert": al.model_dump(), "extracted_ioc": {}, "attack_timeline": tl}
        with contextlib.redirect_stdout(io.StringIO()):
            out = C.node_correlator(st)
        tl = tl + out["attack_timeline"]
        last = out["attack_chain"]
    return last


print("== 1) Allowlist ngữ cảnh benign trên fixture ==")
fx = json.load(open("golden/benign_chain_fixtures_v1.json", encoding="utf-8"))["fixtures"]
for f in fx:
    off, on = run_chain(f["alerts"], False), run_chain(f["alerts"], True)
    e = f["expect"]
    r_off = (off.get("escalation") or {}).get("rule")
    r_on = (on.get("escalation") or {}).get("rule")
    w = on.get("escalation_waived")
    check(r_off == e["without_context"], f"{f['id']} khi TẮT allowlist: {r_off} (mong {e['without_context']})")
    check(r_on == e["with_context"], f"{f['id']} khi BẬT allowlist: {r_on} (mong {e['with_context']})")
    check((w or {}).get("rule") == e["waived"], f"{f['id']} bỏ qua: {(w or {}).get('rule')} (mong {e['waived']})")
    if e.get("patterns"):
        check((w or {}).get("pattern_ids") == e["patterns"], f"{f['id']} mẫu: {(w or {}).get('pattern_ids')}")

print("== 1b) Quy tắc riêng lẻ ==")
base = {"tactic": "persistence", "user": "DOMAIN\\backup", "actor_key": "asset:web-win-01",
        "event_timestamp": "2026-10-03T19:10:00Z", "rule_level": "medium", "source_ip": ""}
check(BC.explain(base) == "BC-BACKUP", "backup, 02:10 local, persistence → BC-BACKUP")
check(BC.explain({**base, "rule_level": "critical"}) is None, "luật mức critical không bao giờ được giải thích")
check(BC.explain({**base, "source_ip": "198.51.100.7"}, iocs={"198.51.100.7"}) is None, "IP nguồn có trong IOC → không giải thích")
check(BC.explain({**base, "tactic": "credential-access"}) is None, "tactic ngoài danh sách → không giải thích")
check(BC.explain({**base, "user": "DOMAIN\\someone"}) is None, "tài khoản lạ → không giải thích")
check(BC.explain({**base, "event_timestamp": "2026-10-03T07:10:00Z"}) is None, "ngoài khung giờ → không giải thích")
check(BC.explain({"tactic": "discovery", "actor_key": "asset:it-scanner-01", "event_timestamp": "2026-10-03T07:10:00Z",
                  "rule_level": "medium", "source_ip": "192.168.56.30"}) == "BC-ITSCAN", "máy quét IT, không ràng giờ → BC-ITSCAN")
check(BC._in_hours("2026-10-03T16:30:00Z", ["22:00", "06:00"], 7.0), "khung giờ vắt qua nửa đêm (23:30 local ∈ 22:00–06:00)")
check(BC.waiver([]) is None, "không có sự kiện → không bỏ qua")
os.environ["BENIGN_CONTEXT_ENABLED"] = "0"
check(BC.waiver([base, {**base, "tactic": "discovery"}]) is None, "BENIGN_CONTEXT_ENABLED=0 → tắt hẳn")
os.environ["BENIGN_CONTEXT_ENABLED"] = "1"

print("== 2) Bộ vàng v2: allowlist không làm đổi R1/R2 ==")
sc = json.load(open("golden/scenarios_v2.json", encoding="utf-8"))["scenarios"]
changed, esc_n = [], 0
for s in sc:
    a, b = run_chain(s["alerts"], False), run_chain(s["alerts"], True)
    ra, rb = (a.get("escalation") or {}).get("rule"), (b.get("escalation") or {}).get("rule")
    esc_n += 1 if ra else 0
    if ra != rb:
        changed.append((s["id"], ra, rb))
check(not changed, f"không kịch bản nào đổi R1/R2 (có R1/R2: {esc_n}/{len(sc)}; đổi: {changed})")

print("== 3) Prefilter: Tier 0 + gộp trùng ==")
os.environ.pop("PREFILTER_DEDUP", None)
from agent.nodes import prefilter as P                            # noqa: E402
P.reset_state()


def A(aid, ts="2026-10-03T10:00:00Z", rule="Suspicious Execution of Systeminfo", level="low", ids=("T1082",),
      surface="endpoint", fields=None, **kw):
    d = {"alert_id": aid, "rule_name": rule, "rule_level": level, "attack_ids": list(ids), "surface": surface,
         "timestamp": ts, "src_ip": "", "dest_ip": "", "dest_port": None, "host": "web-win-01",
         "fields": fields if fields is not None else {"User": "DOMAIN\\admin", "CommandLine": "systeminfo.exe"}}
    d.update(kw)
    return d


v = P.run_prefilter(A("x1"))
check(v["decision"] == "PASS" and v["lane"] == "rule", "alert endpoint bình thường → PASS (làn luật)")
v = P.run_prefilter(A("x1"))
check(v["decision"] == "DUP" and v["reason"].startswith("D1"), "gửi lại cùng alert_id → DUP (D1)")
v = P.run_prefilter(A("x2", ts="2026-10-03T10:00:05Z"))
check(v["decision"] == "DUP" and v["reason"].startswith("D2") and v["repeat_of"] == "x1", "nội dung giống hệt cách 5 s → DUP (D2)")
v = P.run_prefilter(A("x3", ts="2026-10-03T10:00:30Z"))
check(v["decision"] == "PASS", "nội dung giống hệt nhưng cách 30 s (> cửa sổ 10 s) → PASS (giữ để đếm lặp có chủ ý)")
v = P.run_prefilter(A("x4", ts="2026-10-03T10:00:31Z", fields={"User": "DOMAIN\\backup", "CommandLine": "systeminfo.exe"}))
check(v["decision"] == "PASS", "cùng luật nhưng KHÁC nội dung (tài khoản khác) → PASS")
v = P.run_prefilter(A("n1", rule="LB Health Check Heartbeat", level="low", ids=()))
check(v["decision"] == "DROP" and v["reason"].startswith("Tier 0"), "luật health check, mức low, không mã ATT&CK → DROP (Tier 0)")
v = P.run_prefilter(A("n2", rule="LB Health Check Heartbeat", level="low", ids=("T1046",)))
check(v["decision"] == "PASS", "tên giống nhiễu nhưng CÓ mã ATT&CK → PASS (không loại luật phát hiện)")
v = P.run_prefilter(A("n3", rule="LB Health Check Heartbeat", level="high", ids=()))
check(v["decision"] == "PASS", "tên giống nhiễu nhưng mức high → PASS")
nf = {"flow": {"pkts_toserver": 1, "bytes_toserver": 60}}
a1 = A("s1", rule="Net Scan", level="medium", ids=("T1046",), surface="network", fields=nf, src_ip="192.168.56.30")
a2 = A("s2", ts="2026-10-03T10:00:03Z", rule="Net Scan", level="medium", ids=("T1046",), surface="network", fields=nf, src_ip="192.168.56.30")
a3 = A("s3", ts="2026-10-03T10:00:04Z", rule="Net Scan", level="medium", ids=("T1046",), surface="network",
       fields={"flow": {"pkts_toserver": 9, "bytes_toserver": 5000}}, src_ip="192.168.56.30")
P.run_prefilter(a1)
check(P.run_prefilter(a2)["decision"] == "DUP", "Suricata: cùng alert + cùng đặc trưng luồng → DUP")
check(P.run_prefilter(a3)["decision"] != "DUP", "Suricata: luồng KHÁC (đặc trưng khác) → KHÔNG gộp, ML vẫn chấm riêng")
P.reset_state()
check(P.run_prefilter(A("x1"))["decision"] == "PASS", "reset_state() xoá trí nhớ gộp trùng (như /reset)")

print()
if FAILS:
    print(f"THẤT BẠI: {len(FAILS)} kiểm tra không đạt")
    sys.exit(1)
print("TẤT CẢ ĐẠT")
