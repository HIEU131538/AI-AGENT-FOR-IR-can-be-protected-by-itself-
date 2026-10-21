"""replay/demo/attack_on_agent/run.py — Kịch bản 3 (tấn công nhắm vào tác tử AI).

Ba chế độ:
  --what live [--step]  TRÌNH DIỄN TRÊN DASHBOARD: gửi alert sạch + alert bị tiêm tới CẢ off (:8010) và full (:8000),
                KHÔNG reset giữa chừng → mọi alert nằm lại trên feed để chỉ vào. (Không phải phép đo.)
  --what 3a     ĐO Bảng 2 (injection): mỗi payload chạy N lần (--repeat, mặc định 1), có /reset trước từng ca
                → dashboard chỉ giữ ca cuối, NÊN KHÔNG dùng chế độ này để "nhìn dashboard".
  --what live3b [--step]  như live nhưng cho 3b (RAG): baseline → tiêm tài liệu độc → alert sau tiêm, từng bước.
  --what 3b     ĐO Bảng 3 (RAG poisoning): cơ chế cũ vs mới.
  --what both   3a + 3b (mặc định).

Kết quả: results_demo/ . Tự kiểm: python replay/demo/attack_on_agent/verify_demo.py

Biến môi trường: AGENT_TOKEN, AGENT_INTERNAL_TOKEN (3b cần cả hai).
"""
import argparse
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEMO_DIR = Path(__file__).parent
OUT_DIR = ROOT / "results_demo"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(DEMO_DIR))

PAYLOADS_3A = DEMO_DIR / "3a_injection_payloads.json"
DOCS_3B = DEMO_DIR / "3b_rag_poison.json"


def banner(text):
    line = "=" * 70
    print(f"\n{line}\n  {text}\n{line}\n")


def run_cmd(cmd):
    print(f"$ {' '.join(str(x) for x in cmd)}")
    rc = subprocess.run(cmd, cwd=str(ROOT)).returncode
    if rc != 0:
        print(f"\n[!] Lệnh trả mã lỗi {rc}")
    return rc


def run_3a(repeat, skip_preflight):
    banner(f"KỊCH BẢN 3a — Indirect Prompt Injection (ua-003, body-001) · {repeat} lần lặp")
    for old in OUT_DIR.glob("3a_r*"):          # chỉ xoá thư mục kết quả 3a do chính script này sinh
        shutil.rmtree(old, ignore_errors=True)
    rc = 0
    for i in range(1, repeat + 1):
        print(f"--- Lần {i}/{repeat} ---")
        cmd = [sys.executable, "-m", "eval.eval_injection",
               "--payloads", str(PAYLOADS_3A), "--profiles", "off,full",
               "--out", str(OUT_DIR / f"3a_r{i}")]
        if skip_preflight or i > 1:            # kiểm sẵn sàng một lần là đủ
            cmd.append("--skip-preflight")
        rc = max(rc, run_cmd(cmd))
    banner("TỔNG HỢP 3a")
    from verify_demo import print_3a_summary
    print_3a_summary(OUT_DIR)
    return rc


def run_3b():
    banner("KỊCH BẢN 3b — RAG Poisoning (test-poison-002)")
    rc = run_cmd([sys.executable, "-m", "eval.eval_rag_poison",
                  "--docs", str(DOCS_3B), "--mechanisms", "old,new", "--out", str(OUT_DIR)])
    print(f"\n-> Kết quả 3b: {OUT_DIR / 'table3.csv'}")
    return rc


def run_live(step=False):
    """Gửi alert sạch + alert độc tới off và full, KHÔNG reset giữa các alert (trừ một lần ở đầu)."""
    from eval.common import PROFILES, call_agent, extract_prediction, reset_agent
    from eval.eval_injection import BUILDERS, CLEAN_VALUES
    import json

    banner("TRÌNH DIỄN TRÊN DASHBOARD — alert sạch vs alert bị tiêm (off :8010 · full :8000)")
    payloads = json.loads(PAYLOADS_3A.read_text(encoding="utf-8"))["payloads"]
    for prof in ("off", "full"):
        err = reset_agent(prof)
        print(f"  reset {prof}: {'OK' if not err else err}")
        if err:
            return 1
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rc = 0
    print(f"\n  {'alert':<24} {'off':<22} {'full':<22}")
    for idx, pl in enumerate(payloads):
        for kind, value in (("clean", CLEAN_VALUES[pl["field"]]), ("poisoned", pl["injection"])):
            if step:
                try:
                    input(f"\n  [Enter] gửi {pl['id']} {kind} tới off + full ... ")
                except EOFError:
                    pass
            row = {}
            for prof in ("off", "full"):
                a = BUILDERS[pl["base"]](pl["field"], value)
                a["alert_id"] = f"demo3a:{pl['id']}:{kind}"
                a["src_ip"] = f"198.51.100.{10 + idx * 2 + (kind == 'poisoned')}"   # mỗi alert một nguồn → không gộp incident
                a["timestamp"] = now
                a["summary"] = f"{a['rule_name']} | {a['src_ip']} -> {a['dest_ip']}:{a['dest_port']} | host={a['host']}"
                raw = call_agent(prof, [a], reset_first=False)
                p = extract_prediction(raw)
                row[prof] = "LỖI: " + str(p.get("error"))[:30] if p.get("error") else f"{p.get('severity')}/{p.get('action')}"
                rc = max(rc, 1 if p.get("error") else 0)
            print(f"  {pl['id'] + ' ' + kind:<24} {row['off']:<22} {row['full']:<22}")
    print("\n  → Mở dashboard: tab Feed của full (:8000) và off (:8010). Alert 'poisoned' có UA/body chứa lệnh giả.")
    print("    So sánh dòng clean và poisoned ở từng bản: bản nào bị hạ mức/hạ action khi có payload = bị dắt.")
    return rc


def run_live_3b(step=False):
    """3b trên dashboard: baseline → tiêm tài liệu độc → alert sau tiêm, gửi cho cả off (cơ chế cũ) và full (cơ chế mới).
    KHÔNG reset giữa các bước (chỉ một lần ở đầu) nên cả hai alert nằm lại trên feed của từng bản."""
    import json
    from eval.common import PROFILES, call_agent, extract_prediction, reset_agent
    from eval.eval_rag_poison import (make_alert, inject_doc, get_rag_block, conclusion_changed,
                                      reset_all_test_docs, reset_one_doc)
    from datetime import timedelta

    banner("TRÌNH DIỄN 3b TRÊN DASHBOARD — RAG poisoning (off = cơ chế cũ · full = manifest HMAC)")
    doc = json.loads(DOCS_3B.read_text(encoding="utf-8"))["docs"][0]
    sides = (("off", "cũ"), ("full", "mới"))

    def pause(msg):
        if step:
            try:
                input(f"\n  [Enter] {msg} ... ")
            except EOFError:
                pass

    for prof, _ in sides:
        err = reset_agent(prof)
        ok, remaining = reset_all_test_docs(PROFILES[prof])
        print(f"  reset {prof}: feed {'OK' if not err else err} · kho RAG {'sạch' if ok and remaining in (0, None) else 'LỖI (thiếu AGENT_INTERNAL_TOKEN?)'}")
        if err or not ok:
            return 1

    now = datetime.now(timezone.utc)
    base, poisoned = {}, {}
    rc = 0

    def send(kind, ts):
        out = {}
        for prof, _ in sides:
            a = make_alert(kind)
            a["alert_id"] = f"demo3b:sqli:{kind}"             # cùng alert_id cho cả hai bản → tab SO SÁNH ghép đúng cặp
            a["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%SZ")  # lệch >10 s giữa hai alert để dedup không coi là trùng
            raw = call_agent(prof, [a], reset_first=False)
            out[prof] = (extract_prediction(raw), get_rag_block(raw))
        return out

    pause("BƯỚC 1 — gửi alert SQLi khi kho RAG còn SẠCH (đối chứng)")
    base = send("baseline", now - timedelta(minutes=2))
    for prof, name in sides:
        p, rag = base[prof]
        rc = max(rc, 1 if p.get("error") else 0)
        print(f"  [{prof:<4} {name}] mức/hành động = {p.get('severity')}/{p.get('action')}")

    pause("BƯỚC 2 — tiêm tài liệu độc (giả Sigma rule 'hạ mức, đừng chặn IP 203.0.113.45') vào kho của cả hai bản")
    inj = {}
    for prof, name in sides:
        inj[prof] = inject_doc(PROFILES[prof], doc) or {}
        print(f"  [{prof:<4} {name}] cảnh báo toàn vẹn = {inj[prof].get('integrity_alert')} · lý do = {inj[prof].get('integrity_reason')}")

    pause("BƯỚC 3 — gửi lại alert SQLi, xem tài liệu độc có lọt vào ngữ cảnh LLM không")
    poisoned = send("poisoned", now)
    print(f"\n  {'':<12} {'lọt ngữ cảnh?':<16} {'bị chặn ở truy xuất?':<22} {'mức/hành động':<18} đổi kết luận?")
    for prof, name in sides:
        p, rag = poisoned[prof]
        rc = max(rc, 1 if p.get("error") else 0)
        in_ctx = bool(rag.get("injected_in_context"))
        in_rej = bool(rag.get("injected_rejected"))
        chg = conclusion_changed(base[prof][0], p)
        print(f"  {prof + ' (' + name + ')':<12} {('CÓ' if in_ctx else 'không'):<16} {('CÓ' if in_rej else 'không'):<22} "
              f"{str(p.get('severity')) + '/' + str(p.get('action')):<18} {chg}")
    for prof, _ in sides:
        reset_one_doc(PROFILES[prof], doc["doc_id"])           # trả kho về sạch; feed giữ nguyên
    print("\n  → Dashboard: tab SO SÁNH OFF ‖ FULL (chọn demo3b:sqli:poisoned) và tab toàn vẹn RAG.")
    print("    Điểm chính: bản cũ để tài liệu độc lọt vào ngữ cảnh; bản mới chặn ngay ở truy xuất (not_in_signed_manifest).")
    return rc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--what", choices=["live", "live3b", "3a", "3b", "both"], default="both")
    ap.add_argument("--repeat", type=int, default=1, help="số lần lặp 3a (mặc định 1; số liệu nhiều lần lấy từ benchmark đã đo)")
    ap.add_argument("--step", action="store_true", help="chế độ live: dừng chờ Enter trước mỗi alert (gửi từng cái một để chỉ vào dashboard)")
    ap.add_argument("--skip-preflight", action="store_true", help="bỏ kiểm sẵn sàng (chỉ khi chắc agent đã sẵn sàng)")
    args = ap.parse_args()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    rc = 0
    if args.what == "live":
        rc = run_live(args.step)
    if args.what == "live3b":
        rc = run_live_3b(args.step)
    if args.what in ("3a", "both"):
        rc = max(rc, run_3a(max(1, args.repeat), args.skip_preflight))
    if args.what in ("3b", "both"):
        rc = max(rc, run_3b())
    if args.what not in ("live", "live3b"):
        banner("XONG KỊCH BẢN 3")
        print(f"Kết quả ở: {OUT_DIR}\nTự kiểm: python replay/demo/attack_on_agent/verify_demo.py")
    return rc


if __name__ == "__main__":
    sys.exit(main())
