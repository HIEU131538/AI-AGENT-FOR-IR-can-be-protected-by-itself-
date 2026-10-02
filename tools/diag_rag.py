"""
tools/diag_rag.py — CHẨN ĐOÁN: Llama thật sự được đưa gì trước khi phán? (chỉ ĐỌC, không sửa gì)

Với từng kịch bản vàng, chạy các trạm tất định của Agent thật (extractor → correlator → enricher →
retriever) trên kho RAG của profile, rồi CHỤP LẠI prompt đầy đủ mà Analyzer sẽ gửi cho Llama
(không gọi Llama — không cần Ollama). Kèm thống kê kho RAG: số tài liệu theo loại, độ dài token.
B4.3b: đọc danh sách tài liệu thật sự đã dùng (state["rag_docs"]: tra đúng luật / kỹ thuật / tìm lai).

Chạy (tắt uvicorn bản `off` trước cho khỏi tranh kho, ~1–2 phút):
    python tools\\diag_rag.py
    python tools\\diag_rag.py --profile off --scenarios golden/scenarios.json --out results/diag_rag

Kết quả (thư mục results/ đã nằm trong .gitignore):
    summary.csv        mỗi kịch bản một dòng: truy vấn RAG, tài liệu đã dùng (cách lấy + điểm)
    prompts/<id>.txt   prompt đầy đủ Analyzer gửi cho Llama
    store_stats.txt    thống kê kho + tỉ lệ tra đúng luật/kỹ thuật
"""
import argparse
import contextlib
import csv
import io
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # console Windows không lỗi dấu tiếng Việt
sys.path.insert(0, str(REPO))
os.chdir(REPO)

ap = argparse.ArgumentParser(description="Chẩn đoán RAG + prompt của Analyzer (chỉ đọc)")
ap.add_argument("--profile", default="off", help="kho RAG của profile nào (mặc định off)")
ap.add_argument("--scenarios", default="golden/scenarios.json")
ap.add_argument("--out", default="results/diag_rag")
args = ap.parse_args()
os.environ["DEFENSE_PROFILE"] = args.profile          # chọn kho rag_stores/<profile>

BIASED = "chắc chắn là cuộc tấn công"


def quiet(fn, *a, **kw):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **kw)


print("[*] Nạp các trạm của Agent (mất ~20 s để nạp mô hình embedding)...")
with contextlib.redirect_stdout(io.StringIO()):
    from langchain_core.runnables import RunnableLambda
    from api.alert_adapter import Alert, to_legacy_raw_log
    from agent.nodes.extractor import node_extractor
    from agent.nodes.correlator import node_correlator
    from agent.nodes.enricher import node_enricher
    from core.ticket import node_ticket_builder      # B5
    import agent.nodes.retriever as R
    import agent.nodes.analyzer as A
    from core.profile import RAG_STORE_DIR

if R.retriever_instance is None:
    sys.exit("[-] Không khởi tạo được kho RAG (xem lỗi khi chạy Agent). Dừng.")
db = R.retriever_instance.db
print(f"[+] Kho RAG: {RAG_STORE_DIR}")

# Thay Llama bằng một hàm CHỤP prompt — Analyzer chạy y hệt, chỉ không gọi Ollama.
_captured = {}


def _capture(prompt_value):
    _captured["messages"] = prompt_value.to_messages()
    return A.AnalyzerOutput(thought_process="diag", decision="keep_rule_level", mitre_mapping=[], severity="low",
                            evidence_strength=0.0, confidence_score=0.0,
                            is_suspicious=False, reasoning="diag")


A.structured_llm = RunnableLambda(_capture)


def doc_label(d):
    score = f" {d['score']:.2f}" if isinstance(d.get("score"), (int, float)) else ""
    return f"[{d['how']}] {d['id']}{score}"


def run_scenario(sc):
    timeline, state, alert = [], {}, None
    alerts = sc["alerts"]
    for i, alert in enumerate(alerts):
        raw = to_legacy_raw_log(Alert(**alert))
        state = {"raw_log": raw, "alert": alert, "investigation_notes": [],
                 "attack_timeline": list(timeline)}
        state.update(quiet(node_extractor, state))
        c = quiet(node_correlator, state)
        state.update({k: v for k, v in c.items() if k != "attack_timeline"})
        state["attack_timeline"] = timeline + c["attack_timeline"]
        state.update(quiet(node_enricher, state))
        if i < len(alerts) - 1:
            # Agent thật ghi mức Llama đã phán vào lịch sử; ở đây xấp xỉ bằng mức luật Splunk.
            state["attack_timeline"][-1]["severity"] = alert.get("rule_level", "low")
        timeline = state["attack_timeline"]

    state.update(quiet(node_ticket_builder, state))   # B5: đúng thứ tự đồ thị — làm giàu → ticket → RAG
    query = R.build_query(state) if hasattr(R, "build_query") else ""
    state.update(quiet(R.node_retriever, state))
    _captured.clear()
    quiet(A.node_analyzer, state)

    docs = state.get("rag_docs") or []
    ctx = state.get("rag_context", "")
    gt = sc["ground_truth"]
    msgs = _captured.get("messages", [])
    row = {
        "id": sc["id"], "name": sc["name"], "gt_severity": gt.get("severity"),
        "gt_attack_ids": " ".join(gt.get("attack_ids", [])), "is_attack": gt.get("is_attack", True),
        "surface": alert.get("surface"), "rule_name": alert.get("rule_name"), "rule_level": alert.get("rule_level"),
        "indicators": " ".join(state.get("extracted_ioc", {}).get("attack_indicators", [])),
        "incident_severity": state.get("incident_severity"),
        "query": query,
        "n_docs": len(docs),
        "exact_rule": any(d["how"] == "exact_rule" for d in docs),
        "exact_technique": sum(1 for d in docs if d["how"] == "exact_technique"),
        "related": " | ".join(doc_label(d) for d in docs if d["how"] == "related"),
        "ids_in_context": " ".join(sorted({d["id"].split(":")[1] for d in docs if d["id"].startswith("mitre:")})),
        "trust_score": state.get("context_trust_score"),
        "n_docs_biased_sentence": ctx.count(BIASED),
        "prompt_chars": sum(len(m.content) for m in msgs),
    }
    return row, msgs


def store_stats():
    """Thống kê kho: số tài liệu theo loại, token mỗi tài liệu, % bị mô hình nhúng cắt đuôi."""
    from collections import Counter
    out = []
    emb = R.retriever_instance.embeddings
    model = getattr(emb, "client", None) or getattr(emb, "_client", None)
    got = db.get(include=["documents", "metadatas"])
    docs, metas = got["documents"], [m or {} for m in got["metadatas"]]
    kinds = Counter(m.get("doc_kind") or m.get("source_type") for m in metas)
    out.append(f"Tổng số tài liệu: {len(docs)} · theo loại: {dict(kinds)}")
    out.append(f"Luật nền (base_rule): {sum(1 for m in metas if m.get('base_rule'))} · "
               f"bản nạp: {Counter(m.get('ingest_version', 'v1') for m in metas)}")
    if model is not None and hasattr(model, "tokenizer"):
        max_len = getattr(model, "max_seq_length", 256)
        for kind in sorted(kinds):
            lens = sorted(len(model.tokenizer(t, add_special_tokens=True)["input_ids"])
                          for t, m in zip(docs, metas) if (m.get("doc_kind") or m.get("source_type")) == kind)
            if lens:
                cut = sum(1 for n in lens if n > max_len)
                out.append(f"{kind}: {len(lens)} tài liệu · token trung vị {lens[len(lens)//2]} · lớn nhất {lens[-1]} · "
                           f"vượt {max_len} (bị cắt khi nhúng): {cut} ({cut/len(lens):.0%})")
    else:
        out.append("(không đọc được tokenizer — bỏ qua thống kê token)")
    return out


def main():
    scenarios = json.loads(Path(args.scenarios).read_text(encoding="utf-8"))["scenarios"]
    out = Path(args.out)
    (out / "prompts").mkdir(parents=True, exist_ok=True)
    rows = []
    for sc in scenarios:
        row, msgs = run_scenario(sc)
        rows.append(row)
        text = "\n\n".join(f"===== [{m.type}] =====\n{m.content}" for m in msgs)
        (out / "prompts" / f"{sc['id']}.txt").write_text(text, encoding="utf-8")
        print(f"  {row['id']:6} gt={row['gt_severity']:8} | luật khớp={'có' if row['exact_rule'] else 'không':5} "
              f"kỹ thuật={row['exact_technique']} | liên quan: {row['related'][:60]}")
    with open(out / "summary.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print("[*] Thống kê kho RAG...")
    stats = store_stats()
    n = len(rows)
    stats += [
        "",
        f"Kịch bản: {n}",
        f"Tra đúng được luật đã bắn alert: {sum(1 for r in rows if r['exact_rule'])}/{n}",
        f"Tra đúng được kỹ thuật ATT&CK của luật: {sum(1 for r in rows if r['exact_technique'] > 0)}/{n}",
        f"Có tài liệu liên quan qua tìm lai: {sum(1 for r in rows if r['related'])}/{n}",
        f"Có câu '{BIASED}' trong context: {sum(1 for r in rows if r['n_docs_biased_sentence'] > 0)}/{n}",
        f"Độ dài prompt TB: {sum(r['prompt_chars'] for r in rows) // n} ký tự",
    ]
    (out / "store_stats.txt").write_text("\n".join(stats), encoding="utf-8")
    print("\n".join(stats))
    print(f"\n[+] Xong. Kết quả ở {out}/")


if __name__ == "__main__":
    main()
