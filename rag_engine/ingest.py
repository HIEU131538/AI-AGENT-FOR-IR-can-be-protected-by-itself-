"""
rag_engine/ingest.py — B4.3b: NẠP KHO TRI THỨC v2 (thay bản cũ cắt theo ký tự + khung tiếng Việt thiên lệch)

    python rag_engine\\ingest.py            # từ chối nếu chroma_db/ đã có
    python rag_engine\\ingest.py --force    # ĐỔI TÊN kho cũ thành chroma_db_backup_<giờ> rồi nạp mới (không xoá)

Khác bản cũ:
  - Chia theo CẤU TRÚC, không theo số ký tự: 1 luật Sigma = 1 tài liệu; 1 kỹ thuật ATT&CK = 1 đoạn
    "tổng quan" + 1 đoạn "cách phát hiện". Tên và mã có ở MỌI đoạn. Mỗi tài liệu giữ dưới ~256 token
    để mô hình nhúng (MiniLM) không cắt mất đuôi.
  - Văn bản TRUNG TÍNH bằng tiếng Anh (MiniLM là mô hình tiếng Anh). Không còn câu "đây chắc chắn là
    cuộc tấn công"; giữ nguyên mục falsepositives của luật.
  - Metadata đủ để TRA ĐÚNG: luật theo tên (title_norm), kỹ thuật theo mã (technique_id); mã ATT&CK của
    luật Sigma lấy từ tags.
  - MITRE: bỏ phần giảm thiểu dài (trước đây 64% đoạn là văn bản trùng lặp), chỉ giữ tên biện pháp;
    thêm phần phát hiện (detection strategy / analytics) của ATT&CK v18+.
  - Mã tài liệu đọc được: sigma:<id>, mitre:<Txxxx>:overview, mitre:<Txxxx>:detection.
  - Nhúng chuẩn hoá (normalize) + không gian cosine → điểm tương đồng đọc được (0–1).
Nguồn: rules/base/ (luật nền, đánh dấu base_rule=True) + data/sigma_lib/ (thư viện, sync_sigmahq.py)
       + data/mitre_cti.json.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
MITRE_FILE = REPO / "data" / "mitre_cti.json"
BASE_DIR = REPO / "rules" / "base"
LIB_DIR = REPO / "data" / "sigma_lib"
CHROMA_PATH = REPO / "chroma_db"

EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
INGEST_VERSION = "v2"
MAX_CHARS = 950            # ≈ 230 token tiếng Anh — dưới giới hạn 256 của MiniLM
LAB_PLATFORMS = ("Windows", "Network", "Network Devices", "IaaS", "Linux")


def clean(text: str, limit: int) -> str:
    """Bỏ trích dẫn/đường link markdown của ATT&CK, gộp khoảng trắng, cắt độ dài."""
    t = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    t = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"<code>|</code>", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t if len(t) <= limit else t[: limit - 1].rsplit(" ", 1)[0] + "…"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ─────────────────────────────── SIGMA ───────────────────────────────
def _detection_summary(det: dict, limit: int) -> str:
    parts = []
    for key, val in (det or {}).items():
        if key == "condition":
            continue
        items = val if isinstance(val, list) else [val]
        for item in items:
            if isinstance(item, dict):
                for field, v in item.items():
                    vals = v if isinstance(v, list) else [v]
                    shown = ", ".join(str(x) for x in vals[:4]) + (" …" if len(vals) > 4 else "")
                    parts.append(f"{field}: {shown}")
            else:
                parts.append(str(item))
    cond = (det or {}).get("condition")
    text = "; ".join(parts) + (f" (condition: {cond})" if cond else "")
    return clean(text, limit)


def sigma_doc(rule: dict, is_base: bool, origin: str):
    title = str(rule.get("title", "Unknown")).strip()
    level = str(rule.get("level", "medium")).lower()
    ls = rule.get("logsource") or {}
    logsource = "/".join(str(x) for x in [ls.get("product"), ls.get("category"), ls.get("service")] if x)
    tids = [t.split(".", 1)[1].upper() for t in rule.get("tags", []) or []
            if isinstance(t, str) and t.lower().startswith("attack.t")]
    fps = "; ".join(str(x) for x in rule.get("falsepositives") or []) or "Not documented"
    head = (f"Sigma detection rule: {title}\n"
            f"Rule level: {level}. Status: {rule.get('status', 'n/a')}. Log source: {logsource or 'n/a'}.\n"
            f"ATT&CK: {' '.join(tids) or 'none'}\n")
    fp_line = f"Known false positives: {clean(fps, 220)}\n"
    budget = MAX_CHARS - len(head) - len(fp_line)
    desc = clean(str(rule.get("description", "")), max(120, int(budget * 0.55)))
    det = _detection_summary(rule.get("detection"), max(80, budget - len(desc) - 40))
    text = head + f"Description: {desc}\n" + fp_line + f"Detection logic: {det}"
    rid = str(rule.get("id") or sha(title)[:16])
    meta = {
        "source_type": "admin_sigma_rule", "injected_by": "sigma_ingest", "doc_kind": "sigma_rule",
        "sigma_id": rid, "title": title, "title_norm": title.lower(), "level": level,
        "status": str(rule.get("status", "")), "logsource": logsource,
        "technique_id": tids[0] if tids else "", "technique_ids": " ".join(tids),
        "base_rule": is_base, "origin": origin, "trust_score": 1.0,
        "embedding_model": EMBEDDING_MODEL_NAME, "ingest_version": INGEST_VERSION,
    }
    return f"sigma:{rid}", text, meta


def load_sigma():
    docs, seen, skipped = [], set(), 0
    sources = [(p, True, "base") for p in sorted((BASE_DIR / "sigmahq").glob("*.yml"))]
    sources += [(p, True, "base_custom") for p in sorted((BASE_DIR / "custom").glob("*.yml"))]
    sources += [(p, False, "sigmahq_lib") for p in sorted(LIB_DIR.rglob("*.yml"))] if LIB_DIR.exists() else []
    for path, is_base, origin in sources:
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            skipped += 1
            continue
        if not isinstance(rule, dict) or not rule.get("title") or not rule.get("detection"):
            skipped += 1
            continue
        doc_id, text, meta = sigma_doc(rule, is_base, origin)
        if doc_id in seen:           # luật nền cũng có trong thư viện → giữ bản đánh dấu base
            continue
        seen.add(doc_id)
        docs.append((doc_id, text, meta))
    return docs, skipped


# ─────────────────────────────── MITRE ───────────────────────────────
def load_mitre():
    data = json.loads(MITRE_FILE.read_text(encoding="utf-8"))
    objs = data.get("objects", [])
    by_id = {o["id"]: o for o in objs}
    active = lambda o: not (o.get("revoked") or o.get("x_mitre_deprecated"))
    mitig, strat = {}, {}
    for r in objs:
        if r.get("type") != "relationship" or not active(r):
            continue
        src, tgt = by_id.get(r.get("source_ref"), {}), r.get("target_ref")
        if r.get("relationship_type") == "mitigates" and active(src):
            mitig.setdefault(tgt, []).append(src.get("name", ""))
        elif r.get("relationship_type") == "detects" and src.get("type") == "x-mitre-detection-strategy":
            strat.setdefault(tgt, []).append(src)
    version = next((o.get("x_mitre_version") for o in objs if o.get("type") == "x-mitre-collection"), None)
    docs = []
    for o in objs:
        if o.get("type") != "attack-pattern" or not active(o):
            continue
        tid = next((r.get("external_id") for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        name = o.get("name", "")
        tactics = ", ".join(p["phase_name"].replace("-", " ").title() for p in o.get("kill_chain_phases", [])
                            if p.get("kill_chain_name") == "mitre-attack") or "n/a"
        platforms = ", ".join(o.get("x_mitre_platforms", []) or []) or "n/a"
        mits = ", ".join(sorted(set(mitig.get(o["id"], []))))[:200] or "none listed"
        head = f"ATT&CK technique {tid}: {name}\nTactics: {tactics}. Platforms: {platforms}.\n"
        tail = f"\nMitigations: {mits}"
        overview = head + "Description: " + clean(o.get("description", ""), MAX_CHARS - len(head) - len(tail) - 14) + tail
        base_meta = {"source_type": "mitre_framework", "injected_by": "mitre_ingest", "technique_id": tid,
                     "technique_name": name, "tactics": tactics, "platforms": platforms,
                     "is_subtechnique": bool(o.get("x_mitre_is_subtechnique", False)), "trust_score": 0.8,
                     "attack_version": str(version or "unknown"), "embedding_model": EMBEDDING_MODEL_NAME,
                     "ingest_version": INGEST_VERSION}
        docs.append((f"mitre:{tid}:overview", overview, {**base_meta, "doc_kind": "mitre_overview"}))

        analytics = []
        for s in strat.get(o["id"], []):
            for ref in s.get("x_mitre_analytic_refs", []) or []:
                a = by_id.get(ref)
                if a and active(a) and a.get("description"):
                    analytics.append(a)
        # ưu tiên nền tảng có trong lab
        analytics.sort(key=lambda a: 0 if "Windows" in (a.get("x_mitre_platforms") or []) else
                       (1 if any(p in LAB_PLATFORMS for p in a.get("x_mitre_platforms") or []) else 2))
        if analytics:
            dhead = f"How to detect ATT&CK technique {tid}: {name}\n"
            body, budget = [], MAX_CHARS - len(dhead)
            for a in analytics[:3]:
                plat = "/".join(a.get("x_mitre_platforms") or []) or "any"
                piece = f"[{plat}] {clean(a['description'], 380)}"
                if len(piece) + 1 > budget:
                    break
                body.append(piece)
                budget -= len(piece) + 1
            docs.append((f"mitre:{tid}:detection", dhead + "\n".join(body),
                         {**base_meta, "doc_kind": "mitre_detection"}))
    return docs, version


def main() -> int:
    ap = argparse.ArgumentParser(description="Nạp kho tri thức RAG v2")
    ap.add_argument("--force", action="store_true", help="đổi tên kho cũ thành bản sao lưu rồi nạp mới")
    ap.add_argument("--out", default=str(CHROMA_PATH), help="thư mục kho (mặc định chroma_db/)")
    args = ap.parse_args()
    out = Path(args.out)

    if out.exists():
        if not args.force:
            print(f"[-] {out} đã tồn tại. Chạy lại với --force để ĐỔI TÊN kho cũ thành bản sao lưu (không xoá).")
            return 1
        backup = out.with_name(f"{out.name}_backup_{time.strftime('%Y%m%d_%H%M%S')}")
        shutil.move(str(out), str(backup))
        print(f"[*] Đã đổi tên kho cũ → {backup}")

    print("[*] Đọc luật Sigma...")
    sigma, skipped = load_sigma()
    n_base = sum(1 for _, _, m in sigma if m["base_rule"])
    print(f"[+] Sigma: {len(sigma)} luật ({n_base} luật nền), bỏ qua {skipped} file hỏng/rỗng")
    if n_base == 0:
        print("[-] Không thấy luật nền trong rules/base/ — dừng.")
        return 1
    print("[*] Đọc ATT&CK...")
    mitre, version = load_mitre()
    print(f"[+] ATT&CK (phiên bản {version or 'không ghi'}): {len(mitre)} đoạn "
          f"({sum(1 for d in mitre if d[0].endswith(':detection'))} đoạn cách phát hiện)")
    docs = sigma + mitre

    from langchain_huggingface import HuggingFaceEmbeddings
    from langchain_chroma import Chroma
    emb = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL_NAME, encode_kwargs={"normalize_embeddings": True})
    model = getattr(emb, "client", None) or getattr(emb, "_client", None)
    if model is not None and hasattr(model, "tokenizer"):
        max_len = getattr(model, "max_seq_length", 256)
        over = sum(1 for _, t, _ in docs if len(model.tokenizer(t)["input_ids"]) > max_len)
        print(f"[i] Tài liệu vượt {max_len} token (bị mô hình cắt đuôi): {over}/{len(docs)}")

    print(f"[*] Nhúng + lưu {len(docs)} tài liệu vào {out} (vài phút trên CPU)...")
    db = Chroma(persist_directory=str(out), embedding_function=emb,
                collection_metadata={"hnsw:space": "cosine"})
    for i in range(0, len(docs), 500):
        batch = docs[i:i + 500]
        db.add_texts(texts=[t for _, t, _ in batch], metadatas=[m for _, _, m in batch],
                     ids=[d for d, _, _ in batch])
        print(f"    {min(i + 500, len(docs))}/{len(docs)}")

    manifest = {"ingest_version": INGEST_VERSION, "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "embedding_model": EMBEDDING_MODEL_NAME, "attack_version": version,
                "sigma_source": json.loads((LIB_DIR / "_source.json").read_text(encoding="utf-8"))
                if (LIB_DIR / "_source.json").exists() else None,
                "docs": {d: sha(t) for d, t, _ in docs}}
    (out / "_ingest_manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(f"[+] Xong: {db._collection.count()} tài liệu. Manifest: {out / '_ingest_manifest.json'}")
    print("[i] Bước tiếp: python tools\\make_rag_stores.py --force   (sao kho mới thành 4 kho theo profile)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
