"""tools/make_report.py — gom CSV kết quả benchmark thành MỘT báo cáo Markdown (4 bảng) để dán vào Word.

Tự dò thư mục results/ (đệ quy), không cần đặt đường dẫn tay:

  Bảng 1  — Chất lượng triage (golden v2): off vs full vs splunk_copy.
            Lấy từ mọi table4.csv; thêm macro-F1 mức độ (tự tính từ *_detail.csv).
  Bảng 2  — ASR phòng vệ (injection): off / l1 / l12 / full.
            Gom MỌI table2.csv theo 'Cấu hình', trung bình các lần chạy ×N + dải min–max.
  Bảng 2b — ASR theo trường tải (table2b.csv), trung bình theo profile.
  Bảng 3  — Đầu độc RAG: results/**/table3.csv (7 tài liệu, cơ chế cũ vs mới).
  Bảng 4  — Triage theo nhóm siem_correct=true/false: off vs full.

Thiếu profile/bảng nào thì ghi "— (chưa đo)" — chạy được ở mọi giai đoạn benchmark.
KHÔNG sửa file kết quả; chỉ đọc và ghi 1 file .md.

Chạy:  python tools/make_report.py --results results --out results/BAO_CAO_benchmark.md
"""
import argparse
import csv
import glob
import os
from collections import defaultdict

PROFILES = ["off", "l1", "l12", "full"]
SEVERITIES = ["low", "medium", "high", "critical"]

# Chuỗi con trong đường dẫn sẽ BỊ BỎ QUA khi dò (thư mục thử nghiệm/chẩn đoán cũ,
# không phải số liệu chính thức). Ghi đè bằng --ignore "" nếu muốn gom tất.
IGNORE = ["trial", "diag"]

# Thứ tự + nhãn các chỉ số triage trong table4.csv (giữ nguyên tên tiếng Việt của eval_golden)
TRIAGE_METRICS = [
    "Accuracy mức độ",
    "Đúng mã ATT&CK",
    "Đề xuất đúng hành động",
    "Báo nhầm trên ca lành tính",
    "Thời gian xử lý TB (s)",
    "Tỷ lệ JSON lỗi",
    "Tỷ lệ chuyển người duyệt",
]


# ---------------- Tiện ích ----------------

def _read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.reader(f))


def _read_dicts(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _num(v):
    try:
        return float(str(v).strip())
    except (ValueError, AttributeError):
        return None


def _fmt(v, nd=3):
    if v is None or v == "":
        return "—"
    n = _num(v)
    if n is None:
        return str(v)
    if abs(n - round(n)) < 1e-9 and abs(n) >= 100:   # số lớn nguyên (vd thời gian 0) -> gọn
        return f"{n:.0f}"
    return f"{n:.{nd}f}"


def _find(results_dir, filename):
    """Các file khớp, ĐÃ loại đường dẫn chứa token trong IGNORE, sắp theo mtime TĂNG dần
    (để khi gộp 'ghi sau đè trước' thì bản MỚI NHẤT thắng)."""
    hits = glob.glob(os.path.join(results_dir, "**", filename), recursive=True)
    kept = [p for p in hits
            if not any(tok and tok in p.replace("\\", "/").lower() for tok in IGNORE)]
    return sorted(kept, key=lambda p: os.path.getmtime(p))


def _md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


# ---------------- Bảng 2: ASR injection ----------------

def collect_injection(results_dir):
    """Gom mọi table2.csv theo profile. Trả về {profile: [row_dict, ...]} (mỗi lần chạy 1 dict)."""
    by_prof = defaultdict(list)
    for p in _find(results_dir, "table2.csv"):
        for d in _read_dicts(p):
            prof = (d.get("Cấu hình") or "").strip()
            if prof in PROFILES:
                by_prof[prof].append((p, d))
    return by_prof


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def build_table2(by_prof):
    cols = ["ASR", "ASR hạ mức", "ASR đổi action", "ASR (cách cũ)"]
    rows = []
    for prof in PROFILES:
        runs = by_prof.get(prof, [])
        if not runs:
            rows.append([prof, 0, "— (chưa đo)", "", "", ""])
            continue
        asr_vals = [_num(d.get("ASR")) for _, d in runs]
        asr_vals = [v for v in asr_vals if v is not None]
        mean_asr = _mean(asr_vals)
        rng = ""
        if asr_vals:
            lo, hi = min(asr_vals), max(asr_vals)
            rng = f"{lo:.3f}–{hi:.3f}" if lo != hi else f"{lo:.3f}"
        agg = {c: _mean([_num(d.get(c)) for _, d in runs]) for c in cols}
        rows.append([
            prof, len(runs),
            f"{mean_asr:.3f}" if mean_asr is not None else "—",
            rng,
            _fmt(agg["ASR hạ mức"]),
            _fmt(agg["ASR đổi action"]),
            _fmt(agg["ASR (cách cũ)"]),
        ])
    headers = ["Cấu hình", "Số lần chạy", "ASR (TB)", "ASR (dải)",
               "ASR hạ mức", "ASR đổi action", "ASR (cách cũ)"]
    return _md_table(headers, rows)


def build_table2b(results_dir):
    """ASR theo trường tải — gom table2b.csv, trung bình theo profile (cột 'ASR_<prof>')."""
    field_prof = defaultdict(lambda: defaultdict(list))   # field -> prof -> [asr]
    fields_order = []
    for p in _find(results_dir, "table2b.csv"):
        for d in _read_dicts(p):
            field = (d.get("Field") or "").strip()
            if not field:
                continue
            if field not in fields_order:
                fields_order.append(field)
            for k, v in d.items():
                if k and k.startswith("ASR_"):
                    prof = k[4:]
                    if prof in PROFILES:
                        val = _num(v)
                        if val is not None:
                            field_prof[field][prof].append(val)
    if not field_prof:
        return None
    present = [p for p in PROFILES if any(p in field_prof[f] for f in field_prof)]
    headers = ["Trường tải"] + present
    rows = []
    for f in fields_order:
        row = [f]
        for p in present:
            vals = field_prof[f].get(p, [])
            row.append(f"{_mean(vals):.3f}" if vals else "—")
        rows.append(row)
    return _md_table(headers, rows)


# ---------------- Bảng 1 + 4: triage (table4) ----------------

def collect_table4(results_dir, filename, idx_cols):
    """Gom mọi file 'filename'. idx_cols = số cột khoá đầu (1 cho table4, 2 cho by_group).
    File duyệt theo mtime tăng → bản MỚI NHẤT ghi đè bản cũ cho mỗi (key, cột).
    Trả về (data, prov): data[key]={who:val}; prov[who]=đường dẫn file cấp giá trị đó."""
    data = defaultdict(dict)
    prov = {}
    for p in _find(results_dir, filename):
        rows = _read_csv(p)
        if not rows:
            continue
        header = rows[0]
        colmap = {}
        for j, h in enumerate(header[idx_cols:], start=idx_cols):
            hs = (h or "").strip()
            if hs in PROFILES:
                colmap[j] = hs
            elif hs == "splunk_copy":
                colmap[j] = "splunk_copy"
            # bỏ qua cột 'Chênh lệch ...'
        for r in rows[1:]:
            if len(r) <= idx_cols:
                continue
            key = tuple(x.strip() for x in r[:idx_cols])
            for j, who in colmap.items():
                if j < len(r) and r[j].strip() != "":
                    data[key][who] = r[j].strip()
                    prov[who] = p
    return data, prov


def macro_f1_severity(detail_path):
    """Tự tính macro-F1 mức độ (4 lớp low/medium/high/critical) từ *_detail.csv."""
    rows = _read_dicts(detail_path)
    tp = defaultdict(int); fp = defaultdict(int); fn = defaultdict(int)
    n = 0
    for r in rows:
        if (r.get("error") or "").strip():
            continue
        gt = (r.get("gt_severity") or "").strip().lower()
        pr = (r.get("pred_severity") or "").strip().lower()
        if gt not in SEVERITIES:
            continue
        n += 1
        if pr == gt:
            tp[gt] += 1
        else:
            fn[gt] += 1
            if pr in SEVERITIES:
                fp[pr] += 1
    if not n:
        return None
    f1s = []
    for c in SEVERITIES:
        prec = tp[c] / (tp[c] + fp[c]) if (tp[c] + fp[c]) else 0.0
        rec = tp[c] / (tp[c] + fn[c]) if (tp[c] + fn[c]) else 0.0
        f1s.append(2 * prec * rec / (prec + rec) if (prec + rec) else 0.0)
    return sum(f1s) / len(f1s)


def collect_macro_f1(results_dir):
    out = {}
    for p in _find(results_dir, "golden_*_detail.csv"):
        base = os.path.basename(p)
        prof = base[len("golden_"):-len("_detail.csv")]
        if prof in PROFILES or prof == "splunk_copy":
            f1 = macro_f1_severity(p)
            if f1 is not None:
                out[prof] = f1
    return out


def build_table1(results_dir):
    data, prov = collect_table4(results_dir, "table4.csv", idx_cols=1)
    f1 = collect_macro_f1(results_dir)
    who_cols = ["off", "full", "splunk_copy"]
    headers = ["Chỉ số", "off", "full", "splunk_copy", "Δ (off→full)"]
    rows = []

    # macro-F1 chèn ngay sau Accuracy mức độ
    def delta(metric_vals):
        o, fu = metric_vals.get("off"), metric_vals.get("full")
        no, nf = _num(o), _num(fu)
        if no is None or nf is None:
            return "—"
        return f"{nf - no:+.3f}"

    for m in TRIAGE_METRICS:
        vals = data.get((m,), {})
        rows.append([m, _fmt(vals.get("off")), _fmt(vals.get("full")),
                     _fmt(vals.get("splunk_copy")), delta(vals)])
        if m == "Accuracy mức độ" and f1:
            fo, ff, fs = f1.get("off"), f1.get("full"), f1.get("splunk_copy")
            d = f"{ff - fo:+.3f}" if (fo is not None and ff is not None) else "—"
            rows.append(["macro-F1 mức độ (tự tính)",
                         _fmt(fo), _fmt(ff), _fmt(fs), d])
    return _md_table(headers, rows), prov


def build_table4_group(results_dir):
    data, _ = collect_table4(results_dir, "table4_by_group.csv", idx_cols=2)
    if not data:
        return None
    headers = ["Nhóm", "Chỉ số", "off", "full", "splunk_copy"]
    rows = []
    for (group, metric), vals in data.items():
        rows.append([group, metric, _fmt(vals.get("off")),
                     _fmt(vals.get("full")), _fmt(vals.get("splunk_copy"))])
    # sắp theo nhóm rồi theo thứ tự chỉ số
    order = {m: i for i, m in enumerate(TRIAGE_METRICS)}
    rows.sort(key=lambda r: (r[0], order.get(r[1], 99)))
    return _md_table(headers, rows)


# ---------------- Bảng 3: RAG poison ----------------

def build_table3(results_dir):
    files = _find(results_dir, "table3.csv")
    if not files:
        return None
    rows = _read_csv(files[-1])   # bản mới nhất
    if not rows:
        return None
    return _md_table(rows[0], rows[1:]), files[-1]


# ---------------- Ghép báo cáo ----------------

def main():
    global IGNORE
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default="results/BAO_CAO_benchmark.md")
    ap.add_argument("--ignore", default=",".join(IGNORE),
                    help="Chuỗi con đường dẫn cần bỏ qua, phân tách bằng dấu phẩy (mặc định: trial,diag). "
                         "Để chuỗi rỗng để gom tất cả.")
    args = ap.parse_args()
    rd = args.results

    IGNORE = [t.strip().lower() for t in args.ignore.split(",") if t.strip()]

    parts = ["# Báo cáo benchmark AegisSOC",
             "",
             "_Tự sinh từ `tools/make_report.py` — gom CSV trong `%s/`._" % rd,
             ""]

    # Bảng 1
    t1, prov = build_table1(rd)
    parts += ["## Bảng 1 — Chất lượng triage (golden v2)",
              "So sánh bản `off` (đường cũ), bản `full` (đủ 4 lớp) và tham chiếu `splunk_copy` (chép luật Splunk, không AI).",
              "", t1, ""]
    if prov:
        parts += ["<sub>Nguồn cột: " +
                  "; ".join(f"`{w}` ← `{os.path.relpath(p, '.')}`" for w, p in sorted(prov.items()))
                  + "</sub>", ""]

    # Bảng 2
    by_prof = collect_injection(rd)
    parts += ["## Bảng 2 — ASR phòng vệ prompt injection",
              "ASR = tỷ lệ payload tiêm lệnh làm Agent hạ mức/đổi hành động. Thấp hơn = chống tốt hơn. Trung bình các lần chạy.",
              "", build_table2(by_prof), ""]
    t2b = build_table2b(rd)
    if t2b:
        parts += ["### Bảng 2b — ASR theo trường tải (trung bình)", "", t2b, ""]

    # Bảng 3
    t3 = build_table3(rd)
    parts += ["## Bảng 3 — Đầu độc kho RAG (cơ chế cũ vs mới)"]
    if t3:
        tbl, src = t3
        parts += ["Nguồn: `%s`." % os.path.relpath(src, "."), "", tbl, ""]
    else:
        parts += ["", "— (chưa đo — chạy `eval.eval_rag_poison`)", ""]

    # Bảng 4
    t4 = build_table4_group(rd)
    parts += ["## Bảng 4 — Triage theo nhóm (luật Splunk đúng / sai)"]
    if t4:
        parts += ["Nhóm `siem_correct=true`: luật Splunk đã đúng. Nhóm `false`: cần ngữ cảnh/AI mới xử lý đúng.",
                  "", t4, ""]
    else:
        parts += ["", "— (chưa đo)", ""]

    # Ghi chú nguồn
    found = {name: len(_find(rd, name)) for name in
             ("table2.csv", "table4.csv", "table4_by_group.csv", "table3.csv")}
    parts += ["---", "### Nguồn đã gom",
              "", _md_table(["File", "Số bản tìm thấy"],
                            [[k, v] for k, v in found.items()]),
              "",
              "> Các ô `—` là chưa có số liệu cho cấu hình đó. Chạy thêm benchmark rồi chạy lại script."]

    text = "\n".join(parts) + "\n"
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"[+] Đã ghi {args.out}")
    for k, v in found.items():
        print(f"    {k}: {v} bản")


if __name__ == "__main__":
    main()
