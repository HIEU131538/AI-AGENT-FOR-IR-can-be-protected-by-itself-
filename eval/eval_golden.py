"""eval/eval_golden.py — chạy bộ kịch bản vàng, dựng Bảng 4 (giá của phòng thủ).

Chạy:
    $env:AGENT_TOKEN = "<token>"
    python -m eval.eval_golden --scenarios golden/scenarios.json --out results
"""
import argparse
import csv
import json
import logging
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")                    # chạy headless, không cần display
import matplotlib.pyplot as plt
import numpy as np

from eval.common import call_agent, extract_prediction, SEVERITIES

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("eval_golden")


# ---------- Nạp & chấm điểm ----------

def load_scenarios(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)["scenarios"]


def score_one(gt, pred, raw):
    """Chấm 1 scenario. Trả về dict các cờ đúng/sai + số liệu phụ.

    Sửa 29/09: ca lỗi (lỗi mạng/HTTP ở raw["error"], hoặc alert cuối phân tích lỗi ở
    pred["error"]) KHÔNG được chấm đúng ở bất kỳ cột nào — trước đây ca lành tính không có
    mã ATT&CK bị chấm attack_ok=True oan vì "rỗng == rỗng".
    """
    valid = raw.get("error") is None and raw.get("data") is not None and pred.get("error") is None
    gt_ids = set(gt.get("attack_ids", []))
    pred_ids = set(pred.get("attack_ids", []))
    return {
        "severity_ok":   valid and pred["severity"] == gt["severity"],
        "attack_ok":     valid and ((len(gt_ids & pred_ids) > 0) if gt_ids else (len(pred_ids) == 0)),
        "attack_overlap": len(gt_ids & pred_ids),
        "attack_gt_size": len(gt_ids),
        "attack_pred_size": len(pred_ids),
        "action_ok":     valid and pred["action"] == gt.get("correct_action"),
        "json_ok":       valid,
    }


# ---------- Chạy 1 profile ----------

def run_profile(profile, scenarios):
    rows = []
    for sc in scenarios:
        raw = call_agent(profile, sc["alerts"])          # common.py tự /reset trước mỗi scenario
        pred = extract_prediction(raw)                   # tự xử lý cả trường hợp lỗi
        score = score_one(sc["ground_truth"], pred, raw)
        rows.append({
            "id": sc["id"], "name": sc["name"], "profile": profile,
            "elapsed": raw.get("elapsed"),
            "error": raw.get("error") or pred.get("error"),
            "gt_severity": sc["ground_truth"]["severity"],
            "gt_attack_ids": sc["ground_truth"].get("attack_ids", []),
            "gt_action": sc["ground_truth"].get("correct_action"),
            "gt_is_attack": sc["ground_truth"].get("is_attack", True),
            "pred_severity": pred["severity"],
            "pred_attack_ids": pred["attack_ids"],
            "pred_action": pred["action"],
            "pred_action_raw": pred.get("action_raw"),   # nhãn gốc của Agent trước khi quy đổi
            **score,
        })
        log.info("[%s] %s sev=%s/%s atk=%s act=%s (%.1fs)",
                 profile, sc["id"], pred["severity"], sc["ground_truth"]["severity"],
                 "OK" if score["attack_ok"] else "X",
                 "OK" if score["action_ok"] else "X",
                 raw.get("elapsed") or -1)
    return rows


# ---------- Tổng hợp Bảng 4 ----------

def summarize(rows):
    n = len(rows)
    sev_ok = sum(r["severity_ok"] for r in rows)
    atk_ok = sum(r["attack_ok"] for r in rows)
    act_ok = sum(r["action_ok"] for r in rows)
    json_ok = sum(r["json_ok"] for r in rows)

    benign = [r for r in rows if not r["gt_is_attack"]]
    fp_benign = sum(1 for r in benign
                    if r["pred_severity"] in ("high", "critical")
                    or (r["pred_action"] and r["pred_action"] != "no_action"))

    times = [r["elapsed"] for r in rows if r["elapsed"] is not None]

    cm = np.zeros((4, 4), dtype=int)
    idx = {s: i for i, s in enumerate(SEVERITIES)}
    for r in rows:
        g, p = idx.get(r["gt_severity"]), idx.get(r["pred_severity"])
        if g is not None and p is not None:
            cm[g, p] += 1

    return {
        "n": n,
        "acc_severity":      sev_ok / n if n else 0,
        "acc_attack":        atk_ok / n if n else 0,
        "acc_action":        act_ok / n if n else 0,
        "fp_benign":         fp_benign,
        "n_benign":          len(benign),
        "fp_benign_rate":    fp_benign / len(benign) if benign else 0,
        "mean_time":         statistics.mean(times) if times else 0,
        "json_error_rate":   1 - json_ok / n if n else 0,
        "cm":                cm,
    }


def plot_confusion(cm, title, out_path):
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(4)); ax.set_xticklabels(SEVERITIES, rotation=30)
    ax.set_yticks(range(4)); ax.set_yticklabels(SEVERITIES)
    ax.set_xlabel("Agent kết luận"); ax.set_ylabel("Thật")
    ax.set_title(title)
    for i in range(4):
        for j in range(4):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black")
    fig.colorbar(im); fig.tight_layout()
    fig.savefig(out_path, dpi=120); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default="golden/scenarios.json")
    ap.add_argument("--out", default="results")
    ap.add_argument("--profiles", default="off,full")
    args = ap.parse_args()

    scenarios = load_scenarios(args.scenarios)
    log.info("Nạp %d scenario", len(scenarios))
    out_dir = Path(args.out); out_dir.mkdir(parents=True, exist_ok=True)

    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    summary = {}
    for p in profiles:
        rows = run_profile(p, scenarios)
        s = summarize(rows)
        summary[p] = s

        # CSV chi tiết từng scenario
        with open(out_dir / f"golden_{p}_detail.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            for r in rows:
                w.writerow(r)

        # Confusion matrix 4x4
        plot_confusion(s["cm"], f"Confusion — profile {p}", out_dir / f"conf_{p}.png")

    # Bảng 4 tổng hợp
    metrics = [
        ("Accuracy mức độ",              "acc_severity"),
        ("Đúng mã ATT&CK",               "acc_attack"),
        ("Đề xuất đúng hành động",       "acc_action"),
        ("Báo nhầm trên ca lành tính",   "fp_benign_rate"),
        ("Thời gian xử lý TB (s)",       "mean_time"),
        ("Tỷ lệ JSON lỗi",               "json_error_rate"),
    ]
    with open(out_dir / "table4.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Chỉ số"] + profiles + ["Chênh lệch"])
        for label, key in metrics:
            vals = [summary[p][key] for p in profiles]
            diff = (vals[-1] - vals[0]) if len(vals) == 2 else ""
            w.writerow([label] + vals + [diff])
    log.info("Đã ghi %s/table4.csv", out_dir)


if __name__ == "__main__":
    main()