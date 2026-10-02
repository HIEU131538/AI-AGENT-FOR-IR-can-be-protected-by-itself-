"""eval/eval_golden.py — chạy bộ kịch bản vàng, dựng Bảng 4.

Sửa 01/10 (theo Hiếu):
  - Cột "Chênh lệch" CHỈ tính giữa 2 profile Agent (off → full), không tính
    lẫn cột splunk_copy. Trước đây lấy cột cuối trừ cột đầu mà cột cuối là
    splunk_copy → hiệu số vô nghĩa.

Giữ từ 30/09:
  - 3 cột mới vào detail CSV: pred_decision, pred_reasoning, pred_agent_mode.
  - Profile ảo "splunk_copy": tham chiếu chép luật Splunk, KHÔNG gọi Agent.
  - Chỉ số "Tỷ lệ chuyển người duyệt".
  - File table4_by_group.csv tách nhóm theo siem_correct.
  - Preflight trước khi đo.

Chạy:
    $env:AGENT_TOKEN = "<token>"
    python -m eval.eval_golden --scenarios golden/scenarios_v2.json --out results
"""
import argparse
import csv
import json
import logging
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from eval.common import call_agent, extract_prediction, preflight, SEVERITIES

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("eval_golden")

# Quy ước chuyển mức → hành động (dùng cho splunk_copy)
LEVEL_TO_ACTION = {
    "low": "no_action",
    "medium": "review",
    "high": "block",
    "critical": "block",
    "informational": "no_action",
}


# ---------- Nạp & chấm điểm ----------

def load_scenarios(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)["scenarios"]


def score_one(gt, pred, raw):
    """Chấm 1 scenario. Ca lỗi KHÔNG được chấm đúng ở bất kỳ cột nào."""
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


# ---------- splunk_copy — tham chiếu chép luật Splunk ----------

def build_splunk_copy(scenario):
    """Dựng 'kết luận' giả từ alert cuối — không gọi Agent."""
    alerts = scenario.get("alerts") or []
    if not alerts:
        return None, {"error": "no alerts", "data": None}

    last = alerts[-1]
    level = (last.get("rule_level") or "").lower()
    if level == "informational":
        level = "low"
    if level not in LEVEL_TO_ACTION:
        level = "low"

    action = LEVEL_TO_ACTION[level]
    pred = {
        "severity": level,
        "attack_ids": list(last.get("attack_ids") or []),
        "action": action,
        "action_raw": action,
        "agent_mode": None, "target_ip": None, "n_results": 1, "error": None,
    }
    raw = {"data": {"results": [{"status": "analyzed"}]}, "error": None}
    return pred, raw


def run_splunk_copy(scenarios):
    rows = []
    for sc in scenarios:
        pred, raw = build_splunk_copy(sc)
        if pred is None:
            score = {k: False for k in ["severity_ok", "attack_ok", "action_ok", "json_ok"]}
            score.update({"attack_overlap": 0, "attack_gt_size": 0, "attack_pred_size": 0})
            rows.append({
                "id": sc["id"], "name": sc["name"], "profile": "splunk_copy",
                "elapsed": 0.0, "error": "no alerts",
                "gt_severity": sc["ground_truth"]["severity"],
                "gt_attack_ids": sc["ground_truth"].get("attack_ids", []),
                "gt_action": sc["ground_truth"].get("correct_action"),
                "gt_is_attack": sc["ground_truth"].get("is_attack", True),
                "pred_severity": None, "pred_attack_ids": [],
                "pred_action": None, "pred_action_raw": None,
                "pred_decision": None, "pred_reasoning": None, "pred_agent_mode": None,
                **score,
            })
            continue

        score = score_one(sc["ground_truth"], pred, raw)
        rows.append({
            "id": sc["id"], "name": sc["name"], "profile": "splunk_copy",
            "elapsed": 0.0, "error": None,
            "gt_severity": sc["ground_truth"]["severity"],
            "gt_attack_ids": sc["ground_truth"].get("attack_ids", []),
            "gt_action": sc["ground_truth"].get("correct_action"),
            "gt_is_attack": sc["ground_truth"].get("is_attack", True),
            "pred_severity": pred["severity"],
            "pred_attack_ids": pred["attack_ids"],
            "pred_action": pred["action"],
            "pred_action_raw": pred["action_raw"],
            "pred_decision": None, "pred_reasoning": None, "pred_agent_mode": None,
            **score,
        })
    return rows


# ---------- Chạy 1 profile agent ----------

def _get_last_result(raw):
    data = raw.get("data") if isinstance(raw, dict) else None
    if not isinstance(data, dict):
        return {}
    results = data.get("results")
    if not isinstance(results, list) or not results:
        return {}
    last = results[-1]
    return last if isinstance(last, dict) else {}


def run_profile(profile, scenarios):
    rows = []
    for sc in scenarios:
        raw = call_agent(profile, sc["alerts"])
        pred = extract_prediction(raw)
        last = _get_last_result(raw)

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
            "pred_action_raw": pred.get("action_raw"),
            "pred_decision":    last.get("decision"),
            "pred_reasoning":   last.get("reasoning"),
            "pred_agent_mode":  last.get("agent_mode"),
            **score,
        })
        log.info("[%s] %s sev=%s/%s dec=%s mode=%s (%.1fs)",
                 profile, sc["id"], pred["severity"], sc["ground_truth"]["severity"],
                 last.get("decision"), last.get("agent_mode"),
                 raw.get("elapsed") or -1)
    return rows


# ---------- Tổng hợp ----------

def summarize(rows):
    n = len(rows)
    if n == 0:
        return {"n": 0, "acc_severity": 0, "acc_attack": 0, "acc_action": 0,
                "fp_benign": 0, "n_benign": 0, "fp_benign_rate": 0,
                "mean_time": 0, "json_error_rate": 0, "human_review_rate": 0,
                "cm": np.zeros((4, 4), dtype=int)}

    sev_ok = sum(r["severity_ok"] for r in rows)
    atk_ok = sum(r["attack_ok"] for r in rows)
    act_ok = sum(r["action_ok"] for r in rows)
    json_ok = sum(r["json_ok"] for r in rows)

    benign = [r for r in rows if not r["gt_is_attack"]]
    fp_benign = sum(1 for r in benign
                    if r["pred_severity"] in ("high", "critical")
                    or (r["pred_action"] and r["pred_action"] != "no_action"))

    valid_rows = [r for r in rows if r["json_ok"]]
    n_valid = len(valid_rows)
    n_review = sum(1 for r in valid_rows
                   if (r.get("pred_agent_mode") or "").upper() == "HUMAN_REVIEW_REQUIRED")

    times = [r["elapsed"] for r in rows if r["elapsed"] is not None and r["elapsed"] > 0]

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
        "human_review_rate": n_review / n_valid if n_valid else 0,
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


# ---------- Ghi CSV ----------

METRICS = [
    ("Accuracy mức độ",              "acc_severity"),
    ("Đúng mã ATT&CK",               "acc_attack"),
    ("Đề xuất đúng hành động",       "acc_action"),
    ("Báo nhầm trên ca lành tính",   "fp_benign_rate"),
    ("Thời gian xử lý TB (s)",       "mean_time"),
    ("Tỷ lệ JSON lỗi",               "json_error_rate"),
    ("Tỷ lệ chuyển người duyệt",     "human_review_rate"),
]


def write_table4(path, profiles, summary):
    """Cột "Chênh lệch" CHỈ tính giữa 2 profile Agent (off → full).
    splunk_copy là cột tham chiếu, không tính hiệu số.
    """
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Chỉ số"] + profiles + ["splunk_copy", "Chênh lệch (off→full)"])
        for label, key in METRICS:
            vals_agent = [summary[p][key] for p in profiles]
            v_sc = summary.get("splunk_copy", {}).get(key, "")
            diff = (vals_agent[-1] - vals_agent[0]) if len(vals_agent) >= 2 else ""
            w.writerow([label] + vals_agent + [v_sc, diff])


def write_detail_csv(path, rows):
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_table4_by_group(path, profiles, all_rows_by_profile, scenarios):
    """Tách theo ground_truth.siem_correct nếu có (v2 có, v1 không)."""
    siem_map = {}
    for sc in scenarios:
        v = sc["ground_truth"].get("siem_correct")
        if v is not None:
            siem_map[sc["id"]] = v

    if not siem_map:
        log.info("Không có siem_correct trong scenarios — bỏ qua table4_by_group.csv")
        return

    groups = {"true": [], "false": []}
    for p, rows in all_rows_by_profile.items():
        for r in rows:
            sc_correct = siem_map.get(r["id"])
            if sc_correct is None:
                continue
            key = "true" if sc_correct else "false"
            groups[key].append(r)

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Nhóm", "Chỉ số"] + profiles + ["Chênh lệch (off→full)"])
        for gk in ("true", "false"):
            rows_g = groups[gk]
            if not rows_g:
                continue
            by_p = {p: [r for r in rows_g if r["profile"] == p] for p in profiles}
            for label, key in METRICS:
                vals = [summarize(by_p[p]).get(key, 0) if by_p[p] else 0 for p in profiles]
                # 02/10: giống table4 — Chênh lệch chỉ tính giữa các profile Agent, bỏ cột splunk_copy
                agent_vals = [v for p, v in zip(profiles, vals) if p != "splunk_copy"]
                diff = (agent_vals[-1] - agent_vals[0]) if len(agent_vals) >= 2 else ""
                w.writerow([f"siem_correct={gk}", label] + vals + [diff])


# ---------- Main ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default="golden/scenarios_v2.json")
    ap.add_argument("--out", default="results")
    ap.add_argument("--profiles", default="off,full")
    ap.add_argument("--skip-preflight", action="store_true")
    args = ap.parse_args()

    scenarios = load_scenarios(args.scenarios)
    log.info("Nạp %d scenario", len(scenarios))
    out_dir = Path(args.out); out_dir.mkdir(parents=True, exist_ok=True)

    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]

    if not args.skip_preflight:
        for p in profiles:
            problems = preflight(p, sample_alerts=scenarios[0]["alerts"][:1])
            if problems:
                for msg in problems:
                    log.error("[preflight %s] %s", p, msg)
                raise SystemExit(f"Dừng: bản `{p}` chưa sẵn sàng.")
            log.info("[preflight %s] OK", p)

    all_rows_by_profile = {}
    summary = {}

    for p in profiles:
        rows = run_profile(p, scenarios)
        all_rows_by_profile[p] = rows
        summary[p] = summarize(rows)
        write_detail_csv(out_dir / f"golden_{p}_detail.csv", rows)
        plot_confusion(summary[p]["cm"], f"Confusion — profile {p}", out_dir / f"conf_{p}.png")

    # Profile ảo splunk_copy — tham chiếu, không tính Chênh lệch
    rows_sc = run_splunk_copy(scenarios)
    all_rows_by_profile["splunk_copy"] = rows_sc
    summary["splunk_copy"] = summarize(rows_sc)
    write_detail_csv(out_dir / "golden_splunk_copy_detail.csv", rows_sc)
    plot_confusion(summary["splunk_copy"]["cm"], "Confusion — splunk_copy",
                   out_dir / "conf_splunk_copy.png")

    # Bảng 4 — cột Chênh lệch chỉ tính giữa các profile Agent
    write_table4(out_dir / "table4.csv", profiles, summary)
    log.info("Đã ghi %s/table4.csv", out_dir)

    # Bảng 4 theo nhóm siem_correct
    profiles_out = profiles + ["splunk_copy"]
    write_table4_by_group(out_dir / "table4_by_group.csv", profiles_out,
                          all_rows_by_profile, scenarios)
    log.info("Đã ghi xong")


if __name__ == "__main__":
    main()