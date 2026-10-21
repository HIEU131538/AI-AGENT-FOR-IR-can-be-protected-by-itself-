"""tools/attack_layers.py — B10: xuất lớp MITRE ATT&CK Navigator + hình bản đồ phủ cho báo cáo.

1) Bản đồ PHỦ của bộ luật (rules/base/base_rules.csv → mã ATT&CK của từng luật):
       python tools/attack_layers.py coverage
   → results/attack/coverage_layer.json   (mở bằng https://mitre-attack.github.io/attack-navigator/ → Open Existing Layer)
   → docs/figures/attack_coverage.png     (hình cho Chương 2: cột = tactic theo thứ tự ma trận, ô = kỹ thuật được phủ)

2) Lớp cho TỪNG SỰ CỐ đang có trên Agent (tô các kỹ thuật đã quan sát + thứ tự xuất hiện):
       python tools/attack_layers.py incidents --api http://127.0.0.1:8000
   → results/attack/incident_<id>.json

Chỉ đọc dữ liệu ATT&CK tất định (core/attack_kb.py). Không gọi LLM.
"""
import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from core import attack_kb as K  # noqa: E402

OUT = REPO / "results" / "attack"
FIG = REPO / "docs" / "figures"


def _layer(name: str, description: str, techniques: list) -> dict:
    return {
        "name": name, "description": description, "domain": "enterprise-attack",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "sorting": 0, "hideDisabled": False,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "gradient": {"colors": ["#c6dbef", "#2171b5"], "minValue": 1, "maxValue": 3},
        "techniques": techniques,
        "legendItems": [], "metadata": [], "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f", "selectTechniquesAcrossTactics": True,
    }


def load_rules():
    rows = list(csv.DictReader(open(REPO / "rules" / "base" / "base_rules.csv", encoding="utf-8-sig")))
    return [(r["base_id"], r["title"], r["attack_ids"].split()) for r in rows if r.get("attack_ids")]


def coverage():
    rules = load_rules()
    by_tech = defaultdict(list)
    for bid, _title, ids in rules:
        for t in ids:
            by_tech[t.upper()].append(bid)
    techs = []
    for t, bids in sorted(by_tech.items()):
        techs.append({"techniqueID": t, "score": len(bids), "enabled": True,
                      "comment": "Luật: " + ", ".join(bids)})
    OUT.mkdir(parents=True, exist_ok=True)
    layer = _layer("AegisSOC — phủ ATT&CK của bộ luật nền",
                   f"{len(rules)} luật Sigma/Splunk · {len(by_tech)} kỹ thuật", techs)
    (OUT / "coverage_layer.json").write_text(json.dumps(layer, ensure_ascii=False, indent=1), encoding="utf-8")

    # bảng tactic → kỹ thuật (một kỹ thuật thuộc nhiều tactic thì hiện ở mọi tactic của nó, như ATT&CK Navigator)
    col = defaultdict(list)
    for t, bids in by_tech.items():
        for tac in K.tactics_of(t) or ["?"]:
            col[tac].append((t, bids))
    tactics = [x["short"] for x in K._kb()["tactics"]]
    covered = [tc for tc in tactics if col.get(tc)]
    print(f"[+] {len(rules)} luật · {len(by_tech)} kỹ thuật · phủ {len(covered)}/{len(tactics)} tactic Enterprise")
    for tc in tactics:
        items = sorted(col.get(tc, []))
        print(f"  {K.tactic_id(tc) or '':7} {K.tactic_name(tc):22} {len(items):2}  " + " ".join(t for t, _ in items))
    _figure(tactics, col)
    print(f"[+] {OUT / 'coverage_layer.json'}\n[+] {FIG / 'attack_coverage.png'}")


def _figure(tactics, col):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.patches import Rectangle
    except ImportError:
        print("[i] Không có matplotlib — bỏ qua hình.")
        return
    FIG.mkdir(parents=True, exist_ok=True)
    rows = max(len(col.get(tc, [])) for tc in tactics) or 1
    w, h = 1.55, 0.62
    fig, ax = plt.subplots(figsize=(len(tactics) * w * 0.82, (rows + 1.6) * h * 0.82))
    shades = {1: "#c6dbef", 2: "#6baed6", 3: "#2171b5"}
    for i, tc in enumerate(tactics):
        ax.add_patch(Rectangle((i * w, rows * h), w - 0.05, h * 1.25, color="#205b8f"))
        ax.text(i * w + w / 2, rows * h + h * 0.62, f"{K.tactic_name(tc)}\n{K.tactic_id(tc) or ''}",
                ha="center", va="center", fontsize=6.2, color="white", weight="bold")
        for j, (t, bids) in enumerate(sorted(col.get(tc, []))):
            y = (rows - 1 - j) * h
            c = shades.get(min(len(bids), 3))
            ax.add_patch(Rectangle((i * w, y), w - 0.05, h - 0.05, color=c))
            name = (K.technique(t) or {}).get("name", "")
            name = name if len(name) <= 22 else name[:21] + "…"
            ax.text(i * w + w / 2, y + h / 2, f"{t}\n{name}", ha="center", va="center", fontsize=5.2,
                    color="white" if len(bids) >= 3 else "#08306b")
        if not col.get(tc):
            ax.add_patch(Rectangle((i * w, (rows - 1) * h), w - 0.05, h - 0.05, color="#f0f0f0"))
            ax.text(i * w + w / 2, (rows - 1) * h + h / 2, "—", ha="center", va="center", fontsize=7, color="#999")
    ax.set_xlim(0, len(tactics) * w)
    ax.set_ylim(0, (rows + 1.3) * h)
    ax.axis("off")
    ax.set_title("Phủ MITRE ATT&CK của bộ luật nền AegisSOC (màu đậm = nhiều luật phủ cùng kỹ thuật)", fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG / "attack_coverage.png", dpi=220)
    plt.close(fig)


def incidents(api: str):
    import requests
    data = requests.get(api.rstrip("/") + "/recent", timeout=10).json().get("results", [])
    groups = defaultdict(list)
    for e in data:
        groups[e.get("incident_id") or "?"].append(e)
    OUT.mkdir(parents=True, exist_ok=True)
    for inc, evs in groups.items():
        evs.sort(key=lambda x: x.get("received_at", ""))
        techs, order = {}, 0
        for x in evs:
            rule = ((x.get("ticket") or {}).get("trusted") or {}).get("rule") or {}
            for t in rule.get("attack_ids") or x.get("mitre_techniques") or []:
                order += 1
                d = techs.setdefault(t, {"techniqueID": t, "score": order, "enabled": True, "comment": ""})
                d["comment"] = (d["comment"] + f" #{order} {rule.get('name', '')}").strip()
        ch = (evs[-1].get("attack_chain") or {})
        desc = (f"Sự cố {inc}: {len(evs)} alert · chuỗi tactic: {' → '.join(ch.get('tactic_names') or [])}"
                + (f" · nâng mức {ch['escalation']['rule']}" if ch.get("escalation") else ""))
        layer = _layer(f"AegisSOC — sự cố {inc}", desc, list(techs.values()))
        layer["gradient"] = {"colors": ["#fee0d2", "#de2d26"], "minValue": 1, "maxValue": max(order, 2)}
        f = OUT / f"incident_{inc}.json"
        f.write_text(json.dumps(layer, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"[+] {f} · {desc}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("coverage")
    p = sub.add_parser("incidents")
    p.add_argument("--api", default="http://127.0.0.1:8000")
    a = ap.parse_args()
    coverage() if a.cmd == "coverage" else incidents(a.api)


if __name__ == "__main__":
    main()
