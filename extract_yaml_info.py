"""extract_yaml_info.py — trích thông tin cần thiết từ 28 file YAML của base rules.

Chạy:  python extract_yaml_info.py
"""
import csv
import json
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Cần cài PyYAML: pip install pyyaml")
    raise SystemExit(1)

ROOT = Path(__file__).parent
RULES_DIR = ROOT / "rules" / "base"
RULES_CSV = RULES_DIR / "base_rules.csv"
SIGMAHQ_DIR = RULES_DIR / "sigmahq"
CUSTOM_DIR = RULES_DIR / "custom"
OUT = RULES_DIR / "_extracted.json"


def find_yaml(base_id, file_col, sigmahq_path, source):
    """Tìm file YAML — chỉ dùng cột `file` và `sigmahq_path` từ CSV.

    Cột `file` trong CSV là nguồn chính xác nhất — không cần đoán.
    """
    candidates = []

    if source == "sigmahq":
        for raw in (file_col, sigmahq_path):
            if not raw:
                continue
            basename = raw.split("/")[-1]
            # Thử 3 kiểu: giữ nguyên, bỏ prefix, chỉ basename
            candidates.append(SIGMAHQ_DIR / raw)
            candidates.append(SIGMAHQ_DIR / basename)
            if raw.startswith("sigmahq/"):
                candidates.append(SIGMAHQ_DIR / raw[len("sigmahq/"):])

    if source == "custom":
        for raw in (file_col, sigmahq_path):
            if not raw:
                continue
            basename = raw.split("/")[-1]
            candidates.append(CUSTOM_DIR / raw)
            candidates.append(CUSTOM_DIR / basename)
            if raw.startswith("custom/"):
                candidates.append(CUSTOM_DIR / raw[len("custom/"):])

    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return None


def simplify_detection(detection, max_list=10, max_str=300):
    if not isinstance(detection, dict):
        return {}
    out = {}
    for k, v in detection.items():
        if k == "condition":
            out[k] = str(v)
        elif isinstance(v, dict):
            out[k] = simplify_detection(v)
        elif isinstance(v, list):
            out[k] = [str(x)[:200] for x in v[:max_list]]
        else:
            out[k] = str(v)[:max_str]
    return out


def main():
    rows = list(csv.DictReader(RULES_CSV.open(encoding="utf-8-sig")))
    print(f"Đọc {len(rows)} dòng từ {RULES_CSV}")

    out = []
    missing = []
    for r in rows:
        base_id = r["base_id"]
        source = r["source"]
        file_col = (r.get("file") or "").strip()
        sigmahq_path = (r.get("sigmahq_path") or "").strip()
        yaml_path = find_yaml(base_id, file_col, sigmahq_path, source)

        item = {
            "base_id": base_id,
            "source": source,
            "group": r["group"],
            "title": r["title"],
            "level": r["level"],
            "attack_ids": r["attack_ids"].split() if r["attack_ids"] else [],
            "logsource": r["logsource"],
            "falsepositives": r["falsepositives"],
            "lab_use": r["lab_use"],
            "yaml_file": str(yaml_path.relative_to(ROOT)) if yaml_path else None,
            "detection": None,
        }

        if yaml_path and yaml_path.exists():
            try:
                doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
                item["detection"] = simplify_detection(doc.get("detection", {}))
                item["author"] = doc.get("author")
                item["description"] = (doc.get("description") or "")[:500]
            except Exception as e:
                item["yaml_error"] = str(e)
        else:
            missing.append(base_id)

        out.append(item)

    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Đã ghi {len(out)} rule vào {OUT}")

    # Kiểm C01, C02, C03 phải khác nhau
    custom_items = [x for x in out if x["source"] == "custom"]
    print(f"\nKiểm {len(custom_items)} rule custom:")
    for x in custom_items:
        print(f"  {x['base_id']}: yaml={x['yaml_file']}")
        if x.get("detection"):
            print(f"       condition: {x['detection'].get('condition', '?')}")

    if missing:
        print(f"\nCẢNH BÁO: {len(missing)} rule không tìm thấy YAML: {missing}")


if __name__ == "__main__":
    main()