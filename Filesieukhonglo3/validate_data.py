"""validate_data.py — tự kiểm dữ liệu data/processed/ của AegisSOC theo checklist mục 7.2.
 
Chạy:  python validate_data.py
Đặt file này CÙNG THƯ MỤC với prepare_data.py (thư mục gốc dự án).
 
Script duyệt toàn bộ dữ liệu bằng pandas (không giới hạn số dòng), in ra
PASS/FAIL cho từng mục checklist, và tổng kết cuối cùng.
"""
 
import json
import sys
from pathlib import Path
 
import numpy as np
import pandas as pd
 
BASE_DIR = Path(__file__).resolve().parent
OUT = BASE_DIR / "data" / "processed"
 
SPLITS = ["train", "calib", "test"]
VARIANTS = ["full", "subset_flow"]
FORBIDDEN_COLS = {"id", "attack_cat"}
 
results = []  # (tên_check, pass/fail, chi_tiết)
 
 
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    mark = "✅ PASS" if ok else "❌ FAIL"
    print(f"{mark} — {name}" + (f"\n        → {detail}" if detail else ""))
 
 
def load_csv(path):
    if not path.exists():
        return None
    return pd.read_csv(path)
 
 
def main():
    print("=" * 70)
    print("TỰ KIỂM DỮ LIỆU — data/processed/")
    print("=" * 70)
 
    # --- 0. File/thư mục cần có ---
    required_files = [
        OUT / "encoders.json",
        OUT / "service_mapping.json",
        OUT / "feature_list_full.txt",
        OUT / "feature_list_subset_flow.txt",
        OUT / "data_report.json",
        BASE_DIR / "data_report.md",
    ]
    for f in required_files:
        check(f"File tồn tại: {f.relative_to(BASE_DIR)}", f.exists())
 
    for variant in VARIANTS:
        for split in SPLITS:
            check(f"File tồn tại: data/processed/{variant}/{split}.csv",
                  (OUT / variant / f"{split}.csv").exists())
 
    # Nếu thiếu file cốt lõi thì dừng sớm, tránh lỗi dây chuyền khó đọc
    core_missing = any(
        not (OUT / v / f"{s}.csv").exists() for v in VARIANTS for s in SPLITS
    )
    if core_missing:
        print("\n⚠️  Thiếu file CSV cốt lõi — dừng kiểm tra các mục còn lại.")
        summarize()
        return
 
    # --- Load toàn bộ CSV ---
    data = {v: {s: load_csv(OUT / v / f"{s}.csv") for s in SPLITS} for v in VARIANTS}
 
    # --- 1. Không có cột id, attack_cat ---
    for variant in VARIANTS:
        for split in SPLITS:
            df = data[variant][split]
            bad_cols = FORBIDDEN_COLS & set(df.columns)
            check(f"Không có cột id/attack_cat — {variant}/{split}.csv",
                  len(bad_cols) == 0,
                  f"Thấy cột cấm: {bad_cols}" if bad_cols else "")
 
    # --- 2. Cột cuối là label, chỉ có giá trị 0/1 ---
    for variant in VARIANTS:
        for split in SPLITS:
            df = data[variant][split]
            last_col_ok = df.columns[-1] == "label"
            check(f"Cột cuối là 'label' — {variant}/{split}.csv", last_col_ok,
                  f"Cột cuối thực tế: {df.columns[-1]}" if not last_col_ok else "")
            if "label" in df.columns:
                vals = set(df["label"].unique().tolist())
                only_01 = vals <= {0, 1}
                check(f"'label' chỉ có giá trị 0/1 — {variant}/{split}.csv", only_01,
                      f"Giá trị lạ: {vals - {0, 1}}" if not only_01 else "")
 
    # --- 3. Không còn ô rỗng, không còn inf ---
    for variant in VARIANTS:
        for split in SPLITS:
            df = data[variant][split]
            n_na = int(df.isna().sum().sum())
            num_df = df.select_dtypes(include="number")
            n_inf = int(np.isinf(num_df.to_numpy(dtype="float64", na_value=0)).sum())
            check(f"Không có ô rỗng (NaN) — {variant}/{split}.csv", n_na == 0,
                  f"{n_na} ô rỗng" if n_na else "")
            check(f"Không có giá trị inf — {variant}/{split}.csv", n_inf == 0,
                  f"{n_inf} ô inf" if n_inf else "")
 
    # --- 4. proto/service(/state) đã là số nguyên ---
    for variant in VARIANTS:
        cols_to_check = ["proto", "service"] + (["state"] if variant == "full" else [])
        for split in SPLITS:
            df = data[variant][split]
            for c in cols_to_check:
                if c not in df.columns:
                    check(f"Cột '{c}' tồn tại — {variant}/{split}.csv", False, "Thiếu cột")
                    continue
                is_int = pd.api.types.is_integer_dtype(df[c])
                check(f"Cột '{c}' là số nguyên — {variant}/{split}.csv", is_int,
                      f"dtype thực tế: {df[c].dtype}" if not is_int else "")
 
    # --- 5. Số dòng khớp data_report.json ---
    report_path = OUT / "data_report.json"
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        splits_report = report.get("splits", {})
        for split in SPLITS:
            expected = splits_report.get(split, {}).get("rows")
            actual = len(data["full"][split]) if data["full"][split] is not None else None
            ok = expected is not None and expected == actual
            check(f"Số dòng khớp data_report.json — {split}", ok,
                  f"Báo cáo ghi {expected}, thực tế {actual}" if not ok else "")
 
    # --- 6. Không còn dòng trùng hoàn toàn trong full/train.csv ---
    dup = data["full"]["train"].duplicated().sum()
    check("Không còn dòng trùng hoàn toàn trong full/train.csv", dup == 0,
          f"{dup} dòng trùng còn sót" if dup else "")
 
    # --- 7. full và subset_flow cùng số dòng tương ứng mỗi split ---
    for split in SPLITS:
        n_full = len(data["full"][split])
        n_sub = len(data["subset_flow"][split])
        check(f"full và subset_flow cùng số dòng — {split}", n_full == n_sub,
              f"full={n_full}, subset_flow={n_sub}" if n_full != n_sub else "")
 
    summarize()
 
 
def summarize():
    total = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    failed = total - passed
    print("\n" + "=" * 70)
    print(f"TỔNG KẾT: {passed}/{total} mục PASS — {failed} mục FAIL")
    print("=" * 70)
    if failed:
        print("\nCác mục FAIL cần xử lý lại:")
        for name, ok, detail in results:
            if not ok:
                print(f"  - {name}" + (f" ({detail})" if detail else ""))
        sys.exit(1)
    else:
        print("Toàn bộ checklist đã đạt. Dữ liệu sẵn sàng bàn giao.")
 
 
if __name__ == "__main__":
    main()