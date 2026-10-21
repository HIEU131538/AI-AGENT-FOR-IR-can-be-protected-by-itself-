"""prefilter/eval_prefilter.py — Bảng 1: số ca BỎ LỌT của prefilter trên tập test UNSW-NB15.

So 4 cấu hình quyết định DROP (không đưa lên Agent):
  1. no_prefilter            : không lọc — mọi alert lên Agent (bỏ lọt 0, nhưng 0% tiết kiệm).
  2. rf_0.5                  : DROP nếu p < 0.50 (ngưỡng "ngây thơ").
  3. rf_calibrated_t         : DROP nếu p < t (ngưỡng theo chi phí 10:1, t≈0.09).
  4. rf_calibrated_band      : DROP nếu p < band_lo; trong dải → PASS_UNCERTAIN (vẫn lên Agent).

Cho mỗi cấu hình, với "tấn công" là lớp dương (label=1), tính trên tập test:
  - Bỏ lọt (FN)  : số ca tấn công bị DROP (không bao giờ tới Agent) — chỉ số QUAN TRỌNG NHẤT cho SOC.
  - FNR          : FN / tổng ca tấn công.
  - Recall tấn công = 1 - FNR.
  - % alert lọc bớt : tỉ lệ alert bị DROP trên toàn test (tiết kiệm lượt LLM).
  - Lên Agent    : số alert được chuyển lên Agent (trong đó 'uncertain' = nằm trong dải).

Chạy: python -m prefilter.eval_prefilter --data <processed/> --out results   (mặc định cả full và subset_flow)
"""
import argparse
import csv
from pathlib import Path

import numpy as np
import pandas as pd

from prefilter.model import _load

LABEL = "label"


def _metrics(p, y, drop_below, band_lo=None):
    """DROP nếu p < drop_below. (band_lo chỉ để đếm 'uncertain' khi dùng dải.)"""
    dropped = p < drop_below
    n = len(y)
    n_att = int((y == 1).sum())
    fn = int(((y == 1) & dropped).sum())                 # tấn công bị bỏ lọt
    tn = int(((y == 0) & dropped).sum())                 # lành tính bị lọc đúng
    passed = ~dropped
    uncertain = int((passed & (p < (band_lo if band_lo is not None else -1))).sum())
    return {
        "bỏ lọt (FN)": fn,
        "FNR": round(fn / n_att, 4) if n_att else 0.0,
        "recall tấn công": round(1 - fn / n_att, 4) if n_att else 0.0,
        "lành tính lọc đúng (TN)": tn,
        "% alert lọc bớt": round(int(dropped.sum()) / n, 4) if n else 0.0,
        "lên Agent": int(passed.sum()),
    }


_LABEL_OF = {"full": "full (42 cột — so bài báo)", "subset_flow": "subset_flow (12 cột — chạy thật)"}


def _eval_variant(data, variant):
    mdl = _load(variant)
    if mdl is None:
        raise SystemExit(f"Chưa có model '{variant}'. Chạy prefilter.train_rf --variant {variant} trước.")
    te = pd.read_csv(Path(data) / variant / "test.csv")
    X, y = te[mdl["features"]].values, te[LABEL].values.astype(int)
    p = mdl["cal"].predict_proba(X)[:, 1]
    t, lo = mdl["t"], mdl["lo"]
    print(f"[{variant}] test n={len(y)}, tấn công={int((y==1).sum())}, lành tính={int((y==0).sum())}")
    return [
        ("1. Không prefilter", _metrics(p, y, drop_below=0.0)),
        ("2. RF ngưỡng 0.5", _metrics(p, y, drop_below=0.5)),
        (f"3. RF hiệu chuẩn, ngưỡng t={t}", _metrics(p, y, drop_below=t)),
        (f"4. RF + dải bất định (lo={lo})", _metrics(p, y, drop_below=lo, band_lo=mdl["hi"])),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--variants", default="full,subset_flow", help="danh sách bản, cách nhau dấu phẩy")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    fpath = out / "table1_prefilter.csv"
    cols = None
    with open(fpath, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        for v in [x.strip() for x in args.variants.split(",") if x.strip()]:
            for name, m in _eval_variant(args.data, v):
                if cols is None:
                    cols = list(m.keys()); w.writerow(["Bản", "Cấu hình"] + cols)
                w.writerow([_LABEL_OF.get(v, v), name] + [m[c] for c in cols])
                print(f"  {name:36} FN={m['bỏ lọt (FN)']:5}  FNR={m['FNR']:.4f}  lọc bớt={m['% alert lọc bớt']:.4f}")
    print(f"[+] {fpath}")


if __name__ == "__main__":
    main()
