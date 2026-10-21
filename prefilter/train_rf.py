"""prefilter/train_rf.py — huấn luyện làn ML của prefilter (Random Forest) trên UNSW-NB15.

Làm ở TẦNG QUYẾT ĐỊNH, đúng kế hoạch (AegisSOC_00 mục 4.3):
  1. Train Random Forest (kèm Logistic Regression làm đối chứng) trên tập train.
  2. Hiệu chuẩn xác suất bằng isotonic (CalibratedClassifierCV, cv='prefit') trên tập calib.
  3. Ngưỡng theo chi phí t = C_FP/(C_FP+C_FN). Bỏ lọt đắt gấp 10 → t = 1/11 ≈ 0.091.
  4. Dải bất định quanh t, chọn trên calib: alert trong dải LUÔN đẩy lên Agent (uncertain).

Hai bản cột:
  - full       : toàn bộ 42 cột UNSW (để so với số bài báo — Bảng 1 chính thức).
  - subset_flow: 12 cột Suricata cũng đo được (để gắn pipeline thật).

Lưu artifact vào prefilter/artifacts/<variant>/: model.joblib, meta.json.
KHÔNG commit dữ liệu; chỉ commit model + meta (nhẹ).

Chạy:
  python -m prefilter.train_rf --data <thư mục processed của bạn dataset> --variant subset_flow
  python -m prefilter.train_rf --data <...> --variant full
"""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
import joblib

ART = Path(__file__).resolve().parent / "artifacts"
COST_RATIO = 10          # bỏ lọt (FN) đắt gấp 10 lần báo nhầm (FP)
LABEL = "label"


def _load(data_dir: Path, variant: str):
    d = data_dir / variant
    tr = pd.read_csv(d / "train.csv")
    ca = pd.read_csv(d / "calib.csv")
    feats = [c for c in tr.columns if c != LABEL]
    return tr, ca, feats


def _fit_rf(X, y):
    # max_depth + min_samples_leaf giữ model gọn (<10MB nén) mà gần như không giảm chất lượng.
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=22, min_samples_leaf=5, max_features="sqrt",
        n_jobs=-1, class_weight="balanced_subsample", random_state=42)
    rf.fit(X, y)
    return rf


def _band_from_calib(p_cal, y_cal, t):
    """Dải bất định quanh t: [lo, hi] sao cho ca trong dải là nơi model lẫn lộn nhất.
    Chọn lo = max phân vị để FNR(calib) còn ≤ 1%; hi = t*2 (giới hạn trên gọn)."""
    attacks = p_cal[y_cal == 1]
    lo = float(np.quantile(attacks, 0.01)) if len(attacks) else t * 0.5
    lo = min(lo, t)                         # không vượt quá t
    hi = min(max(t * 2.0, t + 0.05), 0.5)   # trần 0.5
    lo = max(lo, 0.0)
    return round(lo, 4), round(hi, 4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="thư mục processed/ của bạn dataset")
    ap.add_argument("--variant", default="subset_flow", choices=["subset_flow", "full"])
    args = ap.parse_args()

    data_dir = Path(args.data)
    tr, ca, feats = _load(data_dir, args.variant)

    # Đồng bộ BẢNG MÃ của bạn dataset vào artifacts — runtime (core/flow_features.py) mã hoá
    # proto/service bằng đúng bảng này. Lệch bảng mã = model nhận mã sai mà không báo lỗi.
    import shutil
    ART.mkdir(parents=True, exist_ok=True)
    for name in ("encoders.json", "service_mapping.json"):
        src = data_dir / name
        if not src.exists():
            raise SystemExit(f"Thiếu {src} — không train được vì runtime cần đúng bảng mã này.")
        shutil.copyfile(src, ART / name)
    Xtr, ytr = tr[feats].values, tr[LABEL].values
    Xca, yca = ca[feats].values, ca[LABEL].values
    print(f"[{args.variant}] train={Xtr.shape} calib={Xca.shape} feats={len(feats)}")

    # 1. Model chính (RF) + đối chứng (LR có chuẩn hoá)
    rf = _fit_rf(Xtr, ytr)
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced"))
    lr.fit(Xtr, ytr)

    # 2. Hiệu chuẩn RF bằng isotonic trên calib (KHÔNG train lại RF).
    #    sklearn >=1.6 bỏ cv='prefit' → dùng FrozenEstimator; bản cũ thì fallback cv='prefit'.
    try:
        from sklearn.frozen import FrozenEstimator
        cal = CalibratedClassifierCV(FrozenEstimator(rf), method="isotonic")
    except Exception:
        cal = CalibratedClassifierCV(rf, method="isotonic", cv="prefit")
    cal.fit(Xca, yca)

    # 3. Ngưỡng theo chi phí
    t = 1.0 / (1.0 + COST_RATIO)

    # 4. Dải bất định trên calib
    p_cal = cal.predict_proba(Xca)[:, 1]
    band_lo, band_hi = _band_from_calib(p_cal, yca, t)

    # Đối chứng LR: chỉ in FNR để báo cáo, KHÔNG lưu (giữ artifact gọn).
    p_lr = lr.predict_proba(Xca)[:, 1]
    fnr_lr = float(((yca == 1) & (p_lr < 0.5)).sum()) / max(1, int((yca == 1).sum()))
    print(f"[{args.variant}] (đối chứng) LR FNR@0.5 trên calib = {fnr_lr:.4f}")

    out = ART / args.variant
    out.mkdir(parents=True, exist_ok=True)
    # Chỉ lưu model đã hiệu chuẩn (đã gồm RF bên trong) + danh sách đặc trưng. Nén để nhẹ.
    joblib.dump({"rf_calibrated": cal, "features": feats}, out / "model.joblib", compress=3)
    meta = {
        "variant": args.variant, "features": feats, "cost_ratio": COST_RATIO,
        "threshold": round(t, 4), "band_lo": band_lo, "band_hi": band_hi,
        "n_train": int(len(ytr)), "n_calib": int(len(yca)),
        "note": "DROP nếu p<band_lo; PASS_UNCERTAIN nếu band_lo<=p<band_hi; PASS nếu p>=band_hi. "
                "Ngưỡng chi phí t nằm trong dải. Thiếu dữ liệu luồng → PASS (an toàn).",
    }
    (out / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[{args.variant}] t={t:.4f} band=[{band_lo},{band_hi}] → {out}")


if __name__ == "__main__":
    main()
