"""prefilter/model.py — nạp model đã huấn luyện + ra quyết định DROP/PASS_UNCERTAIN/PASS.

Dùng ở runtime (agent/nodes/prefilter.py) và ở eval (prefilter/eval_prefilter.py).
Nạp một lần, cache theo variant. Thiếu artifact → trả None (prefilter sẽ CHO QUA mọi alert).
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

ART = Path(__file__).resolve().parent / "artifacts"


@lru_cache(maxsize=4)
def _load(variant: str):
    import joblib
    d = ART / variant
    mp, meta = d / "model.joblib", d / "meta.json"
    if not (mp.exists() and meta.exists()):
        return None
    bundle = joblib.load(mp)
    m = json.loads(meta.read_text(encoding="utf-8"))
    return {"cal": bundle["rf_calibrated"], "features": bundle["features"],
            "t": m["threshold"], "lo": m["band_lo"], "hi": m["band_hi"]}


def available(variant: str = "subset_flow") -> bool:
    return _load(variant) is not None


def prob(row: List[float], variant: str = "subset_flow") -> Optional[float]:
    mdl = _load(variant)
    if mdl is None:
        return None
    return float(mdl["cal"].predict_proba([row])[:, 1][0])


def decide(p: Optional[float], variant: str = "subset_flow") -> Dict:
    """p None → PASS (không đủ dữ liệu / chưa có model). Trả {decision, prob, band}."""
    mdl = _load(variant)
    if p is None or mdl is None:
        return {"decision": "PASS", "prob": p, "reason": "no_model_or_features"}
    lo, hi = mdl["lo"], mdl["hi"]
    if p < lo:
        dec = "DROP"
    elif p < hi:
        dec = "PASS_UNCERTAIN"
    else:
        dec = "PASS"
    return {"decision": dec, "prob": round(p, 4), "band": [lo, hi]}
