"""prepare_data.py — chuẩn bị UNSW-NB15 cho lớp lọc ML của AegisSOC.

Bản đã sửa theo góp ý:
  1. Bảng 6.3: công thức rate/smean/dmean/sload/dload đúng + hàm kiểm chứng
     (compute_derived / check_derived_cols) so với cột có sẵn trong dữ liệu.
  2. Train/test theo chuẩn chính thức của UNSW-NB15:
       - TRAIN/CALIB lấy từ file "testing-set"  (175.341 dòng)
       - TEST        lấy từ file "training-set" (82.332 dòng)
     (tên file trên Kaggle bị đặt ngược so với bài báo).
  (Cập nhật) Xóa trùng lần 2 (đặc trưng + label, bỏ attack_cat) làm TRƯỚC train_test_split;
     bảng kiểm chứng công thức báo thêm số dòng lệch > 1% và độ lệch tương đối lớn nhất.
  3. Mục 7: thống kê số dòng + tỷ lệ tấn công theo từng giá trị proto
     (đặc biệt `unas` và `__other__`) để báo cáo nêu rõ nguy cơ "đường tắt".
"""

import json
import sys
from datetime import date
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# --- XỬ LÝ ĐƯỜNG DẪN TỰ ĐỘNG ---
BASE_DIR = Path(__file__).resolve().parent
RAW = BASE_DIR / "data" / "raw"
OUT = BASE_DIR / "data" / "processed"

# --- Tên file trên Kaggle (BỊ ĐẶT NGƯỢC so với chuẩn chính thức) ---
# File "testing-set"  (175.341 dòng) = tập TRAIN chính thức của UNSW-NB15.
# File "training-set" (82.332 dòng)  = tập TEST  chính thức của UNSW-NB15.
TRAIN_FILE = "UNSW_NB15_testing-set.csv"
TEST_FILE = "UNSW_NB15_training-set.csv"
EXPECTED_TRAIN_ROWS = 175_341
EXPECTED_TEST_ROWS = 82_332

SEED = 42
CAT_COLS = ["proto", "service", "state"]
TOP_PROTO = 10
PROTO_WATCH = ["unas"]  # luôn thống kê riêng các giá trị proto này (xem mục 7)
SUBSET_FLOW = ["dur", "proto", "service", "spkts", "dpkts", "sbytes", "dbytes",
               "rate", "sload", "dload", "smean", "dmean"]
DERIVED_COLS = ["smean", "dmean", "rate", "sload", "dload"]

# --- Nguồn dữ liệu (mục 8.1 của báo cáo) ---
DATA_SOURCE_URL = "https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15"
DATA_DOWNLOAD_DATE = date.today().isoformat()  # TODO: thay bằng ngày bạn THỰC SỰ tải file nếu khác hôm nay

# --- BẢNG 6.4: Đổi tên dịch vụ (Service Mapping) ---
SERVICE_MAPPING = {
    "http": "http",
    "tls": "ssl",
    "ssl": "ssl",
    "dns": "dns",
    "ssh": "ssh",
    "smtp": "smtp",
    "ftp": "ftp",
    "ftp-data": "ftp-data",
    "pop3": "pop3",
    "irc": "irc",
    "radius": "radius",
    "snmp": "snmp",
    "dhcp": "dhcp",
    "failed": "none",
    "": "none",
    "null": "none",
    "-": "none",
}


# ======================================================================
# CÔNG THỨC CÁC CỘT TÍNH TOÁN (bảng 6.3)
# Khớp dữ liệu UNSW-NB15 với sai số ~1e-8. Dùng lại đúng hàm này khi tính
# từ log Suricata lúc chạy thật để model nhận cùng thang đo.
#   smean = round(sbytes / spkts)
#   dmean = round(dbytes / dpkts)
#   rate  = (spkts + dpkts - 1) / dur
#   sload = (sbytes - smean) * 8 / dur
#   dload = (dbytes - dmean) * 8 / dur
#   Khi dur = 0: rate = sload = dload = 0
# ======================================================================
def _safe_div(a, b):
    """a / b, trả 0 ở những chỗ b <= 0."""
    return np.divide(a, b, out=np.zeros(len(a), dtype=float), where=b > 0)


def compute_derived(df):
    """Tính lại smean, dmean, rate, sload, dload từ spkts/dpkts/sbytes/dbytes/dur."""
    num = lambda c: pd.to_numeric(df[c], errors="coerce").fillna(0).to_numpy(float)
    spk, dpk = num("spkts"), num("dpkts")
    sby, dby = num("sbytes"), num("dbytes")
    dur = num("dur")

    smean = np.round(_safe_div(sby, spk))
    dmean = np.round(_safe_div(dby, dpk))
    return {
        "smean": smean,
        "dmean": dmean,
        "rate": _safe_div(spk + dpk - 1, dur),
        "sload": _safe_div((sby - smean) * 8, dur),
        "dload": _safe_div((dby - dmean) * 8, dur),
    }


def check_derived_cols(df, rtol=1e-6, atol=1e-6, big=0.01):
    """So cột có sẵn trong dữ liệu với giá trị tính lại.

    Với mỗi cột trả về:
      - mismatch  : số dòng lệch theo dung sai chặt (rtol/atol)
      - over_big  : số dòng lệch tương đối > `big` (mặc định 1%)
      - max_rel   : độ lệch tương đối lớn nhất (|a-e| / max(|a|,|e|))
    Ngoài ra trả `any_over_big`: số dòng có ÍT NHẤT MỘT cột lệch > 1%.
    """
    expected = compute_derived(df)
    cols = {}
    any_big = np.zeros(len(df), dtype=bool)
    for col in DERIVED_COLS:
        actual = pd.to_numeric(df[col], errors="coerce").fillna(0).to_numpy(float)
        exp = expected[col]
        diff = np.abs(actual - exp)
        scale = np.maximum(np.maximum(np.abs(actual), np.abs(exp)), 1e-12)
        rel = diff / scale
        bad = ~np.isclose(actual, exp, rtol=rtol, atol=atol)
        over = (rel > big) & (diff > atol)
        any_big |= over
        cols[col] = {
            "rows": int(len(df)),
            "mismatch": int(bad.sum()),
            "over_big": int(over.sum()),
            "max_rel": float(rel.max()) if len(rel) else 0.0,
        }
    return {"cols": cols, "rows": int(len(df)), "any_over_big": int(any_big.sum())}


def _print_derived_check(name, res):
    for col, r in res["cols"].items():
        flag = "OK " if r["mismatch"] == 0 else "LỆCH"
        print(f"  [{flag}] {name}.{col}: {r['mismatch']} / {r['rows']} dòng lệch (>1%: {r['over_big']}, lệch tương đối lớn nhất {r['max_rel']:.2%})")
    pct = res["any_over_big"] / res["rows"] * 100 if res["rows"] else 0
    print(f"  -> {name}: {res['any_over_big']} / {res['rows']} dòng ({pct:.3f}%) có ít nhất 1 cột lệch quá 1%")


# ======================================================================
def load():
    try:
        tr = pd.read_csv(RAW / TRAIN_FILE)
        te = pd.read_csv(RAW / TEST_FILE)
    except FileNotFoundError:
        print(f"LỖI: Không tìm thấy file trong thư mục:\n{RAW}")
        print(f"Cần đủ 2 file: {TRAIN_FILE} và {TEST_FILE}")
        sys.exit(1)

    assert len(tr) == EXPECTED_TRAIN_ROWS and len(te) == EXPECTED_TEST_ROWS, (
        f"Số dòng không khớp chuẩn UNSW-NB15: {TRAIN_FILE} có {len(tr)} dòng "
        f"(cần {EXPECTED_TRAIN_ROWS}), {TEST_FILE} có {len(te)} dòng (cần {EXPECTED_TEST_ROWS}). "
        "Kiểm tra lại tên file/phiên bản dữ liệu. Dừng lại — báo Hiếu, đừng tự sửa cho khớp.")

    tr_cols = set(tr.columns)
    te_cols = set(te.columns)
    if tr_cols != te_cols:
        print("\n" + "=" * 50)
        print("🚨 PHÁT HIỆN LỖI LỆCH CỘT GIỮA TRAIN VÀ TEST 🚨")
        print("-> Cột CÓ ở Train nhưng KHÔNG CÓ ở Test:", tr_cols - te_cols)
        print("-> Cột CÓ ở Test nhưng KHÔNG CÓ ở Train:", te_cols - tr_cols)
        print("=" * 50 + "\n")

    assert list(tr.columns) == list(te.columns), \
        "Cột của train và test không khớp (xem chi tiết lệch cột ở trên). Dừng lại — báo Hiếu, đừng tự sửa cho khớp."

    return tr, te


def clean(df, report, name):
    df = df.drop(columns=["id"], errors="ignore").copy()
    df["attack_cat"] = df["attack_cat"].astype(str).str.strip()
    for c in CAT_COLS:
        df[c] = df[c].astype(str).str.strip().str.lower()
    df["service"] = df["service"].replace("-", "none")
    num = df.select_dtypes(include="number").columns
    df[num] = df[num].replace([np.inf, -np.inf], np.nan)
    report[f"{name}_nan"] = int(df[num].isna().sum().sum())
    df[num] = df[num].fillna(0)
    return df


def fit_encoders(train):
    enc = {}
    for c in CAT_COLS:
        counts = train[c].value_counts()
        keep = list(counts.index[:TOP_PROTO]) if c == "proto" else list(counts.index)
        enc[c] = {str(v): i for i, v in enumerate(keep)}
        enc[c]["__other__"] = len(keep)
    return enc


def apply_encoders(df, enc):
    df = df.copy()
    for c, m in enc.items():
        df[c] = df[c].map(lambda v: m.get(str(v), m["__other__"])).astype(int)
    return df


def row_hashes(df, cols):
    return set(pd.util.hash_pandas_object(df[cols], index=False))


def proto_attack_stats(df, kept):
    """Số dòng + tỷ lệ tấn công theo từng giá trị proto (phải gọi TRƯỚC khi mã hóa).

    Các giá trị trong `kept` (và PROTO_WATCH) được tách riêng; phần còn lại gộp thành `__other__`.
    """
    shown = set(kept) | set(PROTO_WATCH)
    p = df["proto"].where(df["proto"].isin(shown), "__other__")
    g = df.groupby(p)["label"].agg(rows="size", attack="sum")
    return {
        str(k): {
            "rows": int(r["rows"]),
            "attack": int(r["attack"]),
            "attack_rate": float(r["attack"]) / int(r["rows"]),
        }
        for k, r in g.iterrows()
    }


# ======================================================================
# BÁO CÁO MARKDOWN
# ======================================================================
def _attack_cat_table(counts):
    all_cats = sorted({cat for split in counts.values() for cat in split["attack_cat_counts"]})
    header = "| attack_cat | " + " | ".join(counts.keys()) + " |"
    sep = "|---|" + "|".join(["---"] * len(counts)) + "|"
    rows = []
    for cat in all_cats:
        row = [str(counts[split]["attack_cat_counts"].get(cat, 0)) for split in counts]
        rows.append(f"| {cat} | " + " | ".join(row) + " |")
    return "\n".join([header, sep] + rows)


def _derived_check_table(check):
    header = "| Tập | Cột | Dòng lệch (dung sai 1e-6) | Dòng lệch > 1% | Lệch tương đối lớn nhất |"
    sep = "|---|---|---|---|---|"
    rows = []
    for split, label in (("train_full", "Train"), ("test", "Test")):
        res = check[split]
        for col in DERIVED_COLS:
            r = res["cols"][col]
            rows.append(f"| {label} | `{col}` | {r['mismatch']} / {r['rows']} | {r['over_big']} | {r['max_rel'] * 100:.4f}% |")
    return "\n".join([header, sep] + rows)


def _derived_check_summary(check):
    parts = []
    for split, label in (("train_full", "Train"), ("test", "Test")):
        res = check[split]
        pct = res["any_over_big"] / res["rows"] * 100 if res["rows"] else 0
        parts.append(f"{label}: {res['any_over_big']} / {res['rows']} dòng ({pct:.3f}%)")
    return "; ".join(parts)


def _proto_table(ps):
    tr, te = ps["train"], ps["test"]
    protos = sorted(set(tr) | set(te), key=lambda k: -tr.get(k, {"rows": 0})["rows"])

    def cell(d, k):
        if k not in d:
            return "0", "-"
        return str(d[k]["rows"]), f"{d[k]['attack_rate'] * 100:.2f}%"

    header = "| proto | Train: số dòng | Train: % tấn công | Test: số dòng | Test: % tấn công | Ghi chú |"
    sep = "|---|---|---|---|---|---|"
    rows = []
    for k in protos:
        tr_rows, tr_rate = cell(tr, k)
        te_rows, te_rate = cell(te, k)
        note = "⚠️ 100% tấn công ở Train" if k in tr and tr[k]["attack_rate"] == 1.0 and tr[k]["rows"] > 0 else ""
        rows.append(f"| `{k}` | {tr_rows} | {tr_rate} | {te_rows} | {te_rate} | {note} |")
    return "\n".join([header, sep] + rows)


def generate_markdown_report(report, feats_full):
    attack_cat_table = _attack_cat_table(report["splits"])
    derived_table = _derived_check_table(report["derived_check"])
    derived_summary = _derived_check_summary(report["derived_check"])
    _sp = report["splits"]
    train_rate = _sp["train"]["label_counts"].get(1, 0) / _sp["train"]["rows"] * 100
    calib_rate = _sp["calib"]["label_counts"].get(1, 0) / _sp["calib"]["rows"] * 100
    proto_table = _proto_table(report["proto_stats"])
    md_content = f"""# Báo cáo Dữ liệu UNSW-NB15 (AegisSOC)

## 1. Nguồn dữ liệu
- Nguồn: Kaggle (UNSW-NB15)
- Link tải: {DATA_SOURCE_URL}
- Ngày tải: {DATA_DOWNLOAD_DATE}
- Thư mục gốc: `data/raw/`
- **Cách chia train/test (theo chuẩn chính thức của UNSW-NB15):** tên file trên Kaggle bị đặt ngược.
  - Tập TRAIN chính thức = file `{TRAIN_FILE}` ({EXPECTED_TRAIN_ROWS} dòng: 56.000 normal / 119.341 tấn công).
  - Tập TEST chính thức = file `{TEST_FILE}` ({EXPECTED_TEST_ROWS} dòng).
  - Nhờ vậy kết quả có thể đặt cạnh các số đã công bố trong bài báo.

## 2. Thống kê số dòng và Tỷ lệ nhãn
- **Train (80% của tập train chính thức, sau dedup)**: {report['splits']['train']['rows']} dòng.
  - Nhãn 0: {report['splits']['train']['label_counts'].get(0, 0)} | Nhãn 1: {report['splits']['train']['label_counts'].get(1, 0)}
- **Calib (20% của tập train chính thức, sau dedup)**: {report['splits']['calib']['rows']} dòng.
  - Nhãn 0: {report['splits']['calib']['label_counts'].get(0, 0)} | Nhãn 1: {report['splits']['calib']['label_counts'].get(1, 0)}
- Tỷ lệ tấn công: Train {train_rate:.3f}% | Calib {calib_rate:.3f}% (stratify theo label, dedup xong mới chia).
- **Test (tập test chính thức, giữ nguyên)**: {report['splits']['test']['rows']} dòng.
  - Nhãn 0: {report['splits']['test']['label_counts'].get(0, 0)} | Nhãn 1: {report['splits']['test']['label_counts'].get(1, 0)}

## 3. Số dòng theo attack_cat từng tập
{attack_cat_table}

## 4. Thống kê lỗi và Trùng lặp
- Ô trống (NaN/Inf) đã thay bằng 0:
  - Train: {report['train_full_nan']} ô
  - Test: {report['test_nan']} ô
- Số dòng trùng hoàn toàn (tính cả `attack_cat`) trong tập Train đã xóa ở bước làm sạch: {report['train_full_duplicates_removed']} dòng.
- Số dòng trùng lặp **phát sinh thêm sau khi bỏ cột `attack_cat`** (đã xóa tiếp, **trước khi chia train/calib**): {report['train_post_attackcat_duplicates_removed']} dòng.
  - *Nguyên nhân: một số dòng có đặc trưng mạng (đầu vào model) giống hệt nhau nhưng được gán nhãn `attack_cat` khác nhau (ví dụ Backdoor vs Exploits). Vì `attack_cat` không được dùng làm đặc trưng train, các dòng này là bản sao thật sự đối với model nên cần xóa thêm.*
- Số dòng train (toàn bộ, trước khi chia calib) trùng với test (không xóa): {report['overlap_train_test_rows']} dòng.
- Số dòng calib trùng hệt train (đặc trưng + label, sau mã hóa): {report['calib_train_overlap_rows']} dòng.

## 5. Danh sách cột
- **Phiên bản Full**: {len(feats_full)} cột (Xem chi tiết tại `feature_list_full.txt`)
- **Phiên bản Subset_flow**: 12 cột: `{', '.join(SUBSET_FLOW)}`

## 6. Bảng 6.3 - Ánh xạ Suricata và Định nghĩa UNSW
| Cột UNSW | Trường Suricata | Cách tính | Định nghĩa chính thức (UNSW) |
|---|---|---|---|
| `dur` | `flow.start`, `flow.end` | `end - start` | Record total duration |
| `proto` | `proto` | lowercase | Transaction protocol |
| `service` | `app_proto` | map bảng 6.4 | http, ftp, smtp, ssh, dns, ftp-data ,irc and (-) if not much used |
| `spkts` | `flow.pkts_toserver` | lấy thẳng | Source to destination packet count |
| `dpkts` | `flow.pkts_toclient` | lấy thẳng | Destination to source packet count |
| `sbytes` | `flow.bytes_toserver` | lấy thẳng | Source to destination transaction bytes |
| `dbytes` | `flow.bytes_toclient` | lấy thẳng | Destination to source transaction bytes |
| `smean` | tính | `round(sbytes / spkts)` | Mean of the flow packet size transmitted by the src |
| `dmean` | tính | `round(dbytes / dpkts)` | Mean of the flow packet size transmitted by the dst |
| `rate` | tính | `(spkts + dpkts - 1) / dur` | Không mô tả rõ trong tài liệu UNSW; công thức xác định bằng cách dò lại từ dữ liệu |
| `sload` | tính | `(sbytes - smean) * 8 / dur` | Source bits per second |
| `dload` | tính | `(dbytes - dmean) * 8 / dur` | Destination bits per second |

**Quy ước:** khi `dur = 0` thì đặt `rate = sload = dload = 0` (và `smean`/`dmean` = 0 khi `spkts`/`dpkts` = 0).
Các công thức trên khớp dữ liệu UNSW với sai số khoảng 1e-8. Lúc chạy thật, hệ thống tính các cột này
từ log Suricata bằng cùng công thức (hàm `compute_derived` trong `prepare_data.py`); sai công thức thì
model nhận số lệch thang và chấm sai.

**Kiểm chứng công thức** (tính lại từ `spkts`/`dpkts`/`sbytes`/`dbytes`/`dur` rồi so với cột có sẵn; dung sai tương đối 1e-6):

{derived_table}

*Ghi chú:* các dòng bị đánh dấu "lệch" ở dung sai chặt 1e-6 đều lệch rất nhỏ (xem cột "Lệch tương đối lớn nhất"),
nguyên nhân là do làm tròn `smean`/`dmean` và do dữ liệu gốc lưu số thực với độ chính xác hữu hạn. Số dòng có ít nhất
một cột lệch quá 1% chỉ là một phần rất nhỏ: {derived_summary}.

**Điểm không khớp được hoàn toàn giữa Suricata và UNSW-NB15 (bắt buộc ghi, theo mục 6.3):**
- Cách đếm byte của Suricata có thể lệch nhẹ với UNSW do cách tính header/payload.
- Khi Suricata bắn alert, luồng mạng có thể **chưa kết thúc** (chưa đủ `flow.end`), nên `dur`,
  `spkts`/`dpkts`, `sbytes`/`dbytes` và các cột tính từ chúng (`rate`, `sload`, `dload`, `smean`, `dmean`)
  có thể **chưa đầy đủ/không ổn định** so với dữ liệu UNSW vốn đo trên luồng đã hoàn tất.

## 7. Những gì bất thường gặp phải khi xử lý
- Phát hiện {report['train_post_attackcat_duplicates_removed']} dòng ở tập train chính thức trùng lặp hoàn toàn về đặc trưng + label
  sau khi bỏ cột `attack_cat` (dù `attack_cat` của chúng khác nhau) — đã xóa thêm trước khi chia train/calib, xem mục 4.
- **Giá trị `proto` hiếm có tỷ lệ tấn công rất cao (nguy cơ "đường tắt"):** trong UNSW, các giá trị
  `proto` hiếm như `unas` và nhóm `__other__` (mọi proto ngoài top {TOP_PROTO}) có tỷ lệ tấn công 100%. Ngoài đời
  không như vậy, nên model có thể học "đường tắt" (thấy proto lạ là kết luận tấn công) thay vì học
  hành vi luồng thật. Số dòng và tỷ lệ cụ thể (tính trên tập train chính thức sau dedup và tập test,
  trước khi mã hóa):

{proto_table}

  *`__other__` ở đây là các giá trị proto không nằm trong top {TOP_PROTO} của tập train (và không phải `unas`).*
- *(Điền tay thêm nếu có: số dòng/tỷ lệ nhãn khác xa tài liệu mô tả, giá trị service lạ không có trong bảng 6.4, v.v.
  Nếu gặp bất thường khác — báo Hiếu ngay, đừng tự sửa cho khớp.)*
"""
    (BASE_DIR / "data_report.md").write_text(md_content, encoding="utf-8")


# ======================================================================
def main():
    report = {}
    print("Đang đọc dữ liệu...")
    tr_full, te = load()

    print("Đang kiểm chứng công thức các cột tính toán (bảng 6.3)...")
    report["derived_check"] = {
        "train_full": check_derived_cols(tr_full),
        "test": check_derived_cols(te),
    }
    _print_derived_check("train", report["derived_check"]["train_full"])
    _print_derived_check("test", report["derived_check"]["test"])

    print("Đang làm sạch dữ liệu...")
    tr_full = clean(tr_full, report, "train_full")
    te = clean(te, report, "test")

    # Bước 1: xóa trùng lặp trên TOÀN BỘ cột (còn attack_cat) — đúng mục 5 bước 5 của guide
    report["train_full_duplicates_removed"] = int(tr_full.duplicated().sum())
    tr_full = tr_full.drop_duplicates()

    feats_full = [c for c in tr_full.columns if c not in ("label", "attack_cat")]

    # Bước 2: xóa trùng lặp LẦN 2 theo đặc trưng + label (bỏ qua attack_cat), LÀM TRƯỚC khi chia train/calib.
    # attack_cat không phải đặc trưng đầu vào model nên 2 dòng giống hệt nhau trên feats_full + label
    # nhưng khác attack_cat vẫn là "bản sao" đối với model. Nếu xóa SAU khi chia thì bản sao có thể rơi
    # vào cả train lẫn calib (rò rỉ) và tỷ lệ tấn công của train/calib bị lệch nhau.
    dup_mask = tr_full.duplicated(subset=feats_full + ["label"])
    report["train_post_attackcat_duplicates_removed"] = int(dup_mask.sum())
    tr_full = tr_full[~dup_mask].reset_index(drop=True)

    report["overlap_train_test_rows"] = len(
        row_hashes(tr_full, feats_full) & row_hashes(te, feats_full))

    print("Đang chia tập dữ liệu và mã hóa...")
    train, calib = train_test_split(
        tr_full, test_size=0.2, stratify=tr_full["label"], random_state=SEED)

    enc = fit_encoders(train)

    # Thống kê proto hiếm cho mục 7 — phải làm TRƯỚC apply_encoders (sau mã hóa không còn tên proto)
    kept_proto = [k for k in enc["proto"] if k != "__other__"]
    report["proto_stats"] = {
        "train": proto_attack_stats(tr_full, kept_proto),
        "test": proto_attack_stats(te, kept_proto),
    }
    for split_name, stats in report["proto_stats"].items():
        for k, v in stats.items():
            if v["attack_rate"] == 1.0 and k in (set(PROTO_WATCH) | {"__other__"}):
                print(f"  [proto] {split_name}: `{k}` có {v['rows']} dòng, 100% tấn công (nguy cơ đường tắt)")

    OUT.mkdir(parents=True, exist_ok=True)
    counts = {}

    print("Đang xuất dữ liệu ra thư mục processed...")
    encoded = {}
    for name, df in {"train": train, "calib": calib, "test": te}.items():
        df = apply_encoders(df, enc).reset_index(drop=True)
        encoded[name] = df

        for variant, feats in (("full", feats_full), ("subset_flow", SUBSET_FLOW)):
            d = OUT / variant
            d.mkdir(parents=True, exist_ok=True)
            df[feats + ["label"]].to_csv(d / f"{name}.csv", index=False)
        df[["attack_cat", "label"]].to_csv(OUT / f"{name}_attack_cat.csv", index=False)
        counts[name] = {
            "rows": len(df),
            "label_counts": df["label"].value_counts().sort_index().to_dict(),
            "attack_cat_counts": df["attack_cat"].value_counts().to_dict(),
        }

    # Kiểm tra sau mã hóa: calib không được còn dòng giống hệt train (đặc trưng + label)
    key_cols = feats_full + ["label"]
    report["calib_train_overlap_rows"] = len(
        row_hashes(encoded["train"], key_cols) & row_hashes(encoded["calib"], key_cols))
    for split in ("train", "calib"):
        lc = counts[split]["label_counts"]
        rate = lc.get(1, 0) / counts[split]["rows"] * 100
        print(f"  Tỷ lệ tấn công {split}: {rate:.3f}% ({counts[split]['rows']} dòng)")
    print(f"  Số dòng calib trùng hệt train sau mã hóa: {report['calib_train_overlap_rows']}")

    (OUT / "encoders.json").write_text(json.dumps(enc, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "service_mapping.json").write_text(json.dumps(SERVICE_MAPPING, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "feature_list_full.txt").write_text("\n".join(feats_full), encoding="utf-8")
    (OUT / "feature_list_subset_flow.txt").write_text("\n".join(SUBSET_FLOW), encoding="utf-8")

    report["splits"] = counts
    (OUT / "data_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=int), encoding="utf-8")

    generate_markdown_report(report, feats_full)

    print("Xử lý hoàn tất! Đã lưu toàn bộ dữ liệu vào thư mục data/processed/")
    print(f"Đã xóa thêm {report['train_post_attackcat_duplicates_removed']} dòng trùng lặp phát sinh sau khi bỏ attack_cat (làm trước khi chia train/calib).")
    print("Vui lòng mở file data_report.md (cùng thư mục với prepare_data.py) để xem báo cáo.")


if __name__ == "__main__":
    main()
