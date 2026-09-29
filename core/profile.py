"""
core/profile.py — B4 (Ngày 3, AegisSOC): CÔNG TẮC PHÒNG VỆ `DEFENSE_PROFILE`

Một bản Agent = một profile. Profile quyết định 2 thứ:
  1. Bật những lớp phòng vệ nào (các bước sau hỏi qua `layer_enabled(n)`).
  2. Dùng kho RAG nào (mỗi profile một bản sao riêng, tránh dùng chung một thư mục ChromaDB).

    Profile  Cổng  Lớp bật        Dùng cho
    off      8010  (không)        Bảng 2 dòng 0 · Bảng 3 cột "cũ" · Bảng 4
    l1       8011  1              Bảng 2 dòng "Lớp 1"
    l12      8012  1, 2           Bảng 2 dòng "Lớp 1 + 2"
    full     8000  1, 2, 4, 5     Bảng 2 dòng "đủ" · Bảng 3 cột "manifest" · Bảng 4 · demo

Lớp 1 = Rule of Two · Lớp 2 = Spotlighting · Lớp 4 = thu hẹp quyền · Lớp 5 = manifest RAG.
(Lớp 3 đã cắt khỏi bản 7 ngày.) Lớp nào chưa được code thì bật cũng chưa có tác dụng —
bản `off` luôn là đường cũ, không phụ thuộc lớp nào.

Chạy (PowerShell):
    $env:DEFENSE_PROFILE = "full"; uvicorn api.main:app --port 8000
"""
import os

PROFILES = ("off", "l1", "l12", "full")

_LAYERS = {
    "off":  frozenset(),
    "l1":   frozenset({1}),
    "l12":  frozenset({1, 2}),
    "full": frozenset({1, 2, 4, 5}),
}

# Cổng quy ước cho từng profile (khớp eval/common.py) — chỉ để in cảnh báo, không ép buộc
EXPECTED_PORTS = {"off": 8010, "l1": 8011, "l12": 8012, "full": 8000}

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER_STORE = os.path.join(_ROOT, "chroma_db")          # kho gốc sạch (do rag_engine/ingest.py tạo)
STORES_DIR = os.path.join(_ROOT, "rag_stores")           # nơi chứa kho riêng của từng profile


def _read_profile() -> tuple:
    raw = os.getenv("DEFENSE_PROFILE")
    if raw is None or not raw.strip():
        # Mặc định `off` = đúng hành vi cũ, để lệnh chạy quen thuộc không bị vỡ.
        # Ngày 4 (khi đủ lớp phòng vệ) sẽ xem lại mặc định này.
        return "off", "DEFENSE_PROFILE chưa đặt → dùng mặc định `off` (không phòng vệ)."
    value = raw.strip().lower()
    if value not in PROFILES:
        # Sai giá trị → dừng hẳn, không đoán: chạy nhầm profile thì mọi số đo đều sai.
        raise SystemExit(
            f"[Profile] DEFENSE_PROFILE='{raw}' không hợp lệ. Chỉ nhận: {', '.join(PROFILES)}."
        )
    return value, None


PROFILE, STARTUP_WARNING = _read_profile()
LAYERS = _LAYERS[PROFILE]


def layer_enabled(n: int) -> bool:
    """Lớp phòng vệ số n có bật ở bản Agent này không."""
    return n in LAYERS


def _resolve_rag_store() -> tuple:
    """
    Chọn kho RAG theo thứ tự ưu tiên:
      1. Biến môi trường RAG_STORE_DIR (chỉ định thẳng)
      2. rag_stores/<profile>/ nếu đã được tạo bằng tools/make_rag_stores.py
      3. chroma_db/ (kho gốc, dùng chung) — kèm cảnh báo
    """
    explicit = os.getenv("RAG_STORE_DIR", "").strip()
    if explicit:
        return os.path.abspath(explicit), "RAG_STORE_DIR"
    own = os.path.join(STORES_DIR, PROFILE)
    if os.path.isfile(os.path.join(own, "chroma.sqlite3")):
        return own, f"kho riêng của profile `{PROFILE}`"
    return MASTER_STORE, "kho gốc dùng chung (CHƯA tạo kho riêng)"


RAG_STORE_DIR, RAG_STORE_SOURCE = _resolve_rag_store()


def describe() -> dict:
    """Thông tin để in lúc khởi động và trả ở /health."""
    return {
        "defense_profile": PROFILE,
        "layers": sorted(LAYERS),
        "rag_store": RAG_STORE_DIR,
        "rag_store_source": RAG_STORE_SOURCE,
    }


def startup_messages() -> list:
    msgs = [f"[Profile] DEFENSE_PROFILE={PROFILE} · lớp bật: {sorted(LAYERS) or 'không có'} · "
            f"kho RAG: {RAG_STORE_DIR} ({RAG_STORE_SOURCE})"]
    if STARTUP_WARNING:
        msgs.append(f"[Profile] CẢNH BÁO: {STARTUP_WARNING}")
    if RAG_STORE_DIR == MASTER_STORE:
        msgs.append("[Profile] CẢNH BÁO: đang dùng kho gốc chung. Chạy nhiều bản Agent cùng lúc thì "
                    "phải tạo kho riêng trước: python tools\\make_rag_stores.py")
    return msgs
