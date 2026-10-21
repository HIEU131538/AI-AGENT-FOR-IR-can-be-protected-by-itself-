"""
core/rag_manifest.py — LỚP 5 (Ngày 5): TOÀN VẸN KHO RAG BẰNG MANIFEST BĂM + KÝ HMAC

Mô hình đe doạ (ASI06 — đầu độc bộ nhớ / tri thức): kho RAG là "đường thứ hai" để điều khiển Agent. Ghi được
một tài liệu giả vào kho là Agent sẽ tự lấy "lời nói dối" ra dùng ở mọi lần sau.

Cơ chế CŨ (bản off) tin vào metadata TỰ KHAI của tài liệu (source_type, injected_by…). Một tài liệu giả chỉ
cần khai `source_type=admin_sigma_rule` là qua được bộ lọc → đây là lỗ hổng.

Cơ chế MỚI (Lớp 5): lúc nạp kho (ingest) ghi MANIFEST = { doc_id : SHA-256(nội dung) } và KÝ HMAC-SHA256 toàn
bộ manifest bằng khoá bí mật. Lúc truy xuất, retriever CHỈ nhận chunk nào CÓ trong manifest VÀ băm nội dung
khớp. Tài liệu được cài thêm lúc chạy (không có trong manifest) bị loại — bất kể metadata nó tự khai là gì.
Chữ ký HMAC bảo vệ chính file manifest khỏi bị sửa.

Khoá HMAC đọc từ biến môi trường AGENT_RAG_HMAC_KEY (không commit). Có fallback khoá dev chỉ để chạy thử.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path

MANIFEST_NAME = "_ingest_manifest.json"


DEV_KEY = b"aegis-dev-rag-hmac-key-set-AGENT_RAG_HMAC_KEY-in-prod"


def key_source() -> str:
    """'env' | 'file' | 'dev'. B8.1: khi bật Lớp 5, khoá 'dev' (viết cứng trong mã nguồn) KHÔNG được chấp nhận —
    ai đọc được repo cũng ký được bằng khoá đó."""
    if os.getenv("AGENT_RAG_HMAC_KEY", ""):
        return "env"
    if (Path(__file__).resolve().parent.parent / "data" / ".rag_hmac_key").exists():
        return "file"
    return "dev"


def _key() -> bytes:
    k = os.getenv("AGENT_RAG_HMAC_KEY", "")
    if k:
        return k.encode("utf-8")
    kf = Path(__file__).resolve().parent.parent / "data" / ".rag_hmac_key"
    if kf.exists():
        return kf.read_bytes().strip()
    # Fallback chỉ để DEMO khi chưa đặt khoá. Báo cáo ghi rõ: bản thật phải đặt AGENT_RAG_HMAC_KEY.
    return DEV_KEY


def sha(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _canonical(core: dict) -> bytes:
    return json.dumps(core, sort_keys=True, ensure_ascii=False).encode("utf-8")


def sign(core: dict) -> str:
    """Ký HMAC-SHA256 phần manifest KHÔNG gồm trường signature."""
    body = {k: v for k, v in (core or {}).items() if k != "signature"}
    return hmac.new(_key(), _canonical(body), hashlib.sha256).hexdigest()


def load(store_dir) -> dict:
    f = Path(store_dir) / MANIFEST_NAME
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {}


def verify(manifest: dict) -> bool:
    """True nếu manifest có chữ ký và chữ ký khớp khoá hiện tại."""
    sig = (manifest or {}).get("signature")
    if not sig:
        return False
    return hmac.compare_digest(str(sig), sign(manifest))


def docs_map(manifest: dict) -> dict:
    """{ doc_id : sha256(nội dung) } của các chunk hợp lệ."""
    return (manifest or {}).get("docs") or {}
