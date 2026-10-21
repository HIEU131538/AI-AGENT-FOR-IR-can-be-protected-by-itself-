"""
tools/sign_manifests.py — LỚP 5: ký HMAC cho manifest của kho RAG ĐÃ NẠP SẴN (không cần nạp lại).

Từ Ngày 5, rag_engine/ingest.py tự ký manifest. Nhưng các kho đã nạp từ trước (chroma_db/ và rag_stores/<p>/)
có manifest CHƯA ký. Nạp lại tốn vài phút nhúng — không cần, vì nội dung chunk không đổi. Script này chỉ TÍNH
và GHI trường "signature" vào các manifest hiện có, dùng đúng khoá AGENT_RAG_HMAC_KEY.

Chạy (PowerShell), đặt khoá trước:
    $env:AGENT_RAG_HMAC_KEY = "<chuỗi bí mật của bạn>"
    python tools\\sign_manifests.py

Lưu ý: khoá này phải GIỮ BÍ MẬT và GIỐNG NHAU lúc chạy Agent (retriever xác minh bằng chính khoá đó).
Không commit khoá vào Git.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from core import rag_manifest as rm   # noqa: E402
try:
    from dotenv import load_dotenv   # đọc AGENT_RAG_HMAC_KEY từ .env (không in ra)
    load_dotenv(REPO / ".env")
except Exception:
    pass

STORES = [REPO / "chroma_db"] + sorted((REPO / "rag_stores").glob("*")) if (REPO / "rag_stores").exists() \
    else [REPO / "chroma_db"]


def check() -> int:
    """B8.1: chỉ KIỂM (không ký lại): manifest có chữ ký và khớp khoá AGENT_RAG_HMAC_KEY hiện tại không."""
    src = rm.key_source()
    print(f"[i] Nguồn khoá: {src}" + ("  ← khoá DEV viết cứng: bản full sẽ FAIL-CLOSED" if src == "dev" else ""))
    bad = 0
    for store in STORES:
        f = store / rm.MANIFEST_NAME
        if not f.exists():
            continue
        m = json.loads(f.read_text(encoding="utf-8"))
        ok = bool(m.get("signature")) and rm.verify(m)
        bad += (not ok) or src == "dev"
        print(f"[{'+' if ok else '-'}] {f} · {len(rm.docs_map(m))} chunk · chữ ký {'HỢP LỆ' if ok else 'SAI/THIẾU'}")
    return 1 if bad else 0


def main():
    if "--check" in sys.argv:
        sys.exit(check())
    if rm.key_source() == "dev":
        print("[-] Chưa đặt AGENT_RAG_HMAC_KEY (đang là khoá DEV). Đặt khoá thật rồi chạy lại.")
        sys.exit(1)
    n = 0
    for store in STORES:
        f = store / rm.MANIFEST_NAME
        if not f.exists():
            continue
        m = json.loads(f.read_text(encoding="utf-8"))
        m.pop("signature", None)
        m["signature"] = rm.sign(m)
        f.write_text(json.dumps(m, indent=1, ensure_ascii=False), encoding="utf-8")
        ok = rm.verify(m)
        print(f"[{'+' if ok else '-'}] Đã ký {f}  ·  {len(rm.docs_map(m))} chunk  ·  xác minh={ok}")
        n += 1
    if n == 0:
        print("[-] Không tìm thấy manifest nào. Hãy nạp kho trước (rag_engine/ingest.py).")
    else:
        print(f"[i] Xong {n} manifest. Nhớ đặt CÙNG AGENT_RAG_HMAC_KEY khi chạy Agent bản `full`.")


if __name__ == "__main__":
    main()
