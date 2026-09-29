"""
tools/make_rag_stores.py — B4 (Ngày 3, AegisSOC): TẠO KHO RAG RIÊNG CHO TỪNG PROFILE

Vì sao: 4 bản Agent (off / l1 / l12 / full) chạy song song mà cùng mở MỘT thư mục ChromaDB thì
  (1) ChromaDB 0.5 dễ lỗi khi nhiều tiến trình cùng ghi một file SQLite, và
  (2) tài liệu tiêm vào bản này lọt sang bản kia → Bảng 3 đo sai.
Script sao kho gốc sạch `chroma_db/` thành `rag_stores/<profile>/`. Agent tự nhận kho riêng
khi khởi động (xem core/profile.py).

An toàn:
  - Kiểm kho gốc TRƯỚC khi sao: có tài liệu không rõ nguồn → từ chối (kho gốc phải sạch).
  - Không ghi đè kho riêng đã có, trừ khi thêm --force.
  - Chỉ ĐỌC kho gốc, không sửa gì trong đó.

Chạy (TẮT mọi bản Agent đang chạy trước):
    python tools\\make_rag_stores.py                    # tạo đủ 4 kho
    python tools\\make_rag_stores.py --force            # tạo lại (xoá kho riêng cũ)
    python tools\\make_rag_stores.py --profiles full    # chỉ tạo kho cho full
"""
import argparse
import json
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.profile import PROFILES  # noqa: E402  (chỉ lấy danh sách tên profile)

MASTER = ROOT / "chroma_db"
STORES = ROOT / "rag_stores"
TRUSTED_SOURCES = ("admin_sigma_rule", "mitre_framework")


def inspect_store(path: Path) -> dict:
    """Đếm chunk theo nguồn, chỉ đọc (mở SQLite ở chế độ read-only)."""
    db_file = path / "chroma.sqlite3"
    con = sqlite3.connect(db_file.as_uri() + "?mode=ro", uri=True)
    try:
        total = con.execute("SELECT count(*) FROM embeddings").fetchone()[0]
        by_source = dict(con.execute(
            "SELECT m.string_value, count(*) FROM embeddings e "
            "LEFT JOIN embedding_metadata m ON e.id = m.id AND m.key = 'source_type' "
            "GROUP BY m.string_value").fetchall())
        placeholders = ",".join("?" * len(TRUSTED_SOURCES))
        unknown_ids = [r[0] for r in con.execute(
            "SELECT e.embedding_id FROM embeddings e "
            "LEFT JOIN embedding_metadata m ON e.id = m.id AND m.key = 'source_type' "
            f"WHERE m.string_value IS NULL OR m.string_value NOT IN ({placeholders})",
            TRUSTED_SOURCES).fetchall()]
    finally:
        con.close()
    return {"total": total, "by_source": by_source, "unknown_ids": unknown_ids}


def main() -> int:
    ap = argparse.ArgumentParser(description="Tạo kho RAG riêng cho từng profile từ kho gốc chroma_db/")
    ap.add_argument("--profiles", default=",".join(PROFILES), help="danh sách, mặc định: %(default)s")
    ap.add_argument("--force", action="store_true", help="xoá và tạo lại kho riêng đã có")
    args = ap.parse_args()

    profiles = [p.strip().lower() for p in args.profiles.split(",") if p.strip()]
    bad = [p for p in profiles if p not in PROFILES]
    if bad:
        print(f"[-] Profile không hợp lệ: {bad}. Chỉ nhận: {', '.join(PROFILES)}")
        return 1

    if not (MASTER / "chroma.sqlite3").is_file():
        print(f"[-] Không thấy kho gốc {MASTER}\\chroma.sqlite3")
        return 1

    # --- 1. Kiểm kho gốc ---
    wal = MASTER / "chroma.sqlite3-wal"
    if wal.exists() and wal.stat().st_size > 0:
        print("[!] Kho gốc có file -wal chưa gộp — có thể một bản Agent đang mở kho. "
              "Nên tắt hết uvicorn rồi chạy lại để bản sao nhất quán.")
    info = inspect_store(MASTER)
    print(f"[*] Kho gốc: {info['total']} chunk · theo nguồn: {info['by_source']}")
    if info["unknown_ids"]:
        print(f"[-] DỪNG: kho gốc có {len(info['unknown_ids'])} tài liệu không rõ nguồn "
              f"(ví dụ: {info['unknown_ids'][:5]}). Kho gốc phải sạch trước khi sao — "
              f"xoá các tài liệu này (hoặc ingest lại) rồi chạy lại script.")
        return 1

    # --- 2. Sao từng kho ---
    STORES.mkdir(exist_ok=True)
    log_file = STORES / "_copies.json"
    try:
        log = json.loads(log_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log = {}

    failed = 0
    for p in profiles:
        dest = STORES / p
        if dest.exists():
            if not args.force:
                print(f"[=] {p}: đã có kho riêng → giữ nguyên (thêm --force để tạo lại)")
                continue
            try:
                shutil.rmtree(dest)
            except OSError as e:
                print(f"[-] {p}: không xoá được kho cũ ({type(e).__name__}) — "
                      f"có bản Agent `{p}` đang chạy? Tắt nó rồi thử lại.")
                failed += 1
                continue
        shutil.copytree(MASTER, dest, ignore=shutil.ignore_patterns("*Zone.Identifier"))
        copied = inspect_store(dest)
        ok = copied["total"] == info["total"] and not copied["unknown_ids"]
        print(f"[{'+' if ok else '-'}] {p}: {dest} · {copied['total']} chunk"
              + ("" if ok else "  ← KHÔNG KHỚP kho gốc!"))
        if not ok:
            failed += 1
            continue
        log[p] = {
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": str(MASTER),
            "chunks": copied["total"],
            "by_source": copied["by_source"],
        }

    log_file.write_text(json.dumps(log, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[*] Xong. Lỗi: {failed}. Nhật ký sao chép: {log_file}")
    print("[*] Khởi động Agent với DEFENSE_PROFILE tương ứng — nó tự nhận kho riêng.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
