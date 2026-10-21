"""
core/egress.py — LỚP 4 (Ngày 4): DANH SÁCH TRẮNG NƠI AGENT ĐƯỢC GỌI RA NGOÀI

Mô hình đe doạ (ASI02 — lạm dụng công cụ): một Agent bị chiếm quyền có thể bị ép gọi ra một máy chủ do
kẻ tấn công kiểm soát (tuồn dữ liệu, tải thêm payload, gọi webhook lạ). Lớp 4 thu hẹp quyền: Agent CHỈ
được gọi ra đúng ba nơi nó cần — LLM nội bộ (Ollama), cảnh báo (Telegram), tình báo IP (AbuseIPDB).

Đây là phòng vệ TẤT ĐỊNH: danh sách trắng theo tên host, không phụ thuộc LLM.
Khi Lớp 4 TẮT (off/l1/l12) → cho phép mọi nơi, đúng hành vi cũ (baseline không đổi).
"""
import os
from urllib.parse import urlparse

from core.profile import layer_enabled

# Ba đích Agent thật sự cần. Ollama thường là loopback; nếu OLLAMA_HOST trỏ máy khác thì thêm host đó.
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "api.telegram.org", "api.abuseipdb.com"}

_oh = os.getenv("OLLAMA_HOST", "")
if _oh:
    _h = urlparse(_oh if "://" in _oh else "http://" + _oh).hostname
    if _h:
        ALLOWED_HOSTS.add(_h)


class EgressBlocked(Exception):
    """Gọi ra ngoài tới host không nằm trong danh sách trắng (khi Lớp 4 bật)."""


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def is_allowed(url: str) -> bool:
    """True nếu được phép gọi. Lớp 4 tắt → luôn True (baseline)."""
    if not layer_enabled(4):
        return True
    return host_of(url) in ALLOWED_HOSTS


def guard(url: str) -> None:
    """Chặn (ném lỗi) nếu Lớp 4 bật và host không trong danh sách trắng."""
    if not is_allowed(url):
        raise EgressBlocked(f"[Lớp 4] Chặn egress tới host ngoài danh sách trắng: {host_of(url) or url}")
