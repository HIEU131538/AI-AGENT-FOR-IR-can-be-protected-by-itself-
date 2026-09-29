"""
eval/preflight.py — B4.1: KIỂM MỘT BẢN AGENT CÓ SẴN SÀNG ĐỂ ĐO KHÔNG (chạy tay trước mỗi đợt đo)

    python -m eval.preflight --profile off
    python -m eval.preflight --profile full --no-sample     # chỉ kiểm /health, không gửi alert thử

Kiểm: đúng profile · Agent gọi được Ollama · một alert thử phân tích thật (không lỗi, không quá nhanh).
Thoát mã 0 = sẵn sàng, 1 = chưa sẵn sàng. Cần $env:AGENT_TOKEN như các script đo khác.
"""
import argparse
import json
import sys

from eval.common import PROFILES, preflight

SAMPLE_FILE = "replay/alerts_b1.json"


def main() -> int:
    ap = argparse.ArgumentParser(description="Kiểm bản Agent trước khi đo")
    ap.add_argument("--profile", required=True, choices=list(PROFILES))
    ap.add_argument("--no-sample", action="store_true", help="không gửi alert thử")
    args = ap.parse_args()

    sample = None
    if not args.no_sample:
        with open(SAMPLE_FILE, encoding="utf-8") as f:
            sample = json.load(f)["alerts"][:1]

    problems = preflight(args.profile, sample_alerts=sample)
    if problems:
        print(f"[-] Bản `{args.profile}` CHƯA sẵn sàng để đo:")
        for p in problems:
            print(f"    - {p}")
        return 1
    print(f"[+] Bản `{args.profile}` sẵn sàng để đo "
          f"({'đã chạy alert thử' if sample else 'chỉ kiểm /health'}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
