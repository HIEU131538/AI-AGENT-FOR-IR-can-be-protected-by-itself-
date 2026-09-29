"""
replay/replay_alerts.py — B1 (AegisSOC)

Phát lại alert từ file JSON lên POST /ingest/alerts — đường vào (a) trong kế hoạch,
thay cho Splunk khi Splunk chưa cắm. Luồng phía sau y hệt alert thật.

Chạy từ thư mục gốc repo (API phải đang chạy ở cổng 8000):
    python replay\\replay_alerts.py                       # phát lại replay/alerts_b1.json
    python replay\\replay_alerts.py --reset               # xoá bộ nhớ Agent trước khi phát
    python replay\\replay_alerts.py file_khac.json --no-wait

Token: đọc AGENT_TOKEN từ biến môi trường hoặc .env. Script KHÔNG in token ra màn hình.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FILE = REPO_ROOT / "replay" / "alerts_b1.json"
DEFAULT_URL = "http://127.0.0.1:8000"


def main() -> int:
    parser = argparse.ArgumentParser(description="Phát lại alert lên /ingest/alerts")
    parser.add_argument("file", nargs="?", default=str(DEFAULT_FILE), help="file JSON có khoá 'alerts'")
    parser.add_argument("--url", default=DEFAULT_URL, help="địa chỉ API Agent (mặc định %(default)s)")
    parser.add_argument("--no-wait", action="store_true",
                        help="gửi kiểu bridge: nhận 202 ngay, không chờ kết quả (xem ở /recent)")
    parser.add_argument("--reset", action="store_true", help="gọi /reset trước khi phát lại")
    parser.add_argument("--delay", type=float, default=0.0, help="số giây nghỉ giữa hai alert")
    args = parser.parse_args()

    load_dotenv(REPO_ROOT / ".env")
    token = os.getenv("AGENT_TOKEN", "")
    if not token:
        print("[-] Chưa có AGENT_TOKEN (trong .env hoặc biến môi trường). Dừng.")
        return 1

    alerts = json.loads(Path(args.file).read_text(encoding="utf-8")).get("alerts", [])
    if not alerts:
        print(f"[-] File {args.file} không có alert nào trong khoá 'alerts'.")
        return 1

    headers = {"Authorization": f"Bearer {token}"}
    ingest_url = f"{args.url}/ingest/alerts"

    if args.reset:
        r = requests.post(f"{args.url}/reset", timeout=10)
        print(f"[*] Reset bộ nhớ Agent: HTTP {r.status_code}")

    print(f"[*] Phát lại {len(alerts)} alert từ {args.file} → {ingest_url}\n")
    failed = 0
    for i, alert in enumerate(alerts, 1):
        label = f"[{i}/{len(alerts)}] {alert.get('alert_id')} | {alert.get('rule_name')}"
        try:
            # Gửi từng alert một để thấy kết quả dần; wait=true chờ LLM phân tích xong
            r = requests.post(ingest_url, json={"alerts": [alert]}, headers=headers,
                              params={"wait": "false" if args.no_wait else "true"},
                              timeout=15 if args.no_wait else 600)
        except requests.RequestException as e:
            print(f"{label}\n    [-] Không gọi được API: {e}")
            failed += 1
            continue

        if r.status_code >= 300:
            print(f"{label}\n    [-] HTTP {r.status_code}: {r.text[:300]}")
            failed += 1
        elif args.no_wait:
            print(f"{label}\n    [+] HTTP {r.status_code} — đã nhận, đang phân tích nền")
        else:
            for res in r.json().get("results", []):
                if res.get("status") == "analyzed":
                    print(f"{label}\n    [+] incident={res['incident_id']} severity={res['severity']} "
                          f"mitre={res['mitre_techniques']} action={res['action_taken']} "
                          f"({res['processing_time_ms']:.0f} ms)")
                    if res.get("enrichment_summary"):          # Ngày 2: kết quả làm giàu
                        print(f"        làm giàu: {res['enrichment_summary']}")
                else:
                    print(f"{label}\n    [-] lỗi phân tích: {res.get('detail')}")
                    failed += 1
        if args.delay:
            time.sleep(args.delay)

    print(f"\n[*] Xong. Lỗi: {failed}/{len(alerts)}. Xem chi tiết: {args.url}/recent hoặc dashboard.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
