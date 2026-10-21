"""
Nhận webhook từ Splunk,
chuẩn hóa alert theo contract của AegisSOC,
lưu sample B01/B02/...,
sau đó gửi alert sang Agent.

Khi chưa có Agent thật:
    fake_agent.py -> port 8000
    splunk_bridge.py -> port 9000
"""

import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from fastapi import FastAPI, Request, HTTPException


# ============================================================
# APP
# ============================================================

app = FastAPI(title="AegisSOC Splunk Bridge")


# ============================================================
# CONFIG
# ============================================================

# Agent thật / fake Agent đều dùng API này
AGENT_URL = os.getenv(
    "AGENT_URL",
    "http://127.0.0.1:8000/ingest/alerts"
)

# Token lấy từ biến môi trường
# Khi test fake_agent có thể để trống
AGENT_TOKEN = os.getenv(
    "AGENT_TOKEN",
    ""
)


# ============================================================
# CONTRACT
# ============================================================

LEVELS = {
    "low",
    "medium",
    "high",
    "critical"
}

SURFACES = {
    "web",
    "endpoint",
    "network"
}

CONTRACT_KEYS = {
    "rule_name",
    "rule_level",
    "attack_ids",
    "surface",
    "src_ip",
    "dest_ip",
    "dest_port",
    "host",
}

EMPTY_IP = {
    "",
    "-",
    "n/a",
    "na",
    "none",
    "null",
    "unknown"
}


# ============================================================
# RULE -> BASE SAMPLE
# ============================================================

RULE_TO_BASE_ID = {

    "SQL Injection Strings In URI":
        "B01",

    "Path Traversal Exploitation Attempts":
        "B02",

    "Windows Webshell Strings":
        "B03",

    "Suspicious Windows Strings In URI":
        "B04",

    "Suspicious Encoded PowerShell Command Line":
        "B08",

    "Base64 Encoded PowerShell Command Detected":
        "B09",
    "Suspicious PowerShell Download and Execute Pattern": "B10",
    "Usage Of Web Request Commands And Cmdlets": "B11",
    "Suspicious Download Via Certutil.EXE": "B12",
    "File Decoded From Base64/Hex Via Certutil.EXE": "B13",
    "File Download Via Bitsadmin": "B14",
    "Remotely Hosted HTA File Executed Via Mshta.EXE": "B15",
    "Security Privileges Enumeration Via Whoami.EXE": "B16",
    "Suspicious Execution of Systeminfo": "B17",
    "Suspicious Scan Loop Network": "B18",
    "Scheduled Task Creation Via Schtasks.EXE": "B19",
    "Suspicious Scheduled Task Creation Involving Temp Folder": "B20",
    "Potential Persistence Attempt Via Run Keys Using Reg.EXE": "B21",
    "Psexec Execution": "B22",
    "Suspicious DNS Query with B64 Encoded String": "B23",
    "DNS TXT Answer with Possible Execution Strings": "B24",
    "Cobalt Strike DNS Beaconing": "B25",
    "AegisSOC - Large Outbound Transfer From Web Server": "C01",
    "AegisSOC - Suricata Malware or C2 Communication Alert": "C02",
    "AegisSOC - Suricata Network Scan Alert": "C03",
    "Suspicious Process By Web Server Process": "B05",
    "Webshell Detection With Command Line Keywords": "B06",
    "Webshell Hacking Activity Patterns": "B07",
}


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    filename="bridge.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)


# ============================================================
# DEDUP
# ============================================================

_seen: set[str] = set()


# ============================================================
# TIMESTAMP
# ============================================================

def to_utc_iso(value) -> str:
    """
    Splunk _time thường là epoch dạng chuỗi.

    Ví dụ:
        1790798260.563

    Chuyển thành:
        2026-09-30T08:29:30Z
    """

    try:
        return datetime.fromtimestamp(
            float(value),
            tz=timezone.utc
        ).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    except (TypeError, ValueError):

        return datetime.now(
            timezone.utc
        ).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )


# ============================================================
# ATTACK IDS
# ============================================================

def split_ids(value) -> list[str]:

    if isinstance(value, list):

        return [
            str(x).strip()
            for x in value
            if str(x).strip()
        ]

    return [
        x.strip()
        for x in str(value or "").split(",")
        if x.strip()
    ]


# ============================================================
# DEST PORT
# ============================================================

def to_int(value):

    try:
        return int(value)

    except (TypeError, ValueError):

        return None


# ============================================================
# IP / FIELD NORMALIZATION
# ============================================================

# Các field không phải dữ liệu gốc của log.
# Không đưa chúng vào fields vì Agent chỉ cần dữ liệu nguồn.
EXCLUDED_FIELD_NAMES = {
    "_raw",
    "_bkt",
    "_cd",
    "_si",
    "_serial",
    "_indextime",
    "punct",
    "linecount",
    "timestartpos",
    "timeendpos",
    "eventtype",
    "index",
    "source",
    "sourcetype",
    "search_name",
    "splunk_server",
    "splunk_server_group",
    "splunk_server_version",
    "cmd_l",
    "image_l",
    "original_l",
    "query_l",
}

EXCLUDED_FIELD_PREFIXES = (
    "date_",
    "splunk_server",
    "tag",
    "stats.",
)


def first_value(value):
    """Lấy phần tử đầu tiên có giá trị từ field multivalue."""
    if isinstance(value, (list, tuple)):
        for item in value:
            if item is not None and str(item).strip() != "":
                return item
        return None
    return value


def is_empty_value(value) -> bool:
    """True nếu field không có dữ liệu thực."""
    if value is None:
        return True

    if isinstance(value, str):
        return value.strip() == ""

    if isinstance(value, (list, tuple)):
        return len(value) == 0 or all(is_empty_value(x) for x in value)

    if isinstance(value, dict):
        return len(value) == 0

    return False


def normalize_field_value(key, value):
    """
    Giữ field nguồn, nhưng xử lý multivalue theo cách an toàn:
    - bỏ phần tử rỗng;
    - singleton -> scalar;
    - duplicate hoàn toàn (A,A,...) -> scalar A;
    - các giá trị khác nhau (A,B,...) -> giữ nguyên list;
    - User của Sysmon vẫn được lấy phần tử đầu tiên như trước.
    """
    if isinstance(value, (list, tuple)):
        values = [x for x in value if not is_empty_value(x)]

        if not values:
            return None

        # Splunk/alert webhook có thể serialize cùng một field JSON
        # nhiều lần, ví dụ ["11342", "11342"]. Đây không phải
        # multivalue thực sự; collapse duplicate hoàn toàn về một giá trị.
        if len(values) == 1 or all(item == values[0] for item in values[1:]):
            return values[0]

        # User của Sysmon thường bị trả thành mảng 1 phần tử.
        if key.lower() == "user":
            return values[0]

        # Nếu có nhiều giá trị thực sự khác nhau thì không làm mất dữ liệu.
        return values

    return value


def is_excluded_field(key: str) -> bool:
    k = str(key)
    kl = k.lower()

    if k.startswith("_"):
        return True

    if kl in EXCLUDED_FIELD_NAMES:
        return True

    if any(kl.startswith(prefix) for prefix in EXCLUDED_FIELD_PREFIXES):
        return True

    return False


def build_fields(result: dict) -> dict:
    """
    Chỉ giữ field gốc có dữ liệu.
    Loại field nội bộ Splunk và field phụ do SPL tạo.
    """
    fields = {}

    for key, value in result.items():

        if is_excluded_field(key):
            continue

        # Contract fields đã được đưa ra ngoài alert.
        if key in CONTRACT_KEYS:
            continue

        value = normalize_field_value(key, value)

        # Agent không cần field rỗng.
        if is_empty_value(value):
            continue

        fields[key] = value

    return fields


def clean_ip(value) -> str:
    """
    Agent chỉ nhận một IP dạng chuỗi hoặc "".

    Nếu Splunk/Suricata trả multivalue:
        ["192.168.10.20", "192.168.10.20"]
    thì lấy phần tử đầu tiên.
    """
    value = first_value(value)

    if value is None:
        return ""

    v = str(value).strip()

    if v.lower() in EMPTY_IP:
        return ""

    return v


# ============================================================
# BUILD ALERT
# ============================================================

def build_alert(body: dict) -> dict:

    # Splunk webhook thường có:
    #
    # {
    #   "sid": "...",
    #   "search_name": "...",
    #   "result": {...}
    # }

    result = body.get(
        "result",
        {}
    ) or {}


    # --------------------------------------------------------
    # RULE NAME
    # --------------------------------------------------------

    rule_name = (
        result.get("rule_name")
        or result.get("search_name")
        or body.get("search_name")
        or "unknown_rule"
    )


    # --------------------------------------------------------
    # RULE LEVEL
    # --------------------------------------------------------

    level = str(
        result.get(
            "rule_level",
            "medium"
        )
    ).lower()

    if level not in LEVELS:
        level = "medium"


    # --------------------------------------------------------
    # SURFACE
    # --------------------------------------------------------

    surface = str(
        result.get(
            "surface",
            ""
        )
    ).lower()


    # --------------------------------------------------------
    # ALERT ID
    # --------------------------------------------------------

    serial = (
        result.get("_serial")
        or result.get("_time")
        or ""
    )

    alert_id = (
        f"{body.get('sid', 'nosid')}:{serial}"
    )


    # --------------------------------------------------------
    # BUILD ALERT
    # --------------------------------------------------------

    alert = {

        "alert_id":
            alert_id,

        "rule_name":
            rule_name,

        "rule_level":
            level,

        "attack_ids":
            split_ids(
                result.get("attack_ids")
            ),

        "surface":
            surface,

        # Bridge đổi epoch Splunk -> ISO 8601 UTC.
        "timestamp":
            to_utc_iso(
                result.get("_time")
            ),

        # Nếu Suricata trả multivalue thì lấy 1 IP dạng chuỗi.
        "src_ip":
            clean_ip(
                result.get("src_ip")
            ),

        "dest_ip":
            clean_ip(
                result.get("dest_ip")
            ),

        # Agent yêu cầu số, không phải chuỗi.
        "dest_port":
            to_int(
                first_value(
                    result.get("dest_port")
                )
            ),

        "host":
            first_value(
                result.get("host", "")
            ) or "",

        # Chỉ giữ dữ liệu gốc có giá trị.
        "fields":
            build_fields(result),
    }


    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    alert["summary"] = (
        f"{alert['rule_name']} | "
        f"{alert['src_ip']} -> "
        f"{alert['dest_ip']}:"
        f"{alert['dest_port']} | "
        f"host={alert['host']}"
    )


    return alert


# ============================================================
# SEND TO AGENT
# ============================================================

def send_to_agent(alert: dict) -> bool:

    # --------------------------------------------------------
    # Authorization
    # --------------------------------------------------------

    headers = {
        "Content-Type":
            "application/json"
    }

    if AGENT_TOKEN:

        headers["Authorization"] = (
            f"Bearer {AGENT_TOKEN}"
        )


    # --------------------------------------------------------
    # Payload
    # --------------------------------------------------------

    payload = {
        "alerts": [
            alert
        ]
    }


    # --------------------------------------------------------
    # RETRY 3 LẦN
    # --------------------------------------------------------

    for attempt in range(3):

        try:

            response = requests.post(

                AGENT_URL,

                json=payload,

                headers=headers,

                timeout=10
            )


            # ------------------------------------------------
            # 2xx -> SUCCESS
            # ------------------------------------------------

            if response.status_code < 300:

                logging.info(
                    "Agent nhận alert %s: HTTP %s",
                    alert["alert_id"],
                    response.status_code
                )

                return True


            # ------------------------------------------------
            # 4xx -> KHÔNG RETRY
            # ------------------------------------------------

            if 400 <= response.status_code < 500:

                logging.error(
                    "Agent từ chối alert %s: HTTP %s: %s",
                    alert["alert_id"],
                    response.status_code,
                    response.text[:300]
                )

                return False


            # ------------------------------------------------
            # 5xx -> RETRY
            # ------------------------------------------------

            logging.warning(
                "Agent trả HTTP %s cho alert %s "
                "(lần %d/3)",
                response.status_code,
                alert["alert_id"],
                attempt + 1
            )


        except requests.RequestException as exc:

            logging.warning(
                "Lỗi kết nối Agent "
                "(lần %d/3): %s",
                attempt + 1,
                exc
            )


        # ----------------------------------------------------
        # BACKOFF
        # ----------------------------------------------------

        if attempt < 2:

            time.sleep(
                2 ** attempt
            )


    # --------------------------------------------------------
    # FAILED AFTER 3 ATTEMPTS
    # --------------------------------------------------------

    logging.error(
        "Không thể gửi alert %s sau 3 lần thử",
        alert["alert_id"]
    )

    return False


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "ok",
        "agent_url": AGENT_URL
    }


# ============================================================
# SPLUNK WEBHOOK
# ============================================================

@app.post("/splunk-webhook")
async def splunk_webhook(
    request: Request
):

    # --------------------------------------------------------
    # READ JSON
    # --------------------------------------------------------

    try:

        body = await request.json()

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid JSON"
        )


    print(
        "\n========== SPLUNK WEBHOOK =========="
    )

    print(body)

    print(
        "===================================="
    )


    # --------------------------------------------------------
    # BUILD ALERT
    # --------------------------------------------------------

    alert = build_alert(body)


    # --------------------------------------------------------
    # VALIDATE SURFACE
    # --------------------------------------------------------

    if alert["surface"] not in SURFACES:

        logging.error(
            "alert %s KHÔNG gửi: "
            "surface không hợp lệ: %s",
            alert["alert_id"],
            alert["surface"]
        )

        return {
            "status":
                "rejected_surface",

            "alert_id":
                alert["alert_id"]
        }


    # --------------------------------------------------------
    # DEDUP
    # --------------------------------------------------------

    if alert["alert_id"] in _seen:

        logging.info(
            "Duplicate alert: %s",
            alert["alert_id"]
        )

        return {
            "status":
                "duplicate",

            "alert_id":
                alert["alert_id"]
        }


    # --------------------------------------------------------
    # SAVE SAMPLE B01/B02/B03...
    # --------------------------------------------------------

    sample_dir = Path(
        "rules/base/samples"
    )

    sample_dir.mkdir(
        parents=True,
        exist_ok=True
    )


    rule_name = alert[
        "rule_name"
    ]


    base_id = RULE_TO_BASE_ID.get(
        rule_name
    )


    if base_id:

        sample_path = (
            sample_dir
            / f"{base_id}.json"
        )


        with open(
            sample_path,
            "w",
            encoding="utf-8"
        ) as f:

            import json

            json.dump(
                alert,
                f,
                ensure_ascii=False,
                indent=2
            )


        print(
            f"[SAMPLE] Saved: "
            f"{sample_path}"
        )


    else:

        print(
            "[SAMPLE] WARNING: "
            f"No Base ID mapping for rule: "
            f"{rule_name}"
        )


    # --------------------------------------------------------
    # SEND TO AGENT
    # --------------------------------------------------------

    ok = send_to_agent(
        alert
    )


    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    if ok:

        # Chỉ đánh dấu đã nhận sau khi Agent trả về 2xx.
        # Nếu gửi thất bại, alert_id vẫn có thể được gửi lại.
        _seen.add(
            alert["alert_id"]
        )

        logging.info(
            "alert %s -> agent OK",
            alert["alert_id"]
        )

        return {
            "status":
                "forwarded",

            "alert_id":
                alert["alert_id"]
        }


    logging.error(
        "alert %s -> agent FAILED",
        alert["alert_id"]
    )


    return {
        "status":
            "agent_unreachable",

        "alert_id":
            alert["alert_id"]
    }
