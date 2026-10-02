"""
sync_sigmahq.py — B4.3b: tải luật SigmaHQ ở MỘT commit cố định, dựng lại bộ luật nền + thư viện luật cho RAG.

    python sync_sigmahq.py            # cần git + mạng tới github.com (~1 phút)

Làm 3 việc:
  1. Chép nguyên văn 25 luật nền (danh sách BASE_RULES) vào rules/base/sigmahq/ và sinh lại
     rules/base/base_rules.csv (kèm 3 luật tự viết ở rules/base/custom/ — không đụng tới chúng).
  2. Chép thư viện luật cho RAG (các thư mục trong LIBRARY_DIRS, giữ nguyên cấu trúc thư mục)
     vào data/sigma_lib/ + ghi data/sigma_lib/_source.json (commit, ngày, số luật).
  3. KHÔNG xoá gì: thư mục cũ data/sigma_rules/ để nguyên (ingest v2 không đọc nó nữa).

Vì sao cố định commit: bộ luật nền dùng chung cho Splunk, kho RAG và bộ kịch bản vàng v2 —
lấy "bản mới nhất" mỗi lần chạy sẽ làm ba bên lệch nhau.
"""
import csv
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent
SIGMAHQ_URL = "https://github.com/SigmaHQ/sigma.git"
SIGMAHQ_COMMIT = "07ec293a51695cb1131a2e05260247872b31e1e1"   # 25/09/2026

BASE_DIR = REPO / "rules" / "base"
LIB_DIR = REPO / "data" / "sigma_lib"

# (file SigmaHQ, nhóm → surface khi gửi alert, dùng cho gì trong lab)
BASE_RULES = [
    ("web_sql_injection_in_access_logs.yml", "web", "SQLi trên web IIS"),
    ("web_path_traversal_exploitation_attempt.yml", "web", "dò/khai thác path traversal"),
    ("web_win_webshells_in_access_logs.yml", "web", "gọi webshell qua URL"),
    ("web_susp_windows_path_uri.yml", "web", "chuỗi lệnh Windows trong URI"),
    ("proc_creation_win_webshell_susp_process_spawned_from_webserver.yml", "webshell", "w3wp.exe sinh shell (bước then chốt màn 1)"),
    ("proc_creation_win_webshell_recon_commands_and_processes.yml", "webshell", "webshell chạy lệnh trinh sát"),
    ("proc_creation_win_webshell_hacking.yml", "webshell", "hoạt động hack qua webshell"),
    ("proc_creation_win_powershell_base64_encoded_cmd.yml", "powershell", "PowerShell -enc"),
    ("proc_creation_win_powershell_frombase64string.yml", "powershell", "FromBase64String — FP: thư viện script quản trị"),
    ("proc_creation_win_powershell_susp_download_patterns.yml", "powershell", "tải + chạy (IEX DownloadString)"),
    ("proc_creation_win_susp_web_request_cmd_and_cmdlets.yml", "powershell", "Invoke-WebRequest/curl/wget — mức medium"),
    ("proc_creation_win_certutil_download.yml", "lolbas", "certutil tải file — mức medium"),
    ("proc_creation_win_certutil_decode.yml", "lolbas", "certutil -decode"),
    ("proc_creation_win_bitsadmin_download.yml", "lolbas", "bitsadmin tải file — mức medium"),
    ("proc_creation_win_mshta_http.yml", "lolbas", "mshta chạy HTA từ xa"),
    ("proc_creation_win_whoami_priv_discovery.yml", "discovery", "whoami /priv"),
    ("proc_creation_win_systeminfo_execution.yml", "discovery", "systeminfo — mức low"),
    ("proc_creation_win_susp_network_scan_loop.yml", "discovery", "vòng lặp quét mạng từ máy chủ"),
    ("proc_creation_win_schtasks_creation.yml", "persistence", "schtasks /create — mức low, FP: quản trị"),
    ("proc_creation_win_schtasks_creation_temp_folder.yml", "persistence", "tác vụ chạy file trong Temp — high"),
    ("proc_creation_win_reg_add_run_key.yml", "persistence", "reg add ...\\Run — medium"),
    ("proc_creation_win_sysinternals_psexec_execution.yml", "lateral", "PsExec — medium, FP: script quản trị"),
    ("net_dns_susp_b64_queries.yml", "dns", "truy vấn DNS chứa base64 (tunneling)"),
    ("net_dns_susp_txt_exec_strings.yml", "dns", "bản ghi TXT chứa lệnh"),
    ("net_dns_mal_cobaltstrike.yml", "dns", "beacon DNS kiểu Cobalt Strike"),
]

# Thư viện luật cho RAG: chỉ nguồn log có trong lab (Sysmon Windows, log web/proxy, DNS)
LIBRARY_DIRS = [
    "rules/windows/process_creation",
    "rules/windows/registry/registry_set",
    "rules/windows/powershell/powershell_script",
    "rules/windows/network_connection",
    "rules/windows/dns_query",
    "rules/web",
    "rules/network/dns",
]


def run(cmd, cwd=None):
    subprocess.run(cmd, cwd=cwd, check=True)


def fetch(dst: Path):
    run(["git", "init", "-q", str(dst)])
    run(["git", "remote", "add", "origin", SIGMAHQ_URL], cwd=dst)
    run(["git", "fetch", "-q", "--depth", "1", "origin", SIGMAHQ_COMMIT], cwd=dst)
    run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=dst)


def attack_ids(rule):
    return " ".join(t.split(".", 1)[1].upper() for t in rule.get("tags", []) or []
                    if isinstance(t, str) and t.lower().startswith("attack.t"))


def index_row(base_id, source, group, rule, file_rel, sigmahq_path, lab_use):
    ls = rule.get("logsource") or {}
    return {"base_id": base_id, "source": source, "group": group, "sigma_id": rule.get("id"),
            "title": rule.get("title"), "level": rule.get("level"), "status": rule.get("status"),
            "attack_ids": attack_ids(rule),
            "logsource": "/".join(x for x in [ls.get("product"), ls.get("category"), ls.get("service")] if x),
            "falsepositives": " | ".join(map(str, rule.get("falsepositives") or [])),
            "file": file_rel, "sigmahq_path": sigmahq_path, "lab_use": lab_use}


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="sigmahq_"))
    try:
        print(f"[*] Tải SigmaHQ @ {SIGMAHQ_COMMIT[:7]} ...")
        fetch(tmp)

        # 1. Luật nền
        (BASE_DIR / "sigmahq").mkdir(parents=True, exist_ok=True)
        rows = []
        for i, (fname, group, use) in enumerate(BASE_RULES, 1):
            hits = glob.glob(str(tmp / "rules" / "**" / fname), recursive=True)
            if len(hits) != 1:
                print(f"[-] Không tìm thấy đúng 1 file cho {fname}: {hits}")
                return 1
            shutil.copy2(hits[0], BASE_DIR / "sigmahq" / fname)
            rule = yaml.safe_load(open(hits[0], encoding="utf-8"))
            rows.append(index_row(f"B{i:02d}", "sigmahq", group, rule, f"sigmahq/{fname}",
                                  os.path.relpath(hits[0], tmp).replace("\\", "/"), use))
        for j, f in enumerate(sorted((BASE_DIR / "custom").glob("*.yml")), 1):
            rule = yaml.safe_load(open(f, encoding="utf-8"))
            rows.append(index_row(f"C{j:02d}", "custom", "network", rule, f"custom/{f.name}", "",
                                  rule.get("x_aegis_lab_use", "")))
        with open(BASE_DIR / "base_rules.csv", "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"[+] Luật nền: {len(rows)} ({sum(r['source'] == 'sigmahq' for r in rows)} SigmaHQ + "
              f"{sum(r['source'] == 'custom' for r in rows)} tự viết) → {BASE_DIR}")

        # 2. Thư viện cho RAG
        if LIB_DIR.exists():
            print(f"[*] {LIB_DIR} đã có — ghi đè các file cùng tên, không xoá file khác.")
        n = 0
        for d in LIBRARY_DIRS:
            for src in glob.glob(str(tmp / d / "**" / "*.yml"), recursive=True):
                rel = Path(os.path.relpath(src, tmp / "rules"))
                (LIB_DIR / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, LIB_DIR / rel)
                n += 1
        (LIB_DIR / "_source.json").write_text(json.dumps({
            "repo": SIGMAHQ_URL, "commit": SIGMAHQ_COMMIT, "dirs": LIBRARY_DIRS, "rules": n,
            "license": "Detection Rule License (DRL) 1.1"}, indent=2), encoding="utf-8")
        print(f"[+] Thư viện RAG: {n} luật → {LIB_DIR}")
        print("[i] Thư mục cũ data/sigma_rules/ để nguyên, ingest v2 không đọc nó nữa.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
