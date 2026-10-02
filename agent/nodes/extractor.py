import re
import math
import base64
import urllib.parse
from agent.state import SOCAgentState

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def _deep_extract_strings(obj, depth: int = 0) -> str:
    """Đệ quy toàn bộ dict/list → chuỗi phẳng để scan pattern.
    Depth limit tránh log lồng sâu vô hạn."""
    if depth > 6:
        return ""
    if isinstance(obj, dict):
        return " ".join(_deep_extract_strings(v, depth + 1) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(_deep_extract_strings(v, depth + 1) for v in obj)
    return str(obj)


def node_extractor(state: SOCAgentState):
    print("\n[Trạm 1 - Extractor] Đang bóc tách Log bằng Regex & Heuristics...")

    raw_log = state.get("raw_log", {})

    # ── DEEP STRING EXTRACTION ───────────────────────────────────────────────
    # str(raw_log) cho chuỗi phẳng nhưng giữ Python syntax (dấu nháy đơn).
    # _deep_extract_strings đệ quy qua dict/list để lấy VALUE thật sự,
    # không bị nhiễu bởi key names. Kết hợp cả hai để tối đa coverage.
    log_str     = str(raw_log)
    deep_str    = _deep_extract_strings(raw_log)
    combined    = log_str + " " + deep_str

    # URL-decode (chống obfuscation %2F, %3B, v.v.)
    decoded_log_str = urllib.parse.unquote(combined)
    # B5.1: trong query string, "+" là dấu cách ("1%27+OR+%271" → "1' OR '1"). unquote() giữ nguyên "+",
    # nên từ khoá SQLi dạng "' OR '" / "UNION SELECT" không khớp. Nối thêm bản giải mã unquote_plus.
    _plus_decoded = urllib.parse.unquote_plus(combined)
    if _plus_decoded != decoded_log_str:
        decoded_log_str += " " + _plus_decoded

    # ── BASE64 BODY DECODE ───────────────────────────────────────────────────
    # Phase 2: payload SSRF/RCE có thể bị base64-encode trong field body/request_body.
    # Giải mã và nối vào decoded_log_str để các scanner sau tìm thấy 169.254, file://, v.v.
    _body_fields = ["body", "request_body", "data", "payload", "encoded_body"]
    for _field in _body_fields:
        _b64_candidate = str(raw_log.get(_field, ""))
        if _b64_candidate and len(_b64_candidate) > 16:
            # Thử base64 decode — nếu fail thì bỏ qua yên lặng
            try:
                _pad = _b64_candidate + "=" * (4 - len(_b64_candidate) % 4)
                _decoded_body = base64.b64decode(_pad).decode("utf-8", errors="ignore")
                if _decoded_body:
                    decoded_log_str += " " + urllib.parse.unquote(_decoded_body)
            except Exception:
                pass
        # Cũng thử tìm nested request.body
        _nested_body = raw_log.get("request", {})
        if isinstance(_nested_body, dict):
            _nb = str(_nested_body.get("body", ""))
            if _nb and len(_nb) > 16:
                try:
                    _pad = _nb + "=" * (4 - len(_nb) % 4)
                    _dec = base64.b64decode(_pad).decode("utf-8", errors="ignore")
                    if _dec:
                        decoded_log_str += " " + urllib.parse.unquote(_dec)
                except Exception:
                    pass
        break  # chỉ cần 1 lần với nested
    
    # Khởi tạo kho lưu trữ bằng chứng (IOCs)
    extracted_ioc = {
        "ips": [],
        "domains": [],
        "ports": [],
        "urls": [],
        "base64_strings": [],
        "attack_indicators": []
    }
    notes = ["Extractor: Bắt đầu quét IOC..."]

    # --- 0. KIỂM TRA SOURCE IP NGAY TỪ ĐẦU ---
    import ipaddress
    _raw_source_ip = str(raw_log.get("source_ip", "")).strip()
    _source_ip_valid = False
    if _raw_source_ip:
        try:
            ipaddress.ip_address(_raw_source_ip)
            _source_ip_valid = True
        except ValueError:
            extracted_ioc["attack_indicators"].append("log_injection")
            notes.append(
                f"Extractor [CẢNH BÁO ĐỎ]: source_ip='{_raw_source_ip}' KHÔNG PHẢI IPv4 hợp lệ — "
                f"khả năng Log Injection/Tampering! Không thể thực thi SOAR action trên IP này."
            )

    # --- 1. THỢ SĂN IP (Regex IPv4 chuẩn hóa) ---
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b'
    found_ips = re.findall(ip_pattern, decoded_log_str)
    if found_ips:
        extracted_ioc["ips"] = list(set(found_ips))
        notes.append(f"Extractor: Tóm được IPv4 hợp lệ -> {extracted_ioc['ips']}")

    # --- 2. THỢ SĂN DOMAIN (Generic TLDs) ---
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    # B4.3c: tên file (whoami.exe, backup.bat, backup.ps1...) KHÔNG phải tên miền
    _file_ext = {"exe", "dll", "bat", "cmd", "ps1", "psm1", "vbs", "hta", "js", "sys", "msi", "scr",
                 "tmp", "log", "txt", "zip", "rar", "7z", "ini", "cfg", "config", "xml", "json", "aspx", "asp", "php"}
    found_domains = [d for d in re.findall(domain_pattern, decoded_log_str)
                     if d.rsplit(".", 1)[-1].lower() not in _file_ext]
    if found_domains:
        extracted_ioc["domains"] = list(set(found_domains))
        notes.append(f"Extractor: Phát hiện Domain -> {extracted_ioc['domains']}")

    # --- 3. THỢ SĂN URL (Bản Final - Bắt trọn Path & Query Params) ---
    url_pattern = r'https?://[^\s"\']+'
    found_urls = re.findall(url_pattern, decoded_log_str)
    if found_urls:
        extracted_ioc["urls"] = list(set(found_urls))
        notes.append(f"Extractor: Phát hiện URL khả nghi -> {extracted_ioc['urls']}")

    # --- 4. THỢ SĂN BASE64 (Heuristic Warning) ---
    b64_pattern = r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    found_b64 = re.findall(b64_pattern, decoded_log_str)
    if found_b64:
        extracted_ioc["base64_strings"] = list(set(found_b64))
        notes.append(f"Extractor: Cảnh báo! Phát hiện chuỗi có dấu hiệu Base64 Obfuscation.")

    # --- 5. THỢ SĂN PORT ---
    for key in ["dest_port", "port", "destination_port", "dst_port", "network.port"]:
        if key in raw_log:
            extracted_ioc["ports"].append(raw_log[key])
            notes.append(f"Extractor: Ghi nhận truy cập Port -> {raw_log[key]}")
            break

    # --- 6. THỢ SĂN ATTACK INDICATORS (SQLi, RCE, SSRF) ---
    sqli_keywords = [
        "' or ", "' OR ", " or 1=1", " OR 1=1", "union select", "UNION SELECT",
        "admin'--", "' --", "';--", "OR '1'='1", "drop table", "DROP TABLE",
        "1=1--", "' OR '", "xp_cmdshell", "exec(",
        "pg_sleep", "waitfor delay", "sleep(", "randomblob(", "benchmark(",
    ]
    # B4.3c: bỏ "cmd.exe" (có trong vô số log Windows hợp lệ — trước đây gắn nhãn RCE cho 17/40 kịch bản,
    # kể cả admin chạy whoami) và tách "powershell -enc" sang nhãn riêng encoded_command.
    # Nhãn ở đây chỉ là GỢI Ý cho Analyzer, không còn bắt buộc mức HIGH.
    rce_keywords = [
        "nc -e", "/bin/sh", "/bin/bash",
        "wget|", "curl|", "wget |", "curl |", "rce_attempt", "|bash", "|sh"
    ]
    encoded_keywords = ["powershell -enc", "-encodedcommand", "frombase64string"]
    if any(kw in decoded_log_str.lower() for kw in encoded_keywords):
        extracted_ioc["attack_indicators"].append("encoded_command")
        notes.append("Extractor [GỢI Ý]: có lệnh được mã hoá (PowerShell -enc / FromBase64String)")
    ssrf_keywords = [
        "file://", "gopher://", "dict://", "169.254.169.254",
        "metadata.internal", "169.254"
    ]

    for kw in sqli_keywords:
        if kw.lower() in decoded_log_str.lower():
            extracted_ioc["attack_indicators"].append("sql_injection")
            notes.append(f"Extractor [CẢNH BÁO ĐỎ]: Phát hiện dấu hiệu SQL Injection! Keyword: '{kw}'")
            break

    for kw in rce_keywords:
        if kw.lower() in decoded_log_str.lower():
            extracted_ioc["attack_indicators"].append("rce_attempt")
            notes.append(f"Extractor [CẢNH BÁO ĐỎ]: Phát hiện dấu hiệu RCE/Command Injection! Keyword: '{kw}'")
            break

    for kw in ssrf_keywords:
        if kw.lower() in decoded_log_str.lower():
            extracted_ioc["attack_indicators"].append("ssrf_attempt")
            notes.append(f"Extractor [CẢNH BÁO ĐỎ]: Phát hiện dấu hiệu SSRF! Keyword: '{kw}'")
            break

    # --- 7. THỢ SĂN HTTP REQUEST SMUGGLING (CL.TE / TE.CL) ---
    # Dấu hiệu: request có đồng thời Content-Length VÀ Transfer-Encoding
    # → frontend proxy và backend server hiểu body khác nhau → smuggling
    _log_lower = decoded_log_str.lower()
    if "content-length" in _log_lower and "transfer-encoding" in _log_lower:
        extracted_ioc["attack_indicators"].append("http_smuggling")
        notes.append("Extractor [CẢNH BÁO ĐỎ]: Phát hiện HTTP Request Smuggling! Content-Length + Transfer-Encoding đồng thời trong cùng request.")

    # --- 8. THỢ SĂN HEADER INJECTION / INTERNAL HEADER ABUSE ---
    # X-Forwarded-Host trỏ vào internal → bypass access control
    _fwd_host_keywords = [
        "x-forwarded-host: internal", "x-forwarded-host: admin",
        "x-forwarded-host: localhost", "x-forwarded-host: 127.",
        "x-forwarded-host: 0.0.0.0",
    ]
    for kw in _fwd_host_keywords:
        if kw in _log_lower:
            if "header_injection" not in extracted_ioc["attack_indicators"]:
                extracted_ioc["attack_indicators"].append("header_injection")
            notes.append(f"Extractor [CẢNH BÁO ĐỎ]: X-Forwarded-Host trỏ vào địa chỉ nội bộ! Keyword: '{kw}'")
            break

    # Custom internal headers xuất hiện từ external client → privilege probe
    _internal_headers = [
        "x-internal-trace", "x-admin-override", "x-debug-mode",
        "x-bypass-waf", "x-original-url", "x-rewrite-url",
        "x-custom-ip-authorization", "x-internal-request",
    ]
    for h in _internal_headers:
        if h in _log_lower:
            if "header_abuse" not in extracted_ioc["attack_indicators"]:
                extracted_ioc["attack_indicators"].append("header_abuse")
            notes.append(f"Extractor [CẢNH BÁO ĐỎ]: Header nội bộ xuất hiện từ client bên ngoài: '{h}'")
            break

    # --- 9. THỢ SĂN DNS TUNNELING ---
    # Dấu hiệu: subdomain có entropy Shannon cao (>3.5) hoặc hex-only pattern dài
    # → dữ liệu bị encode vào DNS query để exfiltrate ra ngoài
    _event_type_val = str(raw_log.get("event_type", "")).lower()
    _dns_query_val  = str(raw_log.get("query", raw_log.get("dns_query", raw_log.get("dns_name", ""))))
    if "dns" in _event_type_val or _dns_query_val:
        if _dns_query_val and "." in _dns_query_val:
            _subdomain = _dns_query_val.split(".")[0]
            _entropy   = _shannon_entropy(_subdomain)
            _is_hex    = bool(re.match(r'^[0-9a-f]{20,}$', _subdomain, re.I))
            _is_long_b64 = len(_subdomain) > 30 and re.match(r'^[A-Za-z0-9+/=_-]{20,}$', _subdomain)
            if (_entropy > 3.5 and len(_subdomain) > 20) or _is_hex or _is_long_b64:
                extracted_ioc["attack_indicators"].append("dns_tunneling")
                notes.append(
                    f"Extractor [CẢNH BÁO ĐỎ]: Phát hiện DNS Tunneling! "
                    f"Subdomain '{_subdomain[:40]}...' entropy={_entropy:.2f}, len={len(_subdomain)}"
                )

    # --- 10. THỢ SĂN JWT PRIVILEGE ESCALATION ---
    # JWT token với role=admin trong payload → request giả danh admin từ ngoài
    _jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    for _jwt in re.findall(_jwt_pattern, decoded_log_str):
        try:
            _parts = _jwt.split(".")
            if len(_parts) >= 2:
                _pad    = _parts[1] + "=" * (4 - len(_parts[1]) % 4)
                _decoded = base64.b64decode(_pad).decode("utf-8", errors="ignore").lower()
                _admin_claims = [
                    '"role":"admin"', '"role": "admin"', '"sub":"admin"',
                    '"is_admin":true', '"admin":true', '"access_level":"admin"',
                ]
                if any(c in _decoded for c in _admin_claims):
                    extracted_ioc["attack_indicators"].append("jwt_privilege_escalation")
                    notes.append("Extractor [CẢNH BÁO ĐỎ]: JWT mang role ADMIN xuất hiện trong request từ bên ngoài!")
                    break
        except Exception:
            pass

    # --- 11. THỢ SĂN NETWORK SCAN / BRUTE FORCE ---
    _scan_evt_types = {"port_scan", "network_scan", "nmap_scan", "nmap", "masscan"}
    _scan_keywords  = ["nmap", "masscan", "port scan", "portscan", "-ss ", "-sv ",
                       "syn scan", "udp scan", "os detection", "service detection"]
    if _event_type_val in _scan_evt_types:
        if "network_scan" not in extracted_ioc["attack_indicators"]:
            extracted_ioc["attack_indicators"].append("network_scan")
        notes.append("Extractor [CẢNH BÁO ĐỎ]: Phát hiện Network Scan (Nmap/Masscan) qua event_type!")
    else:
        for kw in _scan_keywords:
            if kw in decoded_log_str.lower():
                if "network_scan" not in extracted_ioc["attack_indicators"]:
                    extracted_ioc["attack_indicators"].append("network_scan")
                notes.append(f"Extractor [CẢNH BÁO ĐỎ]: Phát hiện Network Scan keyword: '{kw}'")
                break

    # Brute force: auth_attempt / login_attempt / login_failed → ghi nhận để Analyzer đánh giá
    # _detected_attack_val đến từ trường "detected_attack" được preserve bởi bridge_service
    _detected_attack_val = str(raw_log.get("detected_attack", "")).lower()
    if (_event_type_val in ("auth_attempt", "login_attempt", "brute_force") or
            _detected_attack_val in ("login_failed", "disabled_user_login")):
        if "brute_force_attempt" not in extracted_ioc["attack_indicators"]:
            extracted_ioc["attack_indicators"].append("brute_force_attempt")
        notes.append(
            "Extractor [CẢNH BÁO CAM]: login_failed / auth_attempt — "
            "có thể Brute Force nếu lặp lại từ cùng source IP."
        )

    # --- 12. NHẬN DIỆN SYNTHETIC RAG INTEGRITY EVENT từ ChromaDB Monitor ---
    # Khi ChromaMonitor phát hiện document bị inject, nó tạo event_type="rag_integrity_violation"
    # → đánh dấu trực tiếp để Analyzer không cần LLM suy luận về loại tấn công này.
    _evt = str(raw_log.get("event_type", "")).lower()
    if _evt == "rag_integrity_violation":
        if "rag_poisoning" not in extracted_ioc["attack_indicators"]:
            extracted_ioc["attack_indicators"].append("rag_poisoning")
        notes.append("Extractor [CRITICAL]: Synthetic RAG Integrity Violation event — ChromaDB đã bị inject document lạ!")

    # Đánh giá sơ bộ
    if extracted_ioc["attack_indicators"]:
        notes.append(f"Extractor [TÓM KẾT]: Attack Indicators xác nhận -> {extracted_ioc['attack_indicators']}")
    elif not extracted_ioc["ips"] and not extracted_ioc["domains"] and not extracted_ioc["urls"]:
        notes.append("Extractor: Log sạch, không tìm thấy bằng chứng mạng (IOC) rõ ràng.")

    print(f"[+] Bóc tách thành công: {extracted_ioc}")

    return {
        "extracted_ioc": extracted_ioc,
        "investigation_notes": notes
    }