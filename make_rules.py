import os

# Đường dẫn chuẩn tới thư mục chứa luật
rules_dir = "data/sigma_rules"
os.makedirs(rules_dir, exist_ok=True)

rules = {
    "rce_netcat.yml": """title: "Phát hiện tấn công Command Injection qua Netcat"
status: experimental
description: "Phát hiện payload nc -e /bin/sh bị chèn vào User-Agent nhằm tạo Reverse Shell."
logsource:
    category: webserver
detection:
    selection:
        message|contains: 'nc -e /bin/sh'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1059.004
    - trust_score: 1.0
""",
    "dns_tunneling_jwt.yml": """title: "Phát hiện Tuồn dữ liệu qua DNS (DNS Tunneling)"
status: experimental
description: "Phát hiện các truy vấn TXT chứa chuỗi base64 của JWT Token nhằm exfiltrate dữ liệu."
logsource:
    category: network
detection:
    selection:
        event_type: 'dns_query'
        message|contains: 'TXT'
    payload:
        message|contains: 'ZXlKa'
    condition: selection and payload
level: critical
tags:
    - attack.exfiltration
    - attack.t1048.003
    - trust_score: 1.0
""",
    "ssrf_aws_metadata.yml": """title: "Phát hiện tấn công SSRF nhắm vào AWS Metadata"
status: experimental
description: "Phát hiện hành vi lợi dụng tính năng export PDF để gọi nội bộ đến địa chỉ 169.254.169.254."
logsource:
    category: web_app
detection:
    selection:
        message|contains|all:
            - '/api/v1/tools/export-pdf'
            - '169.254.169.254'
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1190
    - trust_score: 1.0
"""
}

for filename, content in rules.items():
    filepath = os.path.join(rules_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Đã tạo thần tốc: {filepath}")