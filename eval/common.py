"""eval/common.py — helper dùng chung cho mọi script đánh giá.

Không chứa logic nghiệp vụ (đó là việc của eval_golden.py, eval_injection.py...),
chỉ chứa: gọi agent, parse kết quả, các hằng số chung.

Sửa 29/09 (khớp với Agent thật — xem TIEN_DO.md):
  1. extract_prediction đọc đúng schema thật: {"results": [ {...}, ... ]} của /ingest/alerts,
     và dạng phẳng của /analyze. Tên trường thật: severity · mitre_techniques · action_taken.
  2. Bỏ "rule_level" khỏi khoá đọc severity (đó là mức của LUẬT đầu vào, không phải kết luận Agent).
  3. Kịch bản nhiều alert → lấy kết quả ALERT CUỐI (lúc Agent đã thấy cả chuỗi).
     call_agent mặc định gọi /reset trước khi gửi → các kịch bản không nhiễm chéo lịch sử.
  4. Quy đổi nhãn hành động của Agent (IGNORE, ALERT_OPERATOR, BLOCK_IP...) về 4 nhãn ACTIONS.
  5. PROFILES thêm l1 (8011) và l12 (8012) cho 4 dòng Bảng 2.
"""
import os
import time
import requests

# 4 bản agent chạy song song — cổng theo kế hoạch mục 7.3 (+ 2 bản trung gian cho Bảng 2)
PROFILES = {
    "off":  "http://127.0.0.1:8010",   # DEFENSE_PROFILE=off   — đường cũ, không phòng vệ
    "l1":   "http://127.0.0.1:8011",   # DEFENSE_PROFILE=l1    — Lớp 1 (Rule of Two)
    "l12":  "http://127.0.0.1:8012",   # DEFENSE_PROFILE=l12   — Lớp 1 + 2 (spotlighting)
    "full": "http://127.0.0.1:8000",   # DEFENSE_PROFILE=full  — Lớp 1 + 2 + 4
}
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")

SEVERITIES = ["low", "medium", "high", "critical"]
ACTIONS = ["no_action", "monitor", "review", "block"]

# Nhãn hành động của Agent → 4 nhãn ACTIONS.
# Bản `off` giữ nhãn cũ mãi mãi (nó là đường cũ) nên bảng này luôn cần.
# Từ Ngày 4, Responder mới trả thẳng 4 nhãn ACTIONS → đi qua nguyên vẹn.
ACTION_MAP = {
    "ignore": "no_action",
    "none": "no_action",
    "no_action": "no_action",
    "monitor": "monitor",
    "alert_operator": "review",      # báo analyst xem → cần người xem xét
    "review": "review",
    "human_review": "review",
    "throttle": "block",             # bóp băng thông = một dạng ngăn chặn chủ động
    "block_ip": "block",
    "network_block_full": "block",
    "block": "block",
}


def _headers():
    return {"Authorization": f"Bearer {AGENT_TOKEN}"} if AGENT_TOKEN else {}


def reset_agent(profile, timeout=15):
    """Xoá bộ nhớ Agent (timeline, incident, thống kê) — gọi trước mỗi kịch bản/payload
    để Correlator không gộp alert của lần chạy này vào incident của lần trước.
    Trả None nếu OK, chuỗi lỗi nếu không reset được."""
    base = PROFILES.get(profile)
    if base is None:
        raise ValueError(f"profile lạ: {profile}")
    try:
        r = requests.post(f"{base}/reset", headers=_headers(), timeout=timeout)
    except requests.RequestException as e:
        return f"reset lỗi: {type(e).__name__}: {e}"
    return None if r.status_code < 300 else f"reset HTTP {r.status_code}: {r.text[:200]}"


def call_agent(profile, alerts, wait=True, timeout=180, reset_first=True):
    """POST alerts tới /ingest/alerts?wait=true. Trả về dict có 1 trong 2 dạng:
       {"data": <json>, "elapsed": <giây>}      -- thành công
       {"error": "<mô tả>", "elapsed": <giây>}  -- lỗi mạng / HTTP / parse / reset
    reset_first=True (mặc định): gọi /reset trước — mỗi lần gọi là một ca độc lập.
    `elapsed` chỉ tính thời gian phân tích, không tính thời gian reset.
    """
    base = PROFILES.get(profile)
    if base is None:
        raise ValueError(f"profile lạ: {profile}")
    if reset_first:
        err = reset_agent(profile)
        if err:
            return {"error": err, "elapsed": 0.0}
    url = f"{base}/ingest/alerts" + ("?wait=true" if wait else "")
    # Một alert Llama mất ~6–20 s → nới timeout theo số alert
    timeout = max(timeout, 60 * len(alerts))
    t0 = time.time()
    try:
        r = requests.post(url, json={"alerts": alerts},
                          headers=_headers(), timeout=timeout)
    except requests.RequestException as e:
        return {"error": f"{type(e).__name__}: {e}", "elapsed": time.time() - t0}
    elapsed = time.time() - t0
    if r.status_code >= 300:
        return {"error": f"HTTP {r.status_code}: {r.text[:300]}", "elapsed": elapsed}
    try:
        return {"data": r.json(), "elapsed": elapsed}
    except ValueError:
        return {"error": "invalid json", "elapsed": elapsed}


def _first_present(d, keys):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return None


def normalize_action(value):
    """'BLOCK_IP' → 'block', 'ALERT_OPERATOR' → 'review'... Nhãn lạ: giữ nguyên dạng thường."""
    if value is None:
        return None
    v = str(value).strip().lower()
    return ACTION_MAP.get(v, v)


def extract_prediction(raw):
    """Trích severity/attack_ids/action từ kết quả agent.

    Hai dạng Agent trả về:
      - /ingest/alerts?wait=true : {"status": "done", "results": [ {severity, mitre_techniques,
                                    action_taken, status, ...}, ... ]}  — mỗi alert một phần tử
      - /analyze                 : một dict phẳng {severity, mitre_techniques, action_taken, ...}
    Kịch bản nhiều alert → dùng kết quả ALERT CUỐI (Agent đã thấy cả chuỗi).

    Trả thêm (không bắt buộc dùng):
      action_raw   nhãn gốc của Agent trước khi quy đổi
      agent_mode   có từ Ngày 4 (cổng người duyệt) — None nếu chưa có
      target_ip    IP mà hành động nhắm tới — có từ Ngày 4, None nếu chưa có
      n_results    số alert Agent đã trả kết quả
      error        khác None nếu alert cuối bị lỗi phân tích → KHÔNG tính là dự đoán hợp lệ
    """
    out = {"severity": None, "attack_ids": [], "action": None, "action_raw": None,
           "agent_mode": None, "target_ip": None, "n_results": 0, "error": None}
    data = raw.get("data") if isinstance(raw, dict) else None
    if not isinstance(data, dict):
        out["error"] = (raw or {}).get("error") if isinstance(raw, dict) else "không có dữ liệu"
        return out

    if isinstance(data.get("results"), list):
        results = [r for r in data["results"] if isinstance(r, dict)]
        out["n_results"] = len(results)
        if not results:
            out["error"] = "Agent không trả kết quả nào"
            return out
        node = results[-1]                      # alert cuối của kịch bản
        if node.get("status") not in (None, "analyzed"):
            out["error"] = f"alert cuối lỗi: {node.get('detail') or node.get('status')}"
            return out
    else:
        node = data                             # dạng phẳng của /analyze
        out["n_results"] = 1

    # severity: KHÔNG đọc rule_level (đó là mức của luật đầu vào, không phải kết luận của Agent)
    v = _first_present(node, ["severity", "attack_severity"])
    if v is not None:
        out["severity"] = str(v).strip().lower()

    v = _first_present(node, ["mitre_techniques", "attack_ids", "mitre_ids", "techniques"])
    if isinstance(v, list):
        out["attack_ids"] = [str(x).strip() for x in v if str(x).strip()]
    elif isinstance(v, str):
        out["attack_ids"] = [x.strip() for x in v.split(",") if x.strip()]

    v = _first_present(node, ["action_taken", "action", "recommended_action", "decision"])
    if v is not None:
        out["action_raw"] = str(v)
        out["action"] = normalize_action(v)

    v = _first_present(node, ["agent_mode"])
    out["agent_mode"] = str(v).strip().lower() if v is not None else None
    v = _first_present(node, ["action_target_ip", "target_ip"])
    out["target_ip"] = str(v) if v is not None else None
    return out
