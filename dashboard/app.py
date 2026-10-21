"""dashboard/app.py — AegisSOC Command Center (Streamlit).

Bảng điều khiển cho buổi demo và vận hành AegisSOC:
  • Theo dõi HAI bản Agent cùng lúc: full (bật Lớp 1, 2, 4, 5) và off (không phòng thủ) — để trình diễn off ‖ full.
  • Luồng cảnh báo từ Splunk: làn lọc trước (prefilter ML / làn luật) → Agent → hành động.
  • Sự cố đã gộp (Correlator) và chuỗi ATT&CK của từng sự cố.
  • Điều tra một alert: ticket hai ngăn (trusted / untrusted), phán quyết so với mức luật, phòng thủ đã kích hoạt,
    khối toàn vẹn RAG, audit trail.
  • Hàng chờ duyệt (Lớp 1 — Rule of Two): người duyệt chốt đề xuất BLOCK_PENDING. SOAR LUÔN SIMULATION.
  • Phòng thủ & toàn vẹn: trạng thái các lớp, thống kê prefilter, nhật ký toàn vẹn kho RAG.
  • Phát lại alert (dự phòng khi lab/Splunk trục trặc).

An toàn hiển thị: mọi giá trị lấy từ alert (có thể do kẻ tấn công kiểm soát) đều được escape trước khi chèn vào HTML,
trường gốc `fields` chỉ hiển thị bằng st.json/st.code (không render HTML).

Chạy:  streamlit run dashboard/app.py
Biến môi trường (đọc từ .env nếu có; dashboard KHÔNG in giá trị token):
  API_URL_FULL (mặc định http://127.0.0.1:8000) · API_URL_OFF (mặc định http://127.0.0.1:8010)
  AGENT_TOKEN (gửi alert phát lại) · AGENT_INTERNAL_TOKEN (duyệt đề xuất, xem nhật ký toàn vẹn ở bản full)
"""
from __future__ import annotations

import html
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent
try:   # thứ tự tactic theo ma trận ATT&CK Enterprise (chỉ đọc dữ liệu tất định, không gọi LLM)
    import sys as _sys
    if str(ROOT) not in _sys.path:
        _sys.path.insert(0, str(ROOT))
    from core import attack_kb as _K
    TACTIC_ORDER = {t["name"]: i for i, t in enumerate(_K._kb().get("tactics") or [])}
except Exception:
    TACTIC_ORDER = {}
AGENTS = {
    "full": os.getenv("API_URL_FULL", os.getenv("API_URL", "http://127.0.0.1:8000")).rstrip("/"),
    "off": os.getenv("API_URL_OFF", "http://127.0.0.1:8010").rstrip("/"),
}
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")
INTERNAL_TOKEN = os.getenv("AGENT_INTERNAL_TOKEN", "")

LAYER_INFO = {
    1: ("Lớp 1", "Rule of Two", "Lệnh chặn không tự thực thi — chờ người duyệt"),
    2: ("Lớp 2", "Spotlighting", "Dữ liệu alert được datamarking trong prompt"),
    4: ("Lớp 4", "Egress & Sanitizer", "Danh sách trắng gọi ra ngoài, kiểm lệnh SOAR, khoá /internal"),
    5: ("Lớp 5", "Manifest HMAC", "Chỉ dùng tài liệu RAG đã ký + giám sát toàn vẹn kho"),
}
DECISION_LABEL = {
    "keep_rule_level": ("= Giữ mức luật", "#8b949e"),
    "upgrade_one": ("↑ Nâng 1 mức", "#f85149"),
    "downgrade_one": ("↓ Hạ 1 mức", "#d29922"),
    "downgrade_benign": ("↓↓ Hạ về lành tính", "#3fb950"),
}
SEV_COLORS = {"CRITICAL": "#f85149", "HIGH": "#e3904d", "MEDIUM": "#d29922", "LOW": "#3fb950"}
SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
ACTION_LABEL = {
    "BLOCK_PENDING": ("CHỜ DUYỆT", "#d29922"),
    "BLOCK_IP": ("CHẶN IP", "#f85149"),
    "NETWORK_BLOCK_FULL": ("CÔ LẬP MẠNG", "#f85149"),
    "ALERT_OPERATOR": ("BÁO ANALYST", "#58a6ff"),
    "MONITOR": ("THEO DÕI", "#58a6ff"),
    "IGNORE": ("BỎ QUA", "#3fb950"),
    "NONE": ("—", "#484f58"),
}
PF_COLORS = {"DROP": "#3fb950", "DUP": "#8b949e", "PASS_UNCERTAIN": "#d29922", "PASS": "#58a6ff"}

st.set_page_config(page_title="AegisSOC Command Center", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")

# ═══════════════════════════════════════════════════════════════════
# THEME
# ═══════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.stApp { background-color: #0b0f1a; }
[data-testid="stHeader"] { background: transparent !important; }
.block-container { padding-top: 1.1rem !important; }
[data-testid="stSidebar"] { background-color: #0d1117 !important; border-right: 1px solid rgba(255,255,255,0.05); }
h1, h2, h3 { color: #e6edf3 !important; font-weight: 600 !important; }
[data-testid="stMetric"] { background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 8px; padding: 10px 14px; }
[data-testid="stMetricLabel"] { color: #6e7681 !important; font-size: 0.62rem !important; text-transform: uppercase;
    letter-spacing: 0.08em; font-family: 'JetBrains Mono', monospace !important; }
[data-testid="stMetricValue"] { color: #e6edf3 !important; font-size: 1.45rem !important;
    font-family: 'JetBrains Mono', monospace !important; }
.stTabs [data-baseweb="tab-list"] { border-bottom: 1px solid rgba(255,255,255,0.07) !important; gap: 0 !important; }
.stTabs [data-baseweb="tab"] { color: #6e7681 !important; font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.72rem !important; letter-spacing: 0.05em; padding: 8px 18px !important; }
.stTabs [aria-selected="true"] { color: #79c0ff !important; border-bottom: 2px solid #58a6ff !important; }
.stButton > button { border-radius: 6px !important; font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.72rem !important; }
[data-testid="stVerticalBlockBorderWrapper"] { border-color: rgba(255,255,255,0.07) !important;
    border-radius: 8px !important; background: rgba(255,255,255,0.015) !important; }
.mono { font-family: 'JetBrains Mono', monospace; }
.lbl { font-family: 'JetBrains Mono', monospace; font-size: 0.6rem; color: #6e7681; text-transform: uppercase;
    letter-spacing: 0.12em; margin: 4px 0 8px 0; }
.chip { display: inline-block; padding: 1px 9px; border-radius: 4px; font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem; font-weight: 600; letter-spacing: 0.04em; margin: 2px 3px 2px 0; }
.kv { font-family: 'JetBrains Mono', monospace; font-size: 0.74rem; color: #c9d1d9; line-height: 1.9; }
.kv span.k { color: #6e7681; display: inline-block; min-width: 128px; }
.chain { display: flex; flex-wrap: wrap; align-items: stretch; gap: 6px; }
.chain .step { border: 1px solid rgba(255,255,255,0.08); border-left: 3px solid #58a6ff; border-radius: 0 6px 6px 0;
    padding: 6px 10px; background: rgba(255,255,255,0.02); min-width: 150px; }
.chain .arrow { color: #30363d; align-self: center; font-size: 1.1rem; }
.pipe { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; margin: 4px 0 10px 0; }
.pipe .n { font-family: 'JetBrains Mono', monospace; font-size: 0.64rem; padding: 3px 9px; border-radius: 4px;
    border: 1px solid rgba(255,255,255,0.1); color: #c9d1d9; }
.pipe .a { color: #30363d; font-size: 0.8rem; }
.flow { display: flex; flex-wrap: wrap; gap: 6px; align-items: stretch; margin: 2px 0 12px 0; }
.flow .s { border: 1px solid rgba(255,255,255,0.08); border-radius: 6px; padding: 5px 10px;
    background: rgba(255,255,255,0.02); }
.flow .s .t { font-family: 'JetBrains Mono', monospace; font-size: 0.56rem; color: #6e7681;
    text-transform: uppercase; letter-spacing: 0.08em; }
.flow .a { color: #484f58; align-self: center; font-size: 0.95rem; }
.lane { display: grid; gap: 8px; margin: 8px 0 6px 0; }
.lane .col { border-top: 2px solid #d2a8ff; background: rgba(210,168,255,0.03); border-radius: 0 0 6px 6px;
    padding: 6px; }
.lane .hd { font-family: 'JetBrains Mono', monospace; font-size: 0.62rem; color: #d2a8ff; margin-bottom: 6px; }
.lane .ev { border: 1px solid rgba(255,255,255,0.07); border-left: 3px solid #58a6ff; border-radius: 0 5px 5px 0;
    padding: 4px 7px; margin-bottom: 5px; background: rgba(255,255,255,0.02); }
.node { border: 1px solid rgba(255,255,255,0.07); border-left: 3px solid #58a6ff; border-radius: 0 6px 6px 0;
    padding: 6px 12px; margin-bottom: 6px; background: rgba(255,255,255,0.015); }
.node .h { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #e6edf3; font-weight: 600; }
.node .ty { font-family: 'JetBrains Mono', monospace; font-size: 0.58rem; color: #6e7681; margin-left: 8px; }
.node .ln { font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #c9d1d9; line-height: 1.6;
    white-space: pre-wrap; word-break: break-word; }
.llm { border: 1px solid rgba(227,144,77,0.35); border-radius: 6px; padding: 8px 12px; background: rgba(227,144,77,0.04); }
.llm .q { font-size: 0.8rem; color: #e6edf3; line-height: 1.6; }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════
# HTTP
# ═══════════════════════════════════════════════════════════════════
def _hdr(internal: bool = False, agent: bool = False) -> dict:
    h = {}
    if internal and INTERNAL_TOKEN:
        h["X-Internal-Token"] = INTERNAL_TOKEN
    if agent and AGENT_TOKEN:
        h["Authorization"] = f"Bearer {AGENT_TOKEN}"
    return h


def api_get(agent: str, path: str, internal: bool = False, timeout: float = 4.0):
    try:
        r = requests.get(AGENTS[agent] + path, headers=_hdr(internal=internal), timeout=timeout)
        if r.status_code == 200:
            return r.json(), None
        return None, f"HTTP {r.status_code}"
    except Exception as e:
        return None, type(e).__name__


def api_post(agent: str, path: str, body=None, internal=False, agent_tok=False, timeout: float = 10.0):
    try:
        r = requests.post(AGENTS[agent] + path, json=body if body is not None else {},
                          headers=_hdr(internal=internal, agent=agent_tok), timeout=timeout)
        try:
            data = r.json()
        except ValueError:
            data = {"detail": r.text[:300]}
        return r.status_code, data
    except Exception as e:
        return None, {"detail": type(e).__name__}


def load_agent(agent: str) -> dict:
    health, err = api_get(agent, "/health", timeout=3)
    if health is None:
        return {"online": False, "error": err, "health": {}, "recent": [], "prefilter": {}, "decisions": []}
    recent, _ = api_get(agent, "/recent")
    pf, _ = api_get(agent, "/prefilter/recent?limit=200")
    dec, _ = api_get(agent, "/soar/decisions?limit=200")
    return {"online": True, "health": health,
            "recent": (recent or {}).get("results", []),
            "prefilter": pf or {},            # None nếu Agent chạy bản API cũ (chưa có endpoint)
            "decisions": (dec or {}).get("decisions", [])}


# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════
def esc(v) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


def chip(text, color="#8b949e", bg=None) -> str:
    bg = bg or "rgba(255,255,255,0.03)"
    return f"<span class='chip' style='color:{color};border:1px solid {color};background:{bg}'>{esc(text)}</span>"


def sev_chip(sev) -> str:
    s = str(sev or "?").upper()
    return chip(s, SEV_COLORS.get(s, "#8b949e"))


def action_chip(action) -> str:
    a = str(action or "NONE").upper()
    label, color = ACTION_LABEL.get(a, (a, "#8b949e"))
    return chip(label, color)


def lbl(text: str):
    st.markdown(f"<div class='lbl'>◈ {esc(text)}</div>", unsafe_allow_html=True)


def trusted(e: dict) -> dict:
    return ((e.get("ticket") or {}).get("trusted")) or {}


def rule_of(e: dict) -> dict:
    return trusted(e).get("rule") or {}


def rule_name(e: dict) -> str:
    return rule_of(e).get("name") or e.get("event_type") or "?"


def hhmmss(ts: str) -> str:
    return str(ts or "")[11:19] or "—"


def entity_line(t: dict) -> str:
    if t.get("src_ip") or t.get("dest_ip"):
        port = f":{t['dest_port']}" if t.get("dest_port") else ""
        return f"{t.get('src_ip') or '?'} → {t.get('dest_ip') or '?'}{port}"
    return t.get("host") or "—"


def layers_fired(notes: list) -> dict:
    """Lớp nào đã thực sự can thiệp ở alert này (đọc từ audit trail)."""
    out = {}
    for n in notes or []:
        for m in re.finditer(r"Lớp (\d)", n):
            k = int(m.group(1))
            out.setdefault(k, n)
    return out


def pending_undecided(e: dict) -> bool:
    return str(e.get("action_taken", "")).upper() == "BLOCK_PENDING" and not e.get("human_decision")


def render_attack_block(e: dict):
    """B10: chuỗi tactic ATT&CK của sự cố, luật nâng mức (nếu có) và mitigation ATT&CK (M-code)."""
    ch = e.get("attack_chain") or {}
    names = ch.get("tactic_names") or []
    if names:
        st.markdown("<div class='kv'><span class='k'>Chuỗi tactic</span>"
                    + "<span style='color:#30363d'> › </span>".join(chip(n, "#d2a8ff") for n in names)
                    + f" <span style='color:#6e7681'>({ch.get('distinct_tactics', len(names))} tactic)</span></div>",
                    unsafe_allow_html=True)
    esc_ = (e.get("raw_ai_verdict") or {}).get("attack_escalation") or ch.get("escalation")
    if esc_:
        frm = esc_.get("from")
        st.markdown(f"<div class='kv'><span class='k'>Nâng mức ATT&amp;CK</span>"
                    f"{chip(esc_.get('rule', '?'), '#f85149')} "
                    + (f"{esc(str(frm).upper())} → " if frm else "")
                    + f"{esc(str(esc_.get('to') or esc_.get('floor', '')).upper())} — {esc(esc_.get('why', ''))}</div>",
                    unsafe_allow_html=True)
    wv_ = (e.get("raw_ai_verdict") or {}).get("attack_escalation_waived") or ch.get("escalation_waived")
    if wv_ and not esc_:
        st.markdown(f"<div class='kv'><span class='k'>Bỏ qua nâng mức</span>"
                    f"{chip(wv_.get('rule', '?'), '#d29922')} "
                    f"{esc(str(wv_.get('would_floor') or '').upper())} không áp dụng — "
                    f"{esc(wv_.get('why') or 'mẫu: ' + ', '.join(wv_.get('patterns') or []))}</div>",
                    unsafe_allow_html=True)
    mits = e.get("mitigations") or []
    if mits:
        st.markdown("<div class='kv'><span class='k'>Mitigation ATT&amp;CK</span></div>"
                    + "".join(f"<div class='kv' style='margin-left:12px'>{chip(m.get('id'), '#3fb950')} "
                              f"{esc(m.get('name'))} <span style='color:#6e7681'>"
                              f"({esc(', '.join(m.get('techniques') or []))})</span></div>" for m in mits),
                    unsafe_allow_html=True)
    if not (names or esc_ or mits or wv_):
        st.caption("Alert không có mã ATT&CK (hoặc Agent chạy bản chưa có B10).")


# ── Đọc audit trail → quy trình xử lý & chuỗi quyết định ───────────────────────
NODE_META = [   # (khoá trong ghi chú, tên hiển thị, cơ chế, màu)
    ("Prefilter", "① Lọc trước (prefilter)", "tất định / học máy", "#58a6ff"),
    ("Extractor", "② Extractor — trích dấu hiệu", "tất định", "#8b949e"),
    ("Correlator", "③ Correlator — gộp sự cố · tactic ATT&CK · R1/R2", "tất định", "#d2a8ff"),
    ("Enricher", "④ Enricher — tài sản · tình báo · lịch sử", "tất định", "#8b949e"),
    ("Retriever", "⑤ Retriever — tri thức RAG", "tất định", "#8b949e"),
    ("Analyzer", "⑥ Analyzer — LLM suy luận, mã tất định chốt mức", "LLM + tất định", "#e3904d"),
    ("Reflection", "⑦ Reflection — kiểm toán chéo", "LLM", "#e3904d"),
    ("Responder", "⑧ Responder — ma trận ứng phó · Rule of Two", "tất định", "#f85149"),
    ("Khác", "Ghi đè tất định khác", "tất định", "#8b949e"),
]
_NODE_RE = re.compile(r"^\s*\[?(Extractor|Correlator|Enricher|Ticket|Retriever|Analyzer|Reflection|Responder|Human|HITL)\b")
_TACTIC_RE = re.compile(r"Correlator \[ATT&CK\]: [^→\n]*→ tactic (.+?) \((TA\d{4}|\?)\)")
_PROPOSED_RE = re.compile(r"'(BLOCK_IP|NETWORK_BLOCK_FULL)'")
_HOW_RE = re.compile(r"Analyzer \[Quyết định\]: (.+)")


def group_notes(notes: list) -> dict:
    out: dict = {}
    for n in notes or []:
        m = _NODE_RE.match(str(n))
        k = m.group(1) if m else "Khác"
        k = {"Ticket": "Enricher", "Human": "Responder", "HITL": "Responder"}.get(k, k)
        out.setdefault(k, []).append(str(n))
    return out


def event_tactic(e: dict):
    """(tên tactic, mã TA) của alert — đọc từ ghi chú Correlator (tất định)."""
    for n in e.get("investigation_notes") or []:
        m = _TACTIC_RE.search(str(n))
        if m:
            return m.group(1), (m.group(2) if m.group(2) != "?" else "")
    return None, ""


def escalation_of(e: dict):
    return (e.get("raw_ai_verdict") or {}).get("attack_escalation")


def proposed_of(e: dict) -> str:
    m = _PROPOSED_RE.search(" ".join(e.get("investigation_notes") or []))
    return m.group(1) if m else str(e.get("action_taken") or "").upper()


def effective_action(proposed: str, ip: str, host: str) -> str:
    """Hành động THỰC SỰ sẽ làm: alert endpoint không có IP nguồn → cô lập máy, không phải chặn IP."""
    full = str(proposed).upper() == "NETWORK_BLOCK_FULL"
    if ip:
        return f"{'Chặn toàn phần' if full else 'Chặn'} IP {ip}"
    return f"Cô lập máy {host or '?'}" + (" (toàn phần)" if full else "")


def decision_flow_html(e: dict) -> str:
    """Chuỗi quyết định: mức luật → LLM chọn → bảng tất định → luật ATT&CK → ma trận ứng phó → Rule of Two → người duyệt."""
    v = e.get("raw_ai_verdict") or {}
    rl = str(rule_of(e).get("level") or "?").upper()
    final = str(e.get("severity", "?")).upper()
    dec_label, dec_color = DECISION_LABEL.get(v.get("decision"), (v.get("decision") or "—", "#8b949e"))
    esc_ = escalation_of(e)
    wv_ = v.get("attack_escalation_waived") or (e.get("attack_chain") or {}).get("escalation_waived")
    after_table = str(esc_.get("from") if esc_ else final).upper()
    steps = [("Mức luật Splunk", sev_chip(rl)),
             ("LLM chọn", chip(dec_label, dec_color)
              + (f"<span class='mono' style='font-size:0.6rem;color:#6e7681'> tự ước lượng: "
                 f"{esc(str(v.get('severity') or '?').upper())}</span>" if v.get("severity") else "")),
             ("Bảng tất định", sev_chip(after_table))]
    if esc_:
        steps.append((f"ATT&amp;CK {esc(esc_.get('rule'))} (sàn)", sev_chip(str(esc_.get("to")).upper())))
    elif wv_:
        steps.append(("Allowlist ngữ cảnh", chip(f"bỏ qua {wv_.get('rule')}", "#d29922")))
    act = str(e.get("action_taken") or "NONE").upper()
    prop = proposed_of(e)
    t = trusted(e)
    ev = float(e.get("evidence_strength") or 0)
    if act == "BLOCK_PENDING":
        steps.append((f"Ma trận ứng phó · evidence {ev:.2f}", chip(effective_action(prop, t.get("src_ip"), t.get("host")), "#f85149")))
        steps.append(("Rule of Two", action_chip("BLOCK_PENDING")))
        hd = e.get("human_decision")
        if hd:
            steps.append((f"Người duyệt · {esc(hd.get('operator'))}",
                          chip("ĐÃ DUYỆT · MÔ PHỎNG" if hd.get("decision") == "approve" else "TỪ CHỐI",
                               "#3fb950" if hd.get("decision") == "approve" else "#8b949e")))
    else:
        steps.append((f"Ma trận ứng phó · evidence {ev:.2f}", action_chip(act)))
    return ("<div class='flow'>" + "<div class='a'>➜</div>".join(
        f"<div class='s'><div class='t'>{lab}</div>{val}</div>" for lab, val in steps) + "</div>")


def render_process(e: dict):
    """Audit trail theo TỪNG NÚT (thay cho khối chữ thô): mỗi nút một thẻ, đúng thứ tự xử lý."""
    groups = group_notes(e.get("investigation_notes") or [])
    pf = trusted(e).get("prefilter") or {}
    if pf:
        groups["Prefilter"] = [f"Làn {pf.get('lane', '?')} → {pf.get('decision', '?')}"
                               + (f" (p tấn công = {pf['prob']:.3f})" if isinstance(pf.get("prob"), (int, float)) else "")
                               + (f" · {pf.get('reason')}" if pf.get("reason") else "")]
    for key, name, kind, color in NODE_META:
        lines = groups.get(key)
        if not lines:
            continue
        body = ""
        for ln in lines:
            c = ("#f85149" if re.search(r"ATT&CK R\d|CRITICAL OVERRIDE|LỖI", ln)
                 else "#3fb950" if "[Lớp" in ln
                 else "#e3904d" if ("[Thought]" in ln or "[Quyết định]" in ln)
                 else "#d29922" if ("CẢNH BÁO" in ln or "Benign-context" in ln) else "#c9d1d9")
            body += f"<div class='ln' style='color:{c}'>• {esc(ln)}</div>"
        st.markdown(f"<div class='node' style='border-left-color:{color}'><span class='h'>{esc(name)}</span>"
                    f"<span class='ty'>{esc(kind)}</span>{body}</div>", unsafe_allow_html=True)


def build_feed(data: dict) -> pd.DataFrame:
    rows = []
    for e in data["recent"]:
        t = trusted(e)
        pf = t.get("prefilter") or {}
        dec = (e.get("raw_ai_verdict") or {}).get("decision")
        esc_ = escalation_of(e)
        tac, _ta = event_tactic(e)
        rows.append({
            "Thời gian": hhmmss(e.get("received_at")),
            "Luật Splunk": rule_name(e),
            "Tactic": tac or "—",
            "Mức luật": str(rule_of(e).get("level") or "—").upper(),
            "Bề mặt": t.get("surface") or "—",
            "Thực thể": entity_line(t),
            "Prefilter": f"{pf.get('lane', '—')}: {pf.get('decision', '—')}"
                         + (f" (p={pf['prob']:.2f})" if isinstance(pf.get("prob"), (int, float)) else ""),
            "Agent": ("LLM LỖI" if e.get("llm_error") else str(e.get("severity", "?")).upper()),
            "Quyết định": DECISION_LABEL.get(dec, (dec or "—", ""))[0]
                          + (f" → {esc_.get('rule')} ↑{str(esc_.get('to')).upper()}" if esc_ else ""),
            "Hành động": ACTION_LABEL.get(str(e.get("action_taken", "")).upper(), (e.get("action_taken"), ""))[0]
                         + (" ✔ đã duyệt" if (e.get("human_decision") or {}).get("decision") == "approve"
                            else " ✖ từ chối" if (e.get("human_decision") or {}).get("decision") == "reject" else ""),
            "Sự cố": e.get("incident_id", "—"),
            "ms": int(e.get("processing_time_ms") or 0),
            "_ts": e.get("received_at") or "",
        })
    for p in (data.get("prefilter") or {}).get("events", []):
        if p.get("decision") not in ("DROP", "DUP"):
            continue
        _lab = (f"{p.get('lane') or '?'}: DUP" + (f" (của {p['repeat_of']})" if p.get("repeat_of") else "")
                if p.get("decision") == "DUP"
                else (f"ml: DROP (p={p['prob']:.2f})" if isinstance(p.get("prob"), (int, float))
                      else f"{p.get('lane') or 'ml'}: DROP"))
        rows.append({
            "Thời gian": hhmmss(p.get("time")), "Luật Splunk": p.get("rule_name"), "Tactic": "—",
            "Mức luật": str(p.get("rule_level") or "").upper(), "Bề mặt": p.get("surface"),
            "Thực thể": f"{p.get('src_ip') or '?'} → {p.get('dest_ip') or '?'}",
            "Prefilter": _lab,
            "Agent": "không lên", "Quyết định": "—", "Hành động": "—", "Sự cố": "—", "ms": 0,
            "_ts": p.get("time") or "",
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("_ts", ascending=False).drop(columns=["_ts"])
    return df


# ═══════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════
with st.sidebar:
    logo = ROOT / "assets" / "logo.jpg"
    if logo.exists():
        st.image(str(logo), width=80)
    st.markdown("<div style='font-weight:600;color:#e6edf3;font-size:1.05rem'>AegisSOC</div>"
                "<div class='lbl' style='margin-top:0'>Autonomous SOC Agent · MITRE ATT&amp;CK</div>",
                unsafe_allow_html=True)
    st.markdown("---")

    DATA = {a: load_agent(a) for a in AGENTS}
    lbl("Trạng thái Agent")
    for a, d in DATA.items():
        h = d["health"]
        if d["online"]:
            llm_ok = (h.get("llm") or {}).get("reachable")
            layers = h.get("layers") or []
            lay = "".join(chip(LAYER_INFO[k][0], "#3fb950") if k in layers else "" for k in (1, 2, 4, 5)) \
                or chip("không phòng thủ", "#f85149")
            ri = h.get("rag_integrity") or {}
            if 5 in layers and ri.get("manifest_trusted") is False:   # B8.1: fail-closed
                lay += chip(f"RAG FAIL-CLOSED: {ri.get('problem')}", "#f85149")
            st.markdown(
                f"<div class='kv'><b style='color:#e6edf3'>{esc(a.upper())}</b> "
                f"<span style='color:#3fb950'>● online</span> · LLM "
                f"<span style='color:{'#3fb950' if llm_ok else '#f85149'}'>{'OK' if llm_ok else 'LỖI'}</span><br>"
                f"<span class='mono' style='color:#6e7681;font-size:0.65rem'>{esc(AGENTS[a])}</span><br>{lay}</div>",
                unsafe_allow_html=True)
        else:
            st.markdown(f"<div class='kv'><b style='color:#e6edf3'>{esc(a.upper())}</b> "
                        f"<span style='color:#f85149'>● offline</span> "
                        f"<span style='color:#6e7681'>({esc(d['error'])})</span></div>", unsafe_allow_html=True)
    st.markdown("<div class='kv'><span class='k'>SOAR</span>"
                + chip("SIMULATION · KHOÁ", "#d29922") + "</div>", unsafe_allow_html=True)
    st.markdown("---")

    online = [a for a in AGENTS if DATA[a]["online"]] or list(AGENTS)
    view = st.radio("Bản Agent đang xem", online, horizontal=True,
                    format_func=lambda a: {"full": "full (bật phòng thủ)", "off": "off (đường cơ sở)"}[a])
    operator = st.text_input("Người duyệt", value=st.session_state.get("operator", "analyst"), max_chars=60)
    st.session_state["operator"] = operator

    c1, c2 = st.columns(2)
    if c1.button("↺ Reset bản này", use_container_width=True):
        api_post(view, "/reset")
        st.rerun()
    if c2.button("↺ Reset cả hai", use_container_width=True):
        for a in AGENTS:
            api_post(a, "/reset")
        st.rerun()
    auto = st.toggle("Tự làm mới", value=False)
    every = st.slider("Chu kỳ (giây)", 3, 30, 5, disabled=not auto)
    if not INTERNAL_TOKEN:
        st.caption("Chưa có AGENT_INTERNAL_TOKEN → không duyệt được đề xuất / không xem nhật ký toàn vẹn ở bản full.")

D = DATA[view]
H = D["health"]

# ═══════════════════════════════════════════════════════════════════
# HEADER + KPI
# ═══════════════════════════════════════════════════════════════════
prof = str(H.get("defense_profile") or view).upper()
st.markdown(
    f"<div style='display:flex;align-items:center;gap:12px;padding:6px 0 10px 0;"
    f"border-bottom:1px solid rgba(255,255,255,0.05);margin-bottom:14px'>"
    f"<div style='font-size:26px'>🛡️</div><div><div style='font-weight:600;font-size:1.1rem;color:#e6edf3'>"
    f"AEGISSOC COMMAND CENTER</div><div class='lbl' style='margin:2px 0 0 0'>Splunk → Prefilter → Agent "
    f"(LangGraph · Llama 3.1 8B) → SOAR · đang xem bản {esc(prof)}</div></div></div>",
    unsafe_allow_html=True)

if not D["online"]:
    st.error(f"Không kết nối được Agent '{view}' tại {AGENTS[view]} ({D['error']}). Kiểm tra uvicorn đã chạy chưa.")

recent = D["recent"]
pf_counts = (D.get("prefilter") or {}).get("counts", {})
n_drop = sum(v for k, v in pf_counts.items() if k.endswith(":DROP"))
n_unc = sum(v for k, v in pf_counts.items() if k.endswith(":PASS_UNCERTAIN"))
n_recv = sum(pf_counts.values()) if pf_counts else len(recent)
n_pending = sum(1 for e in recent if pending_undecided(e))
incidents = sorted({e.get("incident_id") for e in recent if e.get("incident_id")})
lat = [e.get("processing_time_ms") or 0 for e in recent if not e.get("llm_error")]
k = st.columns(6)
k[0].metric("Alert nhận", n_recv)
k[1].metric("Prefilter DROP", n_drop, help="Alert mạng mà model RF chắc là lành tính — không tốn lượt LLM")
k[2].metric("Agent đã phân tích", len(recent))
k[3].metric("Sự cố (đã gộp)", len(incidents))
k[4].metric("Chờ duyệt", n_pending)
k[5].metric("Độ trễ TB", f"{(sum(lat) / len(lat) / 1000):.1f}s" if lat else "—")
if D["online"] and D.get("prefilter") == {}:
    st.caption("Agent đang chạy bản API chưa có /prefilter/recent — khởi động lại uvicorn để nạp code mới.")

tabs = st.tabs(["LUỒNG CẢNH BÁO", "SỰ CỐ & CHUỖI ATT&CK", "ĐIỀU TRA ALERT", f"HÀNG CHỜ DUYỆT ({n_pending})",
                "PHÒNG THỦ & TOÀN VẸN", "SO SÁNH OFF ‖ FULL", "PHÁT LẠI ALERT"])


# ───────────────────────────────────────────────────────────────────
# 1. LUỒNG CẢNH BÁO
# ───────────────────────────────────────────────────────────────────
with tabs[0]:
    lbl("Mọi alert theo thời gian (mới nhất trên cùng) — gồm cả alert bị prefilter DROP")
    df = build_feed(D)
    if df.empty:
        st.info("Chưa có alert nào. Gửi alert từ Splunk (bridge) hoặc dùng tab PHÁT LẠI ALERT.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True, height=min(560, 38 + 35 * len(df)))
        st.caption("Prefilter: `rule` = làn luật (web/endpoint: gộp trùng + nhiễu kỹ thuật); `ml` = alert mạng được "
                   "Random Forest chấm; `dedup` = bản trùng. Quyết định: LLM chỉ chọn GIỮ / NÂNG / HẠ so với mức luật; "
                   "\"→ R1 ↑CRITICAL\" nghĩa là luật chuỗi tactic ATT&CK (tất định) đã nâng mức sàn, thắng ý kiến LLM. "
                   "Chi tiết từng bước ở tab ĐIỀU TRA ALERT.")


# ───────────────────────────────────────────────────────────────────
# 2. SỰ CỐ & CHUỖI ATT&CK
# ───────────────────────────────────────────────────────────────────
with tabs[1]:
    lbl("Mỗi sự cố = các alert Correlator đã gộp theo thực thể · cột = tactic ATT&CK theo thứ tự ma trận Enterprise")
    groups: dict = {}
    for e in recent:
        groups.setdefault(e.get("incident_id") or "?", []).append(e)
    if not groups:
        st.info("Chưa có sự cố.")
    for inc, evs in sorted(groups.items(), key=lambda kv: max(x.get("received_at", "") for x in kv[1]),
                           reverse=True):
        evs = sorted(evs, key=lambda x: x.get("received_at", ""))
        top = max((str(x.get("severity", "LOW")).upper() for x in evs), key=lambda s_: SEV_ORDER.get(s_, -1))
        techs = []
        for x in evs:
            for t_ in (rule_of(x).get("attack_ids") or x.get("mitre_techniques") or []):
                if t_ not in techs:
                    techs.append(t_)
        hosts = sorted({trusted(x).get("host") for x in evs if trusted(x).get("host")})
        ips = sorted({ip for x in evs for ip in (trusted(x).get("src_ip"), trusted(x).get("dest_ip")) if ip})
        # cột tactic: theo thứ tự ma trận ATT&CK (thiếu dữ liệu ATT&CK → theo thứ tự xuất hiện)
        tac_of = {id(x): event_tactic(x) for x in evs}
        order: list = []
        for x in evs:
            nm = tac_of[id(x)][0] or "Không có mã ATT&CK"
            if nm not in order:
                order.append(nm)
        _first = {nm: i_ for i_, nm in enumerate(order)}
        order.sort(key=lambda nm: (TACTIC_ORDER.get(nm, 99), _first[nm]))
        first_esc = next((x for x in evs if escalation_of(x)), None)
        n_pend = sum(1 for x in evs if pending_undecided(x))
        with st.container(border=True):
            st.markdown(
                f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                f"<div><span class='mono' style='color:#58a6ff;font-size:0.9rem'>SỰ CỐ {esc(inc)}</span> "
                f"&nbsp;{sev_chip(top)} {chip(f'{len(evs)} alert', '#8b949e')} "
                f"{chip(f'{len(order)} tactic', '#d2a8ff')}"
                + (chip(f'{n_pend} chờ duyệt', '#d29922') if n_pend else "") +
                f"</div><div class='mono' style='color:#6e7681;font-size:0.68rem'>"
                f"{esc(hhmmss(evs[0].get('received_at')))} → {esc(hhmmss(evs[-1].get('received_at')))}</div></div>"
                f"<div class='kv' style='margin-top:4px'><span class='k'>Máy</span>{esc(', '.join(hosts) or '—')}"
                f"<br><span class='k'>IP liên quan</span>{esc(', '.join(ips) or '—')}"
                f"<br><span class='k'>Kỹ thuật</span>{''.join(chip(t_, '#58a6ff') for t_ in techs) or '—'}</div>",
                unsafe_allow_html=True)
            if first_esc:
                fe = escalation_of(first_esc)
                st.markdown(
                    f"<div class='kv' style='border-left:3px solid #f85149;padding-left:10px;margin:6px 0'>"
                    f"⚡ <b style='color:#f85149'>{esc(fe.get('rule'))}</b> kích hoạt lúc "
                    f"<b>{esc(hhmmss(first_esc.get('received_at')))}</b> ở alert "
                    f"<b>{esc(rule_name(first_esc))}</b>: {esc(fe.get('why'))} → mức sàn "
                    f"{sev_chip(str(fe.get('to')).upper())} cho các alert từ đó trở đi. "
                    f"<span style='color:#6e7681'>Luật tất định, không phải ý kiến LLM; alert trước đó giữ mức "
                    f"lúc phân tích (không sửa ngược quá khứ).</span></div>", unsafe_allow_html=True)
            # làn tactic
            cols_html = []
            for nm in order:
                ta = next((tac_of[id(x)][1] for x in evs if tac_of[id(x)][0] == nm), "")
                cards = ""
                for x in evs:
                    if (tac_of[id(x)][0] or "Không có mã ATT&CK") != nm:
                        continue
                    sv = str(x.get("severity", "?")).upper()
                    c = SEV_COLORS.get(sv, "#8b949e")
                    ex = escalation_of(x)
                    act = ACTION_LABEL.get(str(x.get("action_taken", "")).upper(), (x.get("action_taken"), ""))[0]
                    cards += (f"<div class='ev' style='border-left-color:{c}'>"
                              f"<div class='mono' style='font-size:0.6rem;color:#6e7681'>{esc(hhmmss(x.get('received_at')))}"
                              + (f" · <span style='color:#f85149'>⚡{esc(ex.get('rule'))}</span>" if ex else "") +
                              f"</div><div style='font-size:0.74rem;color:#e6edf3'>{esc(rule_name(x))}</div>"
                              f"<div class='mono' style='font-size:0.6rem;color:#58a6ff'>"
                              f"{esc(', '.join(rule_of(x).get('attack_ids') or []))}</div>"
                              f"<div class='mono' style='font-size:0.62rem;color:{c}'>{esc(sv)} · {esc(act)}</div></div>")
                cols_html.append(f"<div class='col'><div class='hd'>{esc(nm)} {esc(ta)}</div>{cards}</div>")
            st.markdown(f"<div class='lane' style='grid-template-columns:repeat({len(cols_html)},minmax(160px,1fr))'>"
                        + "".join(cols_html) + "</div>", unsafe_allow_html=True)
            # bảng từng alert: ai quyết định cái gì
            tbl = []
            for x in evs:
                v_ = x.get("raw_ai_verdict") or {}
                ex = escalation_of(x)
                hd = x.get("human_decision") or {}
                tbl.append({
                    "Thời gian": hhmmss(x.get("received_at")),
                    "Tactic": tac_of[id(x)][0] or "—",
                    "Luật": rule_name(x),
                    "Mức luật": str(rule_of(x).get("level") or "—").upper(),
                    "LLM chọn": DECISION_LABEL.get(v_.get("decision"), (v_.get("decision") or "—", ""))[0],
                    "Nâng mức ATT&CK": f"{ex.get('rule')}: {str(ex.get('from')).upper()} → {str(ex.get('to')).upper()}" if ex else "—",
                    "Mức cuối": str(x.get("severity", "?")).upper(),
                    "Hành động": ACTION_LABEL.get(str(x.get("action_taken", "")).upper(), (x.get("action_taken"), ""))[0],
                    "Người duyệt": {"approve": "✔ duyệt", "reject": "✖ từ chối"}.get(hd.get("decision"), "—"),
                })
            with st.expander("Bảng chi tiết từng alert của sự cố (ai quyết định cái gì)"):
                st.dataframe(pd.DataFrame(tbl), use_container_width=True, hide_index=True)
            render_attack_block(evs[-1])


# ───────────────────────────────────────────────────────────────────
# 3. ĐIỀU TRA ALERT
# ───────────────────────────────────────────────────────────────────
def render_decision_buttons(e: dict, key: str, agent: str):
    tid = (e.get("ticket") or {}).get("ticket_id")
    hd = e.get("human_decision")
    if hd:
        color = "#3fb950" if hd.get("decision") == "approve" else "#8b949e"
        st.markdown(f"<div class='kv'>{chip('ĐÃ DUYỆT' if hd.get('decision') == 'approve' else 'ĐÃ TỪ CHỐI', color)}"
                    f" bởi <b>{esc(hd.get('operator'))}</b> lúc {esc(hhmmss(hd.get('time')))}<br>"
                    f"<span class='k'>Kết quả</span>{esc(hd.get('outcome'))}</div>", unsafe_allow_html=True)
        return
    if not pending_undecided(e) or not tid:
        return
    b1, b2 = st.columns(2)
    if b1.button("✔ Duyệt (SIMULATION)", key=f"ap_{key}", type="primary", use_container_width=True):
        code, res = api_post(agent, "/soar/decision", {"ticket_id": tid, "decision": "approve",
                                                      "operator": st.session_state.get("operator", "analyst")},
                             internal=True)
        (st.success if code == 200 else st.error)(res.get("outcome") or res.get("detail"))
        time.sleep(0.8)
        st.rerun()
    if b2.button("✖ Từ chối", key=f"rj_{key}", use_container_width=True):
        code, res = api_post(agent, "/soar/decision", {"ticket_id": tid, "decision": "reject",
                                                      "operator": st.session_state.get("operator", "analyst")},
                             internal=True)
        (st.success if code == 200 else st.error)(res.get("outcome") or res.get("detail"))
        time.sleep(0.8)
        st.rerun()


def render_investigation(e: dict, key: str, agent: str, compact: bool = False):
    t = trusted(e)
    u = (e.get("ticket") or {}).get("untrusted") or {}
    v = e.get("raw_ai_verdict") or {}
    notes = e.get("investigation_notes") or []
    rag = e.get("rag") or {}
    rl = str(rule_of(e).get("level") or "?").upper()
    sev = str(e.get("severity", "?")).upper()
    dec_label, dec_color = DECISION_LABEL.get(v.get("decision"), (v.get("decision") or "—", "#8b949e"))
    fired = layers_fired(notes)

    if e.get("llm_error"):
        st.error(f"LLM lỗi ở alert này — mức/hành động chỉ là giá trị lấp chỗ. {e.get('llm_error_detail', '')[:200]}")

    lbl("Chuỗi quyết định — từ mức luật tới hành động")
    st.markdown(decision_flow_html(e), unsafe_allow_html=True)

    if compact:   # cột hẹp (so sánh off ‖ full): phán quyết trước, ticket thu gọn bên dưới
        c_right = st.container()
        c_left = st.expander("Ticket hai ngăn (trusted / untrusted)")
    else:
        c_left, c_right = st.columns([1, 1.15], gap="large")
    with c_left:
        lbl("Ngăn TRUSTED — dữ liệu đã kiểm (luật Splunk, làm giàu tất định)")
        a_dest = (t.get("asset") or {}).get("dest") or {}
        a_src = (t.get("asset") or {}).get("src") or {}
        ti = ((t.get("threat_intel") or {}).get("src_ip") or {})
        hist = t.get("history") or {}

        def asset_txt(a):
            if not a:
                return "—"
            return (f"{a.get('name', '?')} · {a.get('role', '?')} · {a.get('criticality', '?')}"
                    f" · tự chặn: {'có' if a.get('auto_block_allowed') else 'KHÔNG'}")
        st.markdown(
            f"<div class='kv'><span class='k'>Luật</span>{esc(rule_of(e).get('name'))}"
            f"<br><span class='k'>Mức luật</span>{sev_chip(rl)}"
            f"<br><span class='k'>ATT&amp;CK</span>{''.join(chip(x, '#58a6ff') for x in rule_of(e).get('attack_ids') or []) or '—'}"
            f"<br><span class='k'>Bề mặt</span>{esc(t.get('surface'))}"
            f"<br><span class='k'>Nguồn → đích</span>{esc(entity_line(t))}"
            f"<br><span class='k'>Máy (host)</span>{esc(t.get('host') or '—')}"
            f"<br><span class='k'>Tài sản đích</span>{esc(asset_txt(a_dest))}"
            f"<br><span class='k'>Tài sản nguồn</span>{esc(asset_txt(a_src))}"
            f"<br><span class='k'>Tình báo IP nguồn</span>{esc(ti.get('verdict') or '—')}"
            f"<br><span class='k'>Lịch sử</span>{esc(hist.get('summary') or str(hist.get('event_count', 0)) + ' sự kiện')}"
            f"<br><span class='k'>Sự cố</span>{esc(e.get('incident_id'))} · {esc(t.get('kill_chain_stage') or '')}"
            f"</div>", unsafe_allow_html=True)
        lbl("Ngăn UNTRUSTED — trường gốc của log (kẻ tấn công kiểm soát được)")
        st.caption("Chỉ đưa vào prompt trong khối datamarking (Lớp 2); không bao giờ là chỉ thị.")
        st.json(u.get("fields") or {}, expanded=False)
        if u.get("contract_values_failed_check"):
            st.warning("Có giá trị hợp đồng không qua kiểm định dạng → bị chuyển sang untrusted: "
                       + ", ".join(map(str, u["contract_values_failed_check"].keys())))

    with c_right:
        lbl("Phán quyết của tác tử")
        st.markdown(
            f"<div style='display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-bottom:8px'>"
            f"<div class='kv'><span style='color:#6e7681'>Mức luật</span><br>{sev_chip(rl)}</div>"
            f"<div style='font-size:1.3rem;color:{dec_color}'>➜</div>"
            f"<div class='kv'><span style='color:#6e7681'>Quyết định</span><br>{chip(dec_label, dec_color)}</div>"
            f"<div style='font-size:1.3rem;color:#30363d'>➜</div>"
            f"<div class='kv'><span style='color:#6e7681'>Mức cuối</span><br>{sev_chip(sev)}</div>"
            f"<div class='kv'><span style='color:#6e7681'>Hành động</span><br>{action_chip(e.get('action_taken'))}</div>"
            f"</div>", unsafe_allow_html=True)
        ev_, cf_, tm_ = (f"{float(e.get('evidence_strength') or 0):.2f}", f"{float(e.get('confidence') or 0):.2f}",
                         f"{(e.get('processing_time_ms') or 0) / 1000:.1f}s")
        if compact:
            st.markdown(f"<div class='kv'><span class='k'>Evidence · Conf · Thời gian</span>"
                        f"{ev_} · {cf_} · {tm_}</div>", unsafe_allow_html=True)
        else:
            m1, m2, m3 = st.columns(3)
            m1.metric("Evidence", ev_)
            m2.metric("Confidence", cf_)
            m3.metric("Thời gian", tm_)
        lbl("LLM suy luận (Llama 3.1 8B · trả lời tiếng Anh theo prompt)")
        thought = str(v.get("thought_process") or "").strip()
        reasoning = str(v.get("reasoning") or "").strip()
        tac, ta = event_tactic(e)
        st.markdown(
            "<div class='llm'>"
            + (f"<div class='t lbl' style='margin:0 0 2px 0'>Suy nghĩ từng bước (thought_process)</div>"
               f"<div class='q'>{esc(thought)}</div>" if thought else "")
            + (f"<div class='t lbl' style='margin:8px 0 2px 0'>Kết luận (reasoning)</div>"
               f"<div class='q'>{esc(reasoning)}</div>" if reasoning and reasoning != thought else "")
            + f"<div class='kv' style='margin-top:6px'><span class='k'>LLM tự đánh giá</span>"
              f"{esc(str(v.get('severity') or '?').upper())} · nghi ngờ: {esc(v.get('is_suspicious'))} · "
              f"mã: {esc(', '.join(v.get('mitre') or []) or '—')}</div>"
            + "</div>", unsafe_allow_html=True)
        st.caption("Mức cuối KHÔNG lấy thẳng từ LLM: LLM chỉ chọn giữ/nâng/hạ so với mức luật, mã tất định quy ra mức, "
                   "rồi luật chuỗi tactic ATT&CK (R1/R2) có thể nâng sàn — xem chuỗi quyết định ở trên.")
        if tac:
            st.markdown(f"<div class='kv'><span class='k'>Tactic của alert</span>{chip(f'{tac} {ta}', '#d2a8ff')}</div>",
                        unsafe_allow_html=True)

        lbl("Phòng thủ đã can thiệp ở alert này")
        layers = (DATA[agent]["health"] or {}).get("layers") or []
        row = ""
        for kk, (name, short, _) in LAYER_INFO.items():
            if kk in fired:
                row += chip(f"{name} · {short} ✓", "#3fb950")
            elif kk in layers:
                row += chip(f"{name} · bật", "#6e7681")
            else:
                row += chip(f"{name} · tắt", "#484f58")
        st.markdown(row, unsafe_allow_html=True)
        for kk, n in fired.items():
            st.caption(f"{LAYER_INFO.get(kk, ('Lớp ' + str(kk),))[0]}: {n[:220]}")

        lbl("Khối RAG (tầng truy xuất)")
        inj_in, inj_rej = rag.get("injected_in_context") or [], rag.get("injected_rejected") or []
        if inj_in:
            st.error(f"Tài liệu LẠ đã lọt vào ngữ cảnh: {', '.join(map(str, inj_in))}")
        if inj_rej:
            st.success(f"Lớp 5 đã loại tài liệu ngoài manifest: {', '.join(map(str, inj_rej))}")
        ctx = rag.get("context_ids") or []
        st.markdown("".join(chip(c, "#8b949e") for c in ctx) or "<span class='kv'>—</span>",
                    unsafe_allow_html=True)
        if rag.get("tampered_rejected"):
            st.error(f"Chunk gốc bị SỬA nội dung (băm không khớp manifest) — đã loại: "
                     f"{', '.join(map(str, rag['tampered_rejected']))}")
        if rag.get("integrity_failure"):
            st.error(f"Lớp 5 FAIL-CLOSED ({rag['integrity_failure']}): không dùng tài liệu RAG nào.")

        lbl("Chuỗi MITRE ATT&CK của sự cố & khuyến nghị")
        render_attack_block(e)

        if str(e.get("action_taken", "")).upper() == "BLOCK_PENDING" or e.get("human_decision"):
            lbl("Người duyệt (Lớp 1 — Rule of Two)")
            render_decision_buttons(e, key, agent)

    if not compact:
        lbl("Audit trail theo từng nút — tác tử đã làm gì, theo thứ tự")
        render_process(e)
        with st.expander("Audit trail dạng thô (toàn bộ ghi chú) · JSON phán quyết"):
            st.code("\n".join(notes) or "—", language="text")
            st.json(v)
    else:
        with st.expander("Audit trail theo từng nút"):
            render_process(e)


with tabs[2]:
    if not recent:
        st.info("Chưa có alert đã phân tích.")
    else:
        items = list(reversed(recent))
        labels = [f"{hhmmss(x.get('received_at'))} · {rule_name(x)} · {str(x.get('severity', '?')).upper()} · "
                  f"{(x.get('ticket') or {}).get('ticket_id', '?')}" for x in items]
        idx = st.selectbox("Chọn alert", range(len(items)), format_func=lambda i: labels[i])
        render_investigation(items[idx], key=f"inv_{idx}", agent=view)


# ───────────────────────────────────────────────────────────────────
# 4. HÀNG CHỜ DUYỆT
# ───────────────────────────────────────────────────────────────────
with tabs[3]:
    lbl("Đề xuất chặn/cô lập đang chờ người duyệt — Agent chỉ ĐỀ XUẤT, con người QUYẾT")
    pend = [e for e in reversed(recent) if pending_undecided(e)]
    if not pend:
        st.info("Không có đề xuất nào đang chờ.")
    for i, e in enumerate(pend):
        t = trusted(e)
        v = e.get("raw_ai_verdict") or {}
        a_dest = (t.get("asset") or {}).get("dest") or {}
        with st.container(border=True):
            st.markdown(
                f"<div class='kv'>{sev_chip(e.get('severity'))} <b style='color:#e6edf3'>{esc(rule_name(e))}</b>"
                f" · {esc(entity_line(t))} · sự cố {esc(e.get('incident_id'))} · {esc(hhmmss(e.get('received_at')))}<br>"
                f"<span class='k'>Đề xuất</span><b style='color:#f85149'>"
                f"{esc(effective_action(proposed_of(e), t.get('src_ip'), t.get('host')))}</b>"
                f" <span style='color:#6e7681'>({esc(proposed_of(e))}; SOAR chỉ mô phỏng)</span><br>"
                f"<span class='k'>Vì sao phải duyệt</span>Lớp 1 — Rule of Two: tác tử đọc dữ liệu không tin cậy nên "
                f"không được tự chặn"
                + (f"; tài sản {esc(a_dest.get('name'))} khai <b>không cho tự chặn</b>" if a_dest and not a_dest.get('auto_block_allowed') else "")
                + "</div>", unsafe_allow_html=True)
            st.markdown(decision_flow_html(e), unsafe_allow_html=True)
            if v.get("reasoning") or v.get("thought_process"):
                st.markdown(f"<div class='kv' style='border-left:2px solid #e3904d;padding-left:10px;line-height:1.6'>"
                            f"<span style='color:#6e7681'>LLM:</span> {esc(v.get('reasoning') or v.get('thought_process'))}</div>",
                            unsafe_allow_html=True)
            render_attack_block(e)
            render_decision_buttons(e, key=f"q_{i}", agent=view)
    lbl("Lịch sử quyết định — mỗi dòng là một đề xuất của tác tử đã được người duyệt chốt")
    if D["decisions"]:
        by_tid = {(x.get("ticket") or {}).get("ticket_id"): x for x in recent}
        hist = []
        for d_ in reversed(D["decisions"]):
            x = by_tid.get(d_.get("ticket_id")) or {}
            ex = escalation_of(x) if x else None
            hist.append({
                "Duyệt lúc": hhmmss(d_.get("time")),
                "Alert lúc": hhmmss(x.get("received_at")) if x else "—",
                "Sự cố": d_.get("incident_id") or "—",
                "Luật": rule_name(x) if x else "—",
                "Mức cuối": str(x.get("severity", "?")).upper() if x else "—",
                "Nâng mức": f"{ex.get('rule')} → {str(ex.get('to')).upper()}" if ex else "—",
                "Quyết định": {"approve": "✔ duyệt", "reject": "✖ từ chối"}.get(d_.get("decision"), d_.get("decision")),
                "Người duyệt": d_.get("operator"),
                "Thực thi (mô phỏng)": effective_action(d_.get("proposed"), d_.get("target_ip"), d_.get("target_host")),
                "Kết quả": d_.get("outcome"),
            })
        st.dataframe(pd.DataFrame(hist), use_container_width=True, hide_index=True)
        st.caption("Alert endpoint không có IP nguồn → hành động thực thi là CÔ LẬP MÁY (giả lập), dù ma trận ứng phó "
                   "gọi là BLOCK_IP / NETWORK_BLOCK_FULL. Mọi thực thi ở chế độ SIMULATION.")
    else:
        st.caption("Chưa có quyết định nào.")


# ───────────────────────────────────────────────────────────────────
# 5. PHÒNG THỦ & TOÀN VẸN
# ───────────────────────────────────────────────────────────────────
with tabs[4]:
    lbl("Các lớp phòng thủ theo bản Agent")
    rows = []
    for kk, (name, short, desc) in LAYER_INFO.items():
        r = {"Lớp": f"{name} — {short}", "Tác dụng": desc}
        for a in AGENTS:
            ls = DATA[a]["health"].get("layers") if DATA[a]["online"] else None
            r[a] = "—" if ls is None else ("BẬT" if kk in ls else "tắt")
        rows.append(r)
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    c_pf, c_int = st.columns(2, gap="large")
    with c_pf:
        lbl(f"Làn lọc trước (bản {view})")
        pfe = (D.get("prefilter") or {}).get("events", [])
        if pf_counts:
            st.markdown("".join(chip(f"{k_}: {v_}", PF_COLORS.get(k_.split(':')[-1], "#8b949e"))
                                for k_, v_ in sorted(pf_counts.items())), unsafe_allow_html=True)
        ml = [p for p in pfe if p.get("lane") == "ml"]
        if ml:
            dfp = pd.DataFrame([{"Thời gian": hhmmss(p.get("time")), "Luật": p.get("rule_name"),
                                 "Luồng": f"{p.get('src_ip')} → {p.get('dest_ip')}",
                                 "p(tấn công)": p.get("prob"), "Quyết định": p.get("decision"),
                                 "Ghi chú": p.get("reason") or ""} for p in reversed(ml)])
            st.dataframe(dfp, use_container_width=True, hide_index=True,
                         column_config={"p(tấn công)": st.column_config.ProgressColumn(
                             "p(tấn công)", min_value=0.0, max_value=1.0, format="%.3f")})
            st.caption("Ngưỡng theo chi phí 10:1: DROP nếu p < 0,091; dải bất định 0,091–0,182 → PASS_UNCERTAIN. "
                       "Thiếu số đo luồng → PASS (không bao giờ vì thiếu dữ liệu mà bỏ alert).")
        else:
            st.caption("Chưa có alert mạng nào đi làn ML.")
    with c_int:
        lbl("Giám sát toàn vẹn kho RAG")
        for a in AGENTS:
            if not DATA[a]["online"]:
                continue
            ev, err = api_get(a, "/internal/rag/integrity-events?limit=50", internal=True)
            st.markdown(f"<div class='kv'><b style='color:#e6edf3'>{esc(a.upper())}</b></div>",
                        unsafe_allow_html=True)
            if ev is None:
                st.caption(f"Không đọc được ({err}). Bản full cần AGENT_INTERNAL_TOKEN.")
                continue
            if not ev.get("events"):
                st.caption("Không có sự kiện — kho khớp manifest.")
                continue
            rows = []
            for x in reversed(ev["events"]):
                for d in x.get("docs") or []:
                    rows.append({"Thời gian": hhmmss(x.get("time")), "Phát hiện qua": x.get("via"),
                                 "Tài liệu": d.get("id"), "Lý do": d.get("reason"),
                                 "source_type (tự khai)": d.get("source_type")})
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


# ───────────────────────────────────────────────────────────────────
# 6. SO SÁNH OFF ‖ FULL
# ───────────────────────────────────────────────────────────────────
with tabs[5]:
    lbl("Cùng một alert gửi tới hai bản Agent — kịch bản tấn công vào chính tác tử")
    if not (DATA["full"]["online"] and DATA["off"]["online"]):
        st.info("Cần cả hai bản Agent online (full :8000 và off :8010).")
    else:
        def by_alert(d):
            m = {}
            for x in d["recent"]:
                aid = trusted(x).get("alert_id") or rule_name(x)
                m[aid] = x
            return m
        mf, mo = by_alert(DATA["full"]), by_alert(DATA["off"])
        common = [a for a in mo if a in mf]
        if not common:
            st.info("Chưa có alert nào được gửi tới cả hai bản. Dùng tab PHÁT LẠI ALERT, chọn đích 'cả hai'.")
        else:
            pick = st.selectbox("Alert", list(reversed(common)))
            co, cf = st.columns(2, gap="large")
            with co:
                st.markdown("<div class='kv'><b style='color:#f85149'>OFF — không phòng thủ</b></div>",
                            unsafe_allow_html=True)
                render_investigation(mo[pick], key="cmp_off", agent="off", compact=True)
            with cf:
                st.markdown("<div class='kv'><b style='color:#3fb950'>FULL — Lớp 1, 2, 4, 5</b></div>",
                            unsafe_allow_html=True)
                render_investigation(mf[pick], key="cmp_full", agent="full", compact=True)


# ───────────────────────────────────────────────────────────────────
# 7. PHÁT LẠI ALERT (dự phòng khi lab / Splunk trục trặc)
# ───────────────────────────────────────────────────────────────────
def _alert_files():
    out = []
    for d in (ROOT / "replay" / "demo", ROOT / "aegis-bridge" / "rules" / "base" / "samples"):
        if d.exists():
            out += sorted(p for p in d.rglob("*.json"))
    return out


def _restamp(a: dict) -> dict:
    a = dict(a)
    a["alert_id"] = f"replay:{a.get('alert_id', 'x')}:{uuid.uuid4().hex[:8]}"[:200]
    a["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return a


with tabs[6]:
    lbl("Gửi alert đã lưu (định dạng hợp đồng 10 trường) tới Agent — giống hệt đường Splunk bridge")
    files = _alert_files()
    c_a, c_b = st.columns([2, 1])
    with c_a:
        chosen = st.multiselect("File alert (replay/demo/ và mẫu của bridge)", files,
                                format_func=lambda p: str(p.relative_to(ROOT)))
        pasted = st.text_area("…hoặc dán JSON (một alert, danh sách alert, hoặc {\"alerts\": [...]})", height=120)
    with c_b:
        target = st.radio("Gửi tới", ["full", "off", "cả hai"], horizontal=True)
        restamp = st.checkbox("Đổi alert_id + timestamp hiện tại", value=True,
                              help="Để Correlator coi là sự kiện mới, gộp đúng theo thời gian thực của buổi demo.")
        gap = st.slider("Giãn cách giữa các alert (giây)", 0, 30, 3)
        send = st.button("▶ Gửi", type="primary", use_container_width=True, disabled=not AGENT_TOKEN)
        if not AGENT_TOKEN:
            st.caption("Cần AGENT_TOKEN trong môi trường để gửi.")
    if send:
        alerts = []
        for p in chosen:
            try:
                obj = json.loads(p.read_text(encoding="utf-8"))
                alerts += obj.get("alerts", []) if isinstance(obj, dict) and "alerts" in obj else \
                    (obj if isinstance(obj, list) else [obj])
            except Exception as ex:
                st.error(f"{p.name}: {ex}")
        if pasted.strip():
            try:
                obj = json.loads(pasted)
                alerts += obj.get("alerts", []) if isinstance(obj, dict) and "alerts" in obj else \
                    (obj if isinstance(obj, list) else [obj])
            except Exception as ex:
                st.error(f"JSON dán vào không hợp lệ: {ex}")
        dests = ["full", "off"] if target == "cả hai" else [target]
        prog = st.progress(0.0)
        for i, a in enumerate(alerts):
            a2 = _restamp(a) if restamp else a
            for dst in dests:   # cùng alert_id cho cả hai bản → tab SO SÁNH ghép được
                code, res = api_post(dst, "/ingest/alerts", {"alerts": [a2]}, agent_tok=True)
                st.write(f"{dst}: {a2.get('rule_name')} → HTTP {code} {res.get('status', res.get('detail', ''))}")
            prog.progress((i + 1) / max(1, len(alerts)))
            if gap and i < len(alerts) - 1:
                time.sleep(gap)
        st.success(f"Đã gửi {len(alerts)} alert. Agent phân tích nền — xem kết quả ở LUỒNG CẢNH BÁO "
                   f"(bật Tự làm mới).")


# ═══════════════════════════════════════════════════════════════════
if auto:
    time.sleep(every)
    st.rerun()
