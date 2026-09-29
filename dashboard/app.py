import streamlit as st
import requests
import json
import time
import os
import plotly.express as px

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")
st.set_page_config(
    page_title="KMA SOC Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════════
# THEME
# ═══════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@300;400;500;600&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

.stApp {
    background-color: #0b0f1a;
    background-image:
        radial-gradient(ellipse at 15% 60%, rgba(88,166,255,0.03) 0%, transparent 55%),
        radial-gradient(ellipse at 85% 10%, rgba(248,81,73,0.025) 0%, transparent 55%);
}

.block-container { padding-top: 1.2rem !important; }

[data-testid="stSidebar"] {
    background-color: #0d1117 !important;
    border-right: 1px solid rgba(255,255,255,0.05);
}
[data-testid="stSidebar"] .stMarkdown p {
    color: #484f58;
    font-size: 0.75rem;
    font-family: 'JetBrains Mono', monospace;
}

h1, h2, h3 {
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    color: #e6edf3 !important;
}

[data-testid="stMetric"] {
    background: rgba(255,255,255,0.02);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 8px;
    padding: 12px 16px;
}
[data-testid="stMetricLabel"] {
    color: #484f58 !important;
    font-size: 0.62rem !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-family: 'JetBrains Mono', monospace !important;
}
[data-testid="stMetricValue"] {
    color: #e6edf3 !important;
    font-size: 1.55rem !important;
    font-weight: 600 !important;
    font-family: 'JetBrains Mono', monospace !important;
}

.stButton > button {
    background: transparent !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    color: #8b949e !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.7rem !important;
    padding: 5px 14px !important;
    transition: all 0.15s ease !important;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.stButton > button:hover {
    border-color: rgba(88,166,255,0.4) !important;
    color: #79c0ff !important;
    background: rgba(88,166,255,0.06) !important;
}
.stButton > button[kind="primary"] {
    background: rgba(88,166,255,0.1) !important;
    border-color: rgba(88,166,255,0.4) !important;
    color: #79c0ff !important;
}
.stButton > button[kind="primary"]:hover {
    background: rgba(88,166,255,0.18) !important;
}

.stTextArea textarea {
    background: rgba(255,255,255,0.02) !important;
    border: 1px solid rgba(255,255,255,0.07) !important;
    color: #8b949e !important;
    border-radius: 8px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.74rem !important;
    line-height: 1.65 !important;
}
.stTextArea textarea:focus {
    border-color: rgba(88,166,255,0.35) !important;
    box-shadow: 0 0 0 1px rgba(88,166,255,0.1) !important;
}

.streamlit-expanderHeader {
    background: rgba(255,255,255,0.02) !important;
    border: 1px solid rgba(255,255,255,0.06) !important;
    border-radius: 6px !important;
    color: #484f58 !important;
    font-size: 0.68rem !important;
    font-family: 'JetBrains Mono', monospace !important;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}
.streamlit-expanderContent {
    border: 1px solid rgba(255,255,255,0.05) !important;
    border-top: none !important;
    background: rgba(255,255,255,0.01) !important;
}

.stTabs [data-baseweb="tab-list"] {
    background: transparent !important;
    border-bottom: 1px solid rgba(255,255,255,0.07) !important;
    gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    border: none !important;
    color: #484f58 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.7rem !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    padding: 8px 22px !important;
}
.stTabs [aria-selected="true"] {
    color: #79c0ff !important;
    border-bottom: 2px solid #58a6ff !important;
    background: transparent !important;
}
.stTabs [data-baseweb="tab-panel"] { padding-top: 18px !important; }

.stAlert { border-radius: 6px !important; border-left-width: 3px !important; }
.stWarning  { background: rgba(210,153,34,0.06) !important; border-left-color: #d29922 !important; color: #e3b341 !important; }
.stSuccess  { background: rgba(63,185,80,0.06)  !important; border-left-color: #3fb950 !important; color: #56d364 !important; }
.stError    { background: rgba(248,81,73,0.06)  !important; border-left-color: #f85149 !important; color: #ff7b72 !important; }
.stInfo     { background: rgba(88,166,255,0.06) !important; border-left-color: #58a6ff !important; color: #79c0ff !important; }

[data-testid="stVerticalBlockBorderWrapper"] {
    border-color: rgba(255,255,255,0.07) !important;
    border-radius: 8px !important;
    background: rgba(255,255,255,0.015) !important;
}

[data-testid="stToggle"] label {
    color: #484f58 !important;
    font-size: 0.74rem !important;
    font-family: 'JetBrains Mono', monospace !important;
}

.stCheckbox label {
    color: #8b949e !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.74rem !important;
}

.stCaption  { color: #30363d !important; font-size: 0.66rem !important; font-family: 'JetBrains Mono', monospace !important; }
.stSpinner > div { border-top-color: #58a6ff !important; }

hr { border-color: rgba(255,255,255,0.05) !important; margin: 16px 0 !important; }

.js-plotly-plot .plotly .bg { fill: transparent !important; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════
SEV_COLORS = {"CRITICAL": "#f85149", "HIGH": "#e3904d", "MEDIUM": "#d29922", "LOW": "#3fb950"}
SEV_BG     = {
    "CRITICAL": "rgba(248,81,73,0.1)",
    "HIGH":     "rgba(227,144,77,0.1)",
    "MEDIUM":   "rgba(210,153,34,0.1)",
    "LOW":      "rgba(63,185,80,0.1)",
}

def sev_color(sev: str) -> str:
    return SEV_COLORS.get(str(sev).upper(), "#8b949e")

def sev_bg(sev: str) -> str:
    return SEV_BG.get(str(sev).upper(), "rgba(139,148,158,0.1)")

def badge(sev: str) -> str:
    s = str(sev).upper()
    c, b = sev_color(s), sev_bg(s)
    return (f"<span style='display:inline-block; padding:1px 10px; border-radius:4px; "
            f"border:1px solid {c}; background:{b}; font-family:JetBrains Mono,monospace; "
            f"font-size:0.68rem; font-weight:600; color:{c}; letter-spacing:0.06em;'>{s}</span>")

def sec_label(text: str):
    st.markdown(
        f"<div style='font-family:JetBrains Mono,monospace; font-size:0.6rem; color:#30363d; "
        f"text-transform:uppercase; letter-spacing:0.15em; margin-bottom:10px;'>◈ {text}</div>",
        unsafe_allow_html=True,
    )

def render_timeline(timeline: list):
    if not timeline:
        st.markdown(
            "<div style='font-family:JetBrains Mono,monospace; font-size:0.72rem; color:#30363d; padding:10px 0;'>"
            "No events recorded yet.</div>",
            unsafe_allow_html=True,
        )
        return

    html = "<div>"
    for i, ev in enumerate(timeline):
        ev_sev   = str(ev.get("severity", "unknown")).upper()
        c        = sev_color(ev_sev)
        stage    = str(ev.get("attack_chain_stage", "unknown")).upper()
        ip       = ev.get("source_ip", "N/A")
        ev_type  = ev.get("event_type", "")
        ts_raw   = ev.get("event_timestamp", "")
        ts       = ts_raw[:19] if ts_raw else "—"
        is_last  = (i == len(timeline) - 1)
        border_w = "3px" if is_last else "2px"
        opacity  = "1" if is_last else "0.65"
        bg_alpha = "0.025" if is_last else "0.01"
        border_a = "0.08" if is_last else "0.04"
        # Single-line strings — no newlines in HTML to avoid Streamlit markdown
        # treating indented lines as code blocks
        current_chip = (
            "<span style='font-family:JetBrains Mono,monospace;font-size:0.58rem;color:#484f58;"
            "background:rgba(255,255,255,0.05);border-radius:3px;padding:1px 7px;margin-left:8px'>CURRENT</span>"
            if is_last else ""
        )
        sep = "<span style='color:#30363d'>·</span>"
        sub_html = sep.join(f"<span>{p}</span>" for p in [ip, ev_type, ts] if p)

        # All CSS on one line — multi-line style='...' breaks Streamlit's HTML renderer
        card_style = (
            f"border-left:{border_w} solid {c};"
            f"border-top:1px solid rgba(255,255,255,{border_a});"
            f"border-right:1px solid rgba(255,255,255,{border_a});"
            f"border-bottom:1px solid rgba(255,255,255,{border_a});"
            f"border-radius:0 6px 6px 0;padding:8px 14px;margin:3px 0;"
            f"background:rgba(255,255,255,{bg_alpha});opacity:{opacity}"
        )
        row1 = (
            f"<div style='display:flex;align-items:center'>"
            f"<span style='font-family:JetBrains Mono,monospace;font-size:0.7rem;color:{c};font-weight:600'>{stage}</span>"
            f"{current_chip}"
            f"<span style='margin-left:auto;font-family:JetBrains Mono,monospace;font-size:0.65rem;color:{c};opacity:0.75'>{ev_sev}</span>"
            f"</div>"
        )
        row2 = (
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.61rem;color:#484f58;margin-top:4px;display:flex;gap:10px;flex-wrap:wrap'>"
            f"{sub_html}</div>"
        )
        html += f"<div style='{card_style}'>{row1}{row2}</div>"

        if not is_last:
            html += "<div style='margin-left:12px;color:#21262d;font-size:13px;line-height:1.1'>│</div>"

    html += "</div>"
    st.markdown(html, unsafe_allow_html=True)


def render_verdict(result: dict):
    sev        = result.get("severity", "LOW")
    c          = sev_color(sev)
    b          = sev_bg(sev)
    agent_mode = result.get("agent_mode", "AUTONOMOUS")
    notes      = result.get("investigation_notes", [])
    action     = result.get("action_taken", "NONE")

    # Execution flow banner
    if agent_mode == "AUTONOMOUS":
        st.success("Extractor → Correlator → Retriever → Analyzer → Reflection → **Auto-Responder** ✓")
    else:
        st.error("Pipeline flagged for **HUMAN REVIEW** before responding.")

    # Attack indicator warning (pulled from Extractor notes)
    attack_notes = [n for n in notes if "CẢNH BÁO ĐỎ" in n]
    if attack_notes:
        indicators = []
        for n in attack_notes[:3]:
            if "Keyword:" in n:
                indicators.append(n.split("Keyword:")[-1].strip().strip("'").strip())
            elif "->" in n:
                indicators.append(n.split("->")[-1].strip())
        st.warning(f"**Extractor flagged attack payload:** {' · '.join(indicators)}")

    # Main verdict card
    with st.container(border=True):
        # Header row
        st.markdown(f"""
        <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;'>
            <span style='font-family:JetBrains Mono,monospace; font-size:0.6rem; color:#30363d; text-transform:uppercase; letter-spacing:0.12em;'>AI VERDICT</span>
            <span style='font-family:JetBrains Mono,monospace; font-size:0.6rem; color:#30363d;'>{result.get("processing_time_ms", 0):.0f} ms</span>
        </div>
        """, unsafe_allow_html=True)

        # Severity + incident block
        inc_id     = result.get("incident_id", "N/A")
        chain_stg  = result.get("attack_chain_stage", "unknown").upper()
        st.markdown(f"""
        <div style='display:flex; align-items:center; gap:16px; margin-bottom:14px;'>
            <div style='padding:8px 22px; border:1px solid {c}; border-radius:6px; background:{b}; text-align:center; min-width:96px;'>
                <div style='font-family:JetBrains Mono,monospace; font-size:0.55rem; color:#484f58; text-transform:uppercase; letter-spacing:0.1em;'>SEVERITY</div>
                <div style='font-family:JetBrains Mono,monospace; font-size:1.35rem; font-weight:600; color:{c}; line-height:1.45;'>{sev}</div>
            </div>
            <div>
                <div style='font-family:JetBrains Mono,monospace; font-size:0.55rem; color:#484f58; text-transform:uppercase;'>INCIDENT ID</div>
                <div style='font-family:JetBrains Mono,monospace; font-size:0.85rem; color:#58a6ff; margin-bottom:5px;'>{inc_id}</div>
                <div style='font-family:JetBrains Mono,monospace; font-size:0.6rem; color:#484f58;'>CHAIN STAGE: <span style='color:#8b949e;'>{chain_stg}</span></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Metrics
        m1, m2 = st.columns(2)
        m1.metric("Evidence Strength", f"{result.get('evidence_strength', 0.0):.2f}")
        m2.metric("Confidence",        f"{result.get('confidence', 0.0):.2f}")

        # Reasoning — fallback to thought_process when Llama echoes Field description
        _raw_v = result.get("raw_ai_verdict", {})
        reasoning = _raw_v.get("reasoning", "")
        _BAD = ("Giải thích tư duy", "Phân tích RAG và đối chiếu log")
        if not reasoning or len(reasoning) < 10 or any(s in reasoning for s in _BAD):
            reasoning = _raw_v.get("thought_process", "")
        reasoning = reasoning or "—"
        st.info(f"**Reasoning:** {reasoning}")

        # MITRE tags
        tags = result.get("mitre_techniques", [])
        if tags:
            tag_html = "".join(
                f"<span style='background:rgba(88,166,255,0.08); border:1px solid rgba(88,166,255,0.2); "
                f"border-radius:3px; padding:2px 8px; font-family:JetBrains Mono,monospace; "
                f"font-size:0.68rem; color:#58a6ff; margin:2px;'>{t}</span>"
                for t in tags
            )
            st.markdown(f"""
            <div style='margin-top:6px;'>
                <div style='font-family:JetBrains Mono,monospace; font-size:0.55rem; color:#484f58; text-transform:uppercase; margin-bottom:6px;'>MITRE ATT&amp;CK</div>
                <div style='display:flex; flex-wrap:wrap; gap:3px;'>{tag_html}</div>
            </div>
            """, unsafe_allow_html=True)

        # Action
        action_color = "#f85149" if action in ("BLOCK_IP", "ISOLATE_CONTAINER") else \
                       "#3fb950" if action in ("IGNORE", "NONE") else "#58a6ff"
        st.markdown(f"""
        <div style='border-top:1px solid rgba(255,255,255,0.05); margin-top:12px; padding-top:10px;
                    display:flex; justify-content:space-between; align-items:center;'>
            <span style='font-family:JetBrains Mono,monospace; font-size:0.58rem; color:#30363d; text-transform:uppercase;'>RESPONSE ACTION</span>
            <span style='font-family:JetBrains Mono,monospace; font-size:0.78rem; font-weight:600; color:{action_color};'>▶ {action}</span>
        </div>
        """, unsafe_allow_html=True)

    # XAI section
    with st.expander("XAI — Internal Monologue"):
        thought = result.get("raw_ai_verdict", {}).get("thought_process", "—")
        st.info(thought)
        with st.expander("Raw JSON Verdict", expanded=False):
            st.json(result.get("raw_ai_verdict", {}))

    with st.expander("Audit Trail — Node Log", expanded=False):
        if notes:
            st.code("\n".join(notes), language="bash")
        else:
            st.caption("No logs captured.")

    if result.get("knowledge_conflict"):
        st.warning("⚠️ Knowledge Conflict detected — possible RAG Poisoning attempt.")


# ═══════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════
with st.sidebar:
    logo_path = "assets/logo.jpg"
    if os.path.exists(logo_path):
        st.image(logo_path, width=90)

    st.markdown("""
    <div style='padding:10px 0 4px 0;'>
        <div style='font-family:JetBrains Mono,monospace; font-size:0.6rem; color:#30363d; text-transform:uppercase; letter-spacing:0.14em;'>OPERATOR</div>
        <div style='font-family:Inter,sans-serif; font-weight:600; font-size:1rem; color:#e6edf3; margin-top:2px;'>Hieudeptryyy</div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")

    # --- System status ---
    try:
        health_res = requests.get(f"{API_URL}/health", timeout=2)
        api_ok = health_res.status_code == 200
    except Exception:
        api_ok = False

    # Memory size — dùng /incidents để đồng bộ với Live Feed (cùng nguồn, tránh lệch 1 event)
    mem_size = 0
    try:
        inc_sidebar_res = requests.get(f"{API_URL}/incidents", timeout=2)
        if inc_sidebar_res.status_code == 200:
            mem_size = inc_sidebar_res.json().get("timeline_size", 0)
    except Exception:
        pass

    # SOAR mode
    try:
        with open("dashboard/config.json", "r") as f:
            current_mode = json.load(f).get("SOAR_MODE", "SIMULATION")
    except Exception:
        current_mode = "SIMULATION"
    allow_live = os.getenv("ALLOW_LIVE_MODE", "true").lower() == "true"
    if current_mode == "LIVE" and not allow_live:
        current_mode = "LOCKED"

    ai_color   = "#3fb950" if api_ok else "#f85149"
    ai_label   = "ONLINE"  if api_ok else "OFFLINE"
    soar_color = "#f85149" if current_mode == "LIVE" else ("#d29922" if current_mode == "SIMULATION" else "#8b949e")
    soar_label = current_mode

    st.markdown(f"""
    <div style='background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.06);
                border-radius:8px; padding:12px 14px; font-family:JetBrains Mono,monospace;
                font-size:0.7rem; line-height:2.3;'>
        <div style='font-family:JetBrains Mono,monospace; font-size:0.58rem; color:#30363d;
                    text-transform:uppercase; letter-spacing:0.12em; margin-bottom:6px;'>SYSTEM STATUS</div>
        <div style='display:flex; justify-content:space-between;'>
            <span style='color:#484f58;'>AI CORE</span>
            <span style='color:{ai_color};'>{ai_label}</span>
        </div>
        <div style='display:flex; justify-content:space-between;'>
            <span style='color:#484f58;'>RAG ENGINE</span>
            <span style='color:#3fb950;'>READY</span>
        </div>
        <div style='display:flex; justify-content:space-between;'>
            <span style='color:#484f58;'>SOAR MODE</span>
            <span style='color:{soar_color};'>{soar_label}</span>
        </div>
        <div style='display:flex; justify-content:space-between;'>
            <span style='color:#484f58;'>MEMORY</span>
            <span style='color:#{"58a6ff" if mem_size > 0 else "30363d"};'>{mem_size} events</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    if allow_live:
        is_live = st.toggle("🔥 LIVE MODE (armed)", value=(current_mode == "LIVE"))
        new_mode = "LIVE" if is_live else "SIMULATION"
        if new_mode != current_mode:
            try:
                with open("dashboard/config.json", "w") as f:
                    json.dump({"SOAR_MODE": new_mode}, f)
            except Exception:
                pass
            st.rerun()
    else:
        st.warning("LIVE mode locked by ENV.")

    st.markdown("---")
    st.caption("KMA Autonomous SOC Agent · ATTT")

# ═══════════════════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════════════════
st.markdown("""
<div style='display:flex; align-items:center; gap:12px; padding:16px 0 8px 0;
            border-bottom:1px solid rgba(255,255,255,0.05); margin-bottom:22px;'>
    <div style='width:36px; height:36px; background:rgba(88,166,255,0.08);
                border:1px solid rgba(88,166,255,0.2); border-radius:8px;
                display:flex; align-items:center; justify-content:center; font-size:18px;'>🛡️</div>
    <div>
        <div style='font-family:Inter,sans-serif; font-weight:600; font-size:1.1rem; color:#e6edf3; letter-spacing:0.03em;'>
            KMA UNIFIED SOC COMMAND CENTER
        </div>
        <div style='font-family:JetBrains Mono,monospace; font-size:0.62rem; color:#30363d; letter-spacing:0.12em; text-transform:uppercase; margin-top:2px;'>
            Autonomous Threat Intelligence &amp; Response Platform
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════
# RADAR OVERVIEW
# ═══════════════════════════════════════════════════════════════════
try:
    inc_res = requests.get(f"{API_URL}/incidents", timeout=4)
    inc_data = inc_res.json() if inc_res.status_code == 200 else {}
except Exception:
    inc_data = {}

col_stat1, col_stat2 = st.columns([1, 1.8])
with col_stat1:
    sec_label("Radar Overview")
    st.metric("TOTAL INCIDENTS", inc_data.get("total_incidents", 0))
    total = inc_data.get("total_incidents", 0) or 1
    for label_txt, key, color in [("CRITICAL","critical","#f85149"),("HIGH","high","#e3904d"),
                                   ("MEDIUM","medium","#d29922"),("LOW","low","#3fb950")]:
        count = inc_data.get(key, 0)
        pct   = int(count / total * 100)
        st.markdown(f"""
        <div style='margin:5px 0;'>
            <div style='display:flex; justify-content:space-between; margin-bottom:3px;'>
                <span style='font-family:JetBrains Mono,monospace; font-size:0.66rem; color:{color};'>{label_txt}</span>
                <span style='font-family:JetBrains Mono,monospace; font-size:0.66rem; color:#484f58;'>{count}</span>
            </div>
            <div style='background:rgba(255,255,255,0.04); border-radius:2px; height:3px;'>
                <div style='background:{color}; width:{pct}%; height:3px; border-radius:2px; opacity:0.85;'></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

with col_stat2:
    sec_label("Severity Distribution")
    values = [inc_data.get(k, 0) for k in ("critical","high","medium","low")]
    if sum(values) > 0:
        try:
            # color_discrete_sequence avoids the plotly 6.x colorway lookup bug
            # that causes a pandas partial-init crash via apply_default_cascade
            fig = px.pie(
                names=["CRITICAL","HIGH","MEDIUM","LOW"],
                values=values,
                hole=0.58,
                color_discrete_sequence=["#f85149","#e3904d","#d29922","#3fb950"],
            )
            fig.update_layout(
                margin=dict(t=0, b=0, l=0, r=0), height=190,
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="JetBrains Mono", size=10, color="#484f58"),
                legend=dict(font=dict(size=10, color="#484f58"), bgcolor="rgba(0,0,0,0)"),
                showlegend=True,
            )
            fig.update_traces(textfont=dict(family="JetBrains Mono", size=10))
            st.plotly_chart(fig, use_container_width=True)
        except Exception as chart_err:
            # Fallback: bar chart using only built-in markdown
            st.caption(f"Chart render error: {chart_err}")
            for label_txt, val, color in zip(
                ["CRITICAL","HIGH","MEDIUM","LOW"],
                values,
                ["#f85149","#e3904d","#d29922","#3fb950"],
            ):
                pct = int(val / (sum(values) or 1) * 100)
                st.markdown(f"""
                <div style='margin:4px 0; display:flex; align-items:center; gap:10px;'>
                    <span style='font-family:JetBrains Mono,monospace; font-size:0.65rem; color:{color}; min-width:70px;'>{label_txt}</span>
                    <div style='flex:1; background:rgba(255,255,255,0.04); border-radius:2px; height:4px;'>
                        <div style='background:{color}; width:{pct}%; height:4px; border-radius:2px;'></div>
                    </div>
                    <span style='font-family:JetBrains Mono,monospace; font-size:0.65rem; color:#484f58;'>{val}</span>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.markdown(
            "<div style='font-family:JetBrains Mono,monospace; font-size:0.72rem; color:#30363d; padding:20px 0;'>"
            "No incident data yet.</div>",
            unsafe_allow_html=True,
        )

st.markdown("---")

# ═══════════════════════════════════════════════════════════════════
# INVESTIGATION CONSOLE — two tabs
# ═══════════════════════════════════════════════════════════════════
sec_label("Investigation Console")
tab_single, tab_batch, tab_live = st.tabs(["  SINGLE LOG  ", "  BATCH CHAIN  ", "  LIVE FEED  "])

# ───────────────────────────────────────────────────────────────────
# TAB 1 — SINGLE LOG
# ───────────────────────────────────────────────────────────────────
with tab_single:
    col_in, col_out = st.columns([1, 1.2], gap="large")

    with col_in:
        st.markdown("""
        <div style='font-family:JetBrains Mono,monospace; font-size:0.66rem; color:#484f58;
                    text-transform:uppercase; letter-spacing:0.1em; margin-bottom:10px;'>
            Log Intake · SIEM / Manual
        </div>
        """, unsafe_allow_html=True)

        b1, b2, b3 = st.columns([1.3, 1, 1])
        with b1:
            fetch_btn = st.button("↓ Pull Latest Log", key="single_fetch")
        with b2:
            analyze_btn = st.button("▶ Run Analysis", type="primary", key="single_run")
        with b3:
            reset_btn = st.button("✕ Clear Memory", key="single_reset")

        if reset_btn:
            try:
                requests.post(f"{API_URL}/reset", timeout=5)
                st.success("Memory cleared.")
                time.sleep(0.6)
                st.rerun()
            except Exception:
                st.error("Failed to contact backend.")

        default_log = ""
        if fetch_btn:
            try:
                r = requests.get(f"{API_URL}/stats", timeout=4)
                if r.status_code == 200:
                    events = r.json().get("recent_events", [])
                    if events:
                        default_log = json.dumps(events[-1], indent=2, ensure_ascii=False)
                        st.success("Fetched latest event from memory.")
                    else:
                        st.warning("Memory is empty.")
            except Exception:
                st.error("Backend unreachable.")

        log_input = st.text_area(
            "Paste JSON log:",
            value=default_log,
            height=260,
            placeholder='{\n  "timestamp": "2026-06-17T10:00:00",\n  "source_ip": "10.0.0.5",\n  "event_type": "auth_attempt",\n  "message": "\' OR \'1\'=\'1\'--"\n}',
            key="single_input",
        )

        st.markdown("""
        <div style='font-family:JetBrains Mono,monospace; font-size:0.6rem; color:#30363d; margin-top:6px;'>
            Tip: submit logs in sequence without clearing memory to simulate a chain.
        </div>
        """, unsafe_allow_html=True)

    with col_out:
        st.markdown("""
        <div style='font-family:JetBrains Mono,monospace; font-size:0.66rem; color:#484f58;
                    text-transform:uppercase; letter-spacing:0.1em; margin-bottom:10px;'>
            Agent Verdict
        </div>
        """, unsafe_allow_html=True)

        if analyze_btn:
            if not log_input.strip():
                st.warning("No log data. Paste a log or pull from memory.")
            else:
                with st.spinner("LangGraph pipeline executing…"):
                    try:
                        try:
                            log_dict = json.loads(log_input)
                        except json.JSONDecodeError:
                            log_dict = {"message": log_input, "source_ip": "unknown"}

                        res = requests.post(
                            f"{API_URL}/analyze",
                            json={"raw_log": log_dict},
                            timeout=180,
                        )
                        if res.status_code == 200:
                            result = res.json()
                            render_verdict(result)

                            st.markdown("---")
                            sec_label(f"Attack Kill Chain  ·  {len(result.get('attack_timeline', []))} event(s)")
                            render_timeline(result.get("attack_timeline", []))
                        else:
                            st.error(f"Backend error {res.status_code}: {res.text[:300]}")
                    except Exception as e:
                        st.error(f"Connection error: {e}")

# ───────────────────────────────────────────────────────────────────
# TAB 2 — BATCH CHAIN
# ───────────────────────────────────────────────────────────────────
with tab_batch:
    col_b_in, col_b_out = st.columns([1, 1.2], gap="large")

    with col_b_in:
        st.markdown("""
        <div style='font-family:JetBrains Mono,monospace; font-size:0.66rem; color:#484f58;
                    text-transform:uppercase; letter-spacing:0.1em; margin-bottom:10px;'>
            Batch Log Chain · JSON Array
        </div>
        """, unsafe_allow_html=True)

        example_batch = json.dumps([
            {"timestamp": "2026-06-17T09:00:00", "source_ip": "45.33.22.11",
             "event_type": "web_access", "message": "GET /admin"},
            {"timestamp": "2026-06-17T09:01:30", "source_ip": "45.33.22.11",
             "event_type": "auth_attempt", "message": "username=admin&password=' OR '1'='1'--"},
            {"timestamp": "2026-06-17T09:02:45", "source_ip": "45.33.22.11",
             "event_type": "auth_success", "message": "Login successful"},
        ], indent=2, ensure_ascii=False)

        batch_input = st.text_area(
            "JSON array of logs (chronological order):",
            value="",
            height=290,
            placeholder=example_batch,
            key="batch_input",
        )

        reset_before = st.checkbox("Reset memory before running batch", value=True, key="batch_reset")

        b_run = st.button("▶ Run Batch Analysis", type="primary", key="batch_run")

        st.markdown("""
        <div style='font-family:JetBrains Mono,monospace; font-size:0.6rem; color:#30363d; margin-top:8px; line-height:1.8;'>
            Each log is analyzed sequentially.<br>
            Log N+1 sees the history built by log N.<br>
            Ideal for testing kill chain: recon → exploit → auth_success.
        </div>
        """, unsafe_allow_html=True)

    with col_b_out:
        st.markdown("""
        <div style='font-family:JetBrains Mono,monospace; font-size:0.66rem; color:#484f58;
                    text-transform:uppercase; letter-spacing:0.1em; margin-bottom:10px;'>
            Batch Results
        </div>
        """, unsafe_allow_html=True)

        if b_run:
            if not batch_input.strip():
                st.warning("Paste a JSON array of logs first.")
            else:
                try:
                    logs_list = json.loads(batch_input)
                    if not isinstance(logs_list, list):
                        st.error("Input must be a JSON array [ {...}, {...} ].")
                        st.stop()
                except json.JSONDecodeError as e:
                    st.error(f"JSON parse error: {e}")
                    st.stop()

                with st.spinner(f"Running batch analysis on {len(logs_list)} logs…"):
                    try:
                        batch_res = requests.post(
                            f"{API_URL}/analyze/batch",
                            json={"logs": logs_list, "reset_memory": reset_before},
                            timeout=600,
                        )
                        if batch_res.status_code != 200:
                            st.error(f"Backend error {batch_res.status_code}: {batch_res.text[:300]}")
                            st.stop()

                        batch_data = batch_res.json()
                    except Exception as e:
                        st.error(f"Connection error: {e}")
                        st.stop()

                results_list = batch_data.get("results", [])
                summary      = batch_data.get("batch_summary", {})
                pf_stats     = batch_data.get("pre_filter_stats", {})
                processed    = batch_data.get("processed", 0)
                total_logs   = batch_data.get("total", 0)

                # Pre-filter summary (nếu có)
                if pf_stats:
                    pf_c1, pf_c2, pf_c3 = st.columns(3)
                    pf_c1.metric("Noise dropped", pf_stats.get("noise_dropped", 0),
                                 help="event_type rõ ràng là noise kỹ thuật — bỏ qua ngay")
                    pf_c2.metric("Clean filtered", pf_stats.get("clean_filtered", 0),
                                 help="Extractor không tìm thấy attack indicator — skip LLM")
                    pf_c3.metric("LLM analyzed", pf_stats.get("llm_analyzed", 0),
                                 help="Log thực sự đáng ngờ — đi qua toàn bộ 6-node pipeline")
                    st.markdown("---")

                # Summary mini-cards
                sc1, sc2, sc3, sc4, sc5 = st.columns(5)
                sc1.metric("Total", total_logs)
                sc2.metric("OK",    processed)
                sc3.markdown(f"""
                <div style='padding:10px; background:rgba(248,81,73,0.06); border:1px solid rgba(248,81,73,0.2);
                            border-radius:8px; text-align:center;'>
                    <div style='font-family:JetBrains Mono,monospace; font-size:0.6rem; color:#484f58; text-transform:uppercase;'>CRITICAL</div>
                    <div style='font-family:JetBrains Mono,monospace; font-size:1.3rem; font-weight:600; color:#f85149;'>{summary.get("critical",0)}</div>
                </div>
                """, unsafe_allow_html=True)
                sc4.markdown(f"""
                <div style='padding:10px; background:rgba(227,144,77,0.06); border:1px solid rgba(227,144,77,0.2);
                            border-radius:8px; text-align:center;'>
                    <div style='font-family:JetBrains Mono,monospace; font-size:0.6rem; color:#484f58; text-transform:uppercase;'>HIGH</div>
                    <div style='font-family:JetBrains Mono,monospace; font-size:1.3rem; font-weight:600; color:#e3904d;'>{summary.get("high",0)}</div>
                </div>
                """, unsafe_allow_html=True)
                sc5.markdown(f"""
                <div style='padding:10px; background:rgba(210,153,34,0.06); border:1px solid rgba(210,153,34,0.2);
                            border-radius:8px; text-align:center;'>
                    <div style='font-family:JetBrains Mono,monospace; font-size:0.6rem; color:#484f58; text-transform:uppercase;'>MEDIUM</div>
                    <div style='font-family:JetBrains Mono,monospace; font-size:1.3rem; font-weight:600; color:#d29922;'>{summary.get("medium",0)}</div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown("---")

                # Per-log result rows
                sec_label("Per-Log Results")
                for i, r in enumerate(results_list):
                    if "error" in r:
                        st.error(f"Log #{i+1} — {r['error']}")
                        continue

                    # Log đã bị pre-filter → hiển thị dạng mờ, không mở rộng
                    if r.get("pre_filtered"):
                        _tier = r.get("filter_tier", "clean")
                        _tier_label = "NOISE DROP" if _tier == "noise" else "CLEAN FILTER"
                        _tier_color = "#30363d" if _tier == "noise" else "#484f58"
                        st.markdown(
                            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.62rem;"
                            f"color:{_tier_color};padding:3px 8px;border-left:2px solid {_tier_color};"
                            f"margin:2px 0;opacity:0.6'>"
                            f"Log #{i+1} · {r.get('event_type','?')} · {r.get('source_ip','?')} "
                            f"→ [{_tier_label}] bỏ qua LLM</div>",
                            unsafe_allow_html=True,
                        )
                        continue

                    sev_val    = r.get("severity", "LOW")
                    # Full reasoning — fallback to thought_process when Llama echoes Field description
                    _raw_v_b   = r.get("raw_ai_verdict", {})
                    _r_text    = _raw_v_b.get("reasoning", "")
                    _BAD = ("Giải thích tư duy", "Phân tích RAG và đối chiếu log")
                    if not _r_text or len(_r_text) < 10 or any(s in _r_text for s in _BAD):
                        _r_text = _raw_v_b.get("thought_process", "")
                    ev_type    = _r_text or "—"
                    inc        = r.get("incident_id", "N/A")
                    ev_str     = r.get("evidence_strength", 0.0)
                    action_val = r.get("action_taken", "NONE")
                    notes_val  = r.get("investigation_notes", [])
                    conflict   = r.get("knowledge_conflict", False)

                    attack_flag = any("CẢNH BÁO ĐỎ" in n for n in notes_val)
                    # Single-line HTML — avoids Streamlit markdown parser treating
                    # indented multi-line HTML as a code block (4-space rule)
                    flag_chip_html = (
                        "<span style='background:rgba(248,81,73,0.1);border:1px solid rgba(248,81,73,0.3);"
                        "border-radius:3px;padding:1px 7px;font-family:JetBrains Mono,monospace;"
                        "font-size:0.6rem;color:#f85149;margin-left:8px'>ATTACK PAYLOAD</span>"
                        if attack_flag else ""
                    )

                    with st.expander(f"Log #{i+1}  ·  {sev_val}  ·  {inc}", expanded=(sev_val in ("CRITICAL","HIGH"))):
                        # Single-line HTML string — newlines inside f-string cause
                        # Streamlit's markdown engine to code-block the indented spans
                        st.markdown(
                            f"<div style='display:flex;align-items:center;gap:12px;margin-bottom:10px'>"
                            f"{badge(sev_val)}{flag_chip_html}"
                            f"<span style='font-family:JetBrains Mono,monospace;font-size:0.62rem;"
                            f"color:#484f58;margin-left:auto'>evidence {ev_str:.2f} · {action_val}</span>"
                            f"</div>",
                            unsafe_allow_html=True,
                        )
                        st.info(f"**Reasoning:** {ev_type}")

                        if conflict:
                            st.warning("⚠️ **Knowledge Conflict** — Reflection phát hiện mâu thuẫn LLM vs RAG. Có thể là RAG Poisoning. Pipeline vẫn tiếp tục, kết quả cần SOC Analyst xác nhận.")

                        tags_val = r.get("mitre_techniques", [])
                        if tags_val:
                            t_html = "".join(
                                f"<span style='background:rgba(88,166,255,0.08);border:1px solid rgba(88,166,255,0.2);"
                                f"border-radius:3px;padding:2px 8px;font-family:JetBrains Mono,monospace;"
                                f"font-size:0.65rem;color:#58a6ff;margin:2px'>{t}</span>"
                                for t in tags_val
                            )
                            st.markdown(f"<div style='margin-top:4px'>{t_html}</div>", unsafe_allow_html=True)

                        with st.expander("Audit Trail", expanded=False):
                            if notes_val:
                                st.code("\n".join(notes_val), language="bash")

                # Kill chain summary — không render full ở đây để tránh trùng với Live Feed
                _btl_size = batch_data.get("final_timeline_size", 0)
                if _btl_size > 0:
                    st.markdown("---")
                    sec_label(f"Attack Chain Summary · {_btl_size} event(s) accumulated")
                    st.info("📡 Kill chain đầy đủ hiển thị trong tab **Live Feed** — cùng nguồn `/timeline`, không bị trùng.")

# ───────────────────────────────────────────────────────────────────
# TAB 3 — LIVE FEED (nhận log từ hệ thống bên ngoài đẩy vào)
# ───────────────────────────────────────────────────────────────────
with tab_live:
    # Controls row
    lf_ctrl1, lf_ctrl2, lf_ctrl3 = st.columns([1, 1, 5])
    with lf_ctrl1:
        if st.button("✕ Clear Feed", key="live_clear"):
            try:
                requests.post(f"{API_URL}/reset", timeout=5)
                st.success("Feed cleared.")
                time.sleep(0.5)
                st.rerun()
            except Exception:
                st.error("Backend unreachable.")
    with lf_ctrl2:
        if st.button("⟳ Refresh", key="live_manual_refresh"):
            st.rerun()

    # Auto-refresh toggle — NẰM TRONG tab_live, không ảnh hưởng tab khác
    auto_refresh = st.toggle("🔄 Auto Radar Scan (4s)", value=False, key="live_auto_refresh")

    try:
        lf_res  = requests.get(f"{API_URL}/recent",    timeout=4)
        inc_res = requests.get(f"{API_URL}/incidents", timeout=4)
        tl_res  = requests.get(f"{API_URL}/timeline",  timeout=4)
        lf_data   = lf_res.json()  if lf_res.status_code  == 200 else {"count": 0, "results": []}
        inc_data  = inc_res.json() if inc_res.status_code == 200 else {}
        live_timeline = tl_res.json().get("events", []) if tl_res.status_code == 200 else []
    except Exception:
        lf_data  = {"count": 0, "results": []}
        inc_data = {}
        live_timeline = []

    lf_results   = lf_data.get("results", [])
    lf_total     = lf_data.get("count", 0)
    total_pushed = inc_data.get("total_incidents", lf_total)

    _total_received = inc_data.get("total_received", total_pushed)
    _noise    = inc_data.get("noise_dropped", 0)
    _clean    = inc_data.get("clean_filtered", 0)
    _pending  = inc_data.get("pending_analysis", 0)
    _llm_cnt  = inc_data.get("total_incidents", lf_total)

    if lf_total == 0 and _total_received == 0:
        st.markdown(
            "<div style='font-family:JetBrains Mono,monospace; font-size:0.8rem; color:#30363d; "
            "padding:40px 0; text-align:center;'>Đang chờ log từ hệ thống bên ngoài…<br>"
            "<span style='font-size:0.65rem;'>Bật Auto Radar Scan hoặc bấm ⟳ Refresh để cập nhật</span></div>",
            unsafe_allow_html=True,
        )
    elif lf_total == 0:
        # Đã nhận logs nhưng không có LLM result trong buffer
        if _pending > 0:
            st.info(f"🔄 **{_pending}** log đang được LLM phân tích... Bấm ⟳ Refresh sau vài giây.")
        if _llm_cnt > 0:
            # LLM đã chạy nhưng buffer chưa cập nhật (vừa reset hoặc edge case)
            st.warning(
                f"⚠️ **{_total_received}** log đã nhận · **{_llm_cnt}** đã qua LLM.  "
                f"⬇ {_noise} noise dropped · ✓ {_clean} clean (no indicator).  "
                f"Bấm ⟳ Refresh để tải kết quả."
            )
        else:
            st.info(
                f"✅ **{_total_received}** log đã nhận — tất cả bị pre-filter trước LLM.  "
                f"⬇ {_noise} noise dropped · ✓ {_clean} clean (no indicator).  "
                f"Không có mối đe dọa nào đủ điều kiện phân tích sâu."
            )
        # Kill chain vẫn hiện nếu timeline có dữ liệu
        if live_timeline:
            _lf_attack_evs = [e for e in live_timeline if str(e.get("severity", "low")).lower() in ("high", "critical")]
            st.markdown("---")
            sec_label(f"Final Attack Chain · {len(live_timeline)} tổng events · {len(_lf_attack_evs)} attack events được xác nhận")
            render_timeline(live_timeline)
    else:
        # Dùng GLOBAL_INCIDENT_STATS (cùng nguồn với RADAR) thay vì đếm từ RECENT buffer
        # → đảm bảo count cards luôn nhất quán với Radar Overview
        lf_sev = {
            "CRITICAL": inc_data.get("critical", 0),
            "HIGH":     inc_data.get("high", 0),
            "MEDIUM":   inc_data.get("medium", 0),
            "LOW":      inc_data.get("low", 0),
        }

        if _pending > 0:
            st.info(f"🔄 **{_pending}** log đang được LLM phân tích... Bấm ⟳ Refresh sau vài giây.")

        lf_s1, lf_s2, lf_s3, lf_s4, lf_s5 = st.columns(5)
        lf_s1.metric(
            "Nhận được",
            _total_received,
            help=f"LLM phân tích: {_llm_cnt} · Filtered: {_noise + _clean} (noise: {_noise}, clean: {_clean})"
        )
        lf_s2.markdown(
            f"<div style='padding:10px;background:rgba(248,81,73,0.06);border:1px solid rgba(248,81,73,0.2);border-radius:8px;text-align:center'>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;color:#484f58;text-transform:uppercase'>CRITICAL</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:1.3rem;font-weight:600;color:#f85149'>{lf_sev['CRITICAL']}</div></div>",
            unsafe_allow_html=True)
        lf_s3.markdown(
            f"<div style='padding:10px;background:rgba(227,144,77,0.06);border:1px solid rgba(227,144,77,0.2);border-radius:8px;text-align:center'>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;color:#484f58;text-transform:uppercase'>HIGH</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:1.3rem;font-weight:600;color:#e3904d'>{lf_sev['HIGH']}</div></div>",
            unsafe_allow_html=True)
        lf_s4.markdown(
            f"<div style='padding:10px;background:rgba(210,153,34,0.06);border:1px solid rgba(210,153,34,0.2);border-radius:8px;text-align:center'>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;color:#484f58;text-transform:uppercase'>MEDIUM</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:1.3rem;font-weight:600;color:#d29922'>{lf_sev['MEDIUM']}</div></div>",
            unsafe_allow_html=True)
        lf_s5.markdown(
            f"<div style='padding:10px;background:rgba(63,185,80,0.06);border:1px solid rgba(63,185,80,0.2);border-radius:8px;text-align:center'>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;color:#484f58;text-transform:uppercase'>LOW / CLEAN</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:1.3rem;font-weight:600;color:#3fb950'>{lf_sev['LOW']}</div></div>",
            unsafe_allow_html=True)

        if _noise + _clean > 0:
            st.markdown(
                f"<div style='font-family:JetBrains Mono,monospace; font-size:0.62rem; "
                f"color:#484f58; margin:6px 0 2px 0; padding:6px 10px; "
                f"background:rgba(255,255,255,0.02); border-radius:6px;'>"
                f"Pre-filter: "
                f"<span style='color:#d29922'>⬇ {_noise} noise dropped</span>"
                f"<span style='color:#30363d'> · </span>"
                f"<span style='color:#3fb950'>✓ {_clean} clean (no indicator)</span>"
                f"<span style='color:#30363d'> · </span>"
                f"<span style='color:#58a6ff'>🔬 {_llm_cnt} LLM analyzed</span></div>",
                unsafe_allow_html=True)

        st.markdown("---")
        sec_label("Kết quả phân tích từng log (mới nhất ở trên)")

        for _r in reversed(lf_results):
            _sev      = str(_r.get("severity", "LOW")).upper()
            _src_ip   = _r.get("source_ip", "N/A")
            _ev_type  = _r.get("event_type", "unknown")
            _recv_at  = _r.get("received_at", "")[:19]
            _action   = _r.get("action_taken", "NONE")
            _ev_str   = _r.get("evidence_strength", 0.0)
            _notes    = _r.get("investigation_notes", [])
            _chain    = _r.get("attack_chain_stage", "").upper()

            _attack_flag = any("CẢNH BÁO ĐỎ" in n for n in _notes)
            _flag_chip = (
                "<span style='background:rgba(248,81,73,0.1);border:1px solid rgba(248,81,73,0.3);"
                "border-radius:3px;padding:1px 7px;font-family:JetBrains Mono,monospace;"
                "font-size:0.6rem;color:#f85149;margin-left:8px'>ATTACK PAYLOAD</span>"
                if _attack_flag else ""
            )

            with st.expander(
                f"{_recv_at}  ·  {_src_ip}  ·  {_ev_type}  →  {_sev}",
                expanded=(_sev in ("CRITICAL", "HIGH"))
            ):
                st.markdown(
                    f"<div style='display:flex;align-items:center;gap:12px;margin-bottom:10px'>"
                    f"{badge(_sev)}{_flag_chip}"
                    f"<span style='font-family:JetBrains Mono,monospace;font-size:0.62rem;"
                    f"color:#484f58;margin-left:auto'>{_chain} · evidence {_ev_str:.2f} · {_action}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

                _raw_verdict = _r.get("raw_ai_verdict", {})
                _reasoning = _raw_verdict.get("reasoning", "")
                _BAD = ("Giải thích tư duy", "Phân tích RAG và đối chiếu log")
                if not _reasoning or len(_reasoning) < 10 or any(s in _reasoning for s in _BAD):
                    _reasoning = _raw_verdict.get("thought_process", "")
                _reasoning = _reasoning or "—"
                st.info(f"**Reasoning:** {_reasoning}")

                _tags = _r.get("mitre_techniques", [])
                if _tags:
                    _t_html = "".join(
                        f"<span style='background:rgba(88,166,255,0.08);border:1px solid rgba(88,166,255,0.2);"
                        f"border-radius:3px;padding:2px 8px;font-family:JetBrains Mono,monospace;"
                        f"font-size:0.65rem;color:#58a6ff;margin:2px'>{t}</span>"
                        for t in _tags
                    )
                    st.markdown(f"<div style='margin-top:4px'>{_t_html}</div>", unsafe_allow_html=True)

                if _r.get("knowledge_conflict"):
                    st.warning("⚠️ Knowledge Conflict — có thể là RAG Poisoning.")

                with st.expander("Audit Trail", expanded=False):
                    if _notes:
                        st.code("\n".join(_notes), language="bash")

            st.divider()

        # Final Attack Chain — fetch LIVE từ /timeline (cùng nguồn với Batch Chain tab)
        if live_timeline:
            _lf_attack_evs = [e for e in live_timeline if str(e.get("severity", "low")).lower() in ("high", "critical")]
            st.markdown("---")
            sec_label(f"Final Attack Chain · {len(live_timeline)} tổng events · {len(_lf_attack_evs)} attack events được xác nhận")
            render_timeline(live_timeline)

    # Auto-refresh ở cuối tab_live — chỉ rerun khi đang bật, không ảnh hưởng tab khác
    if st.session_state.get("live_auto_refresh", False):
        time.sleep(4)
        st.rerun()
