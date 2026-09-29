import logging
import os
import secrets
import time
import threading
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header, Query, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from typing import Optional
from dotenv import load_dotenv
load_dotenv()  # Load .env TRƯỚC KHI import graph để OLLAMA_BASE_URL sẵn sàng

# ==========================================
# CẤU HÌNH LOGGING
# ==========================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Ngăn ChromaMonitor thread và FastAPI thread pool chạy analyze_log đồng thời
# → tránh SQLite deadlock khi 2 PersistentClient mở cùng lúc
_analysis_lock = threading.Lock()

# ==========================================
# IMPORT GRAPH
# ==========================================
from core.graph import soc_app as langgraph_app
from agent.nodes.extractor import node_extractor  # Pre-filter tier 1
from agent.nodes.retriever import retriever_instance  # dùng chung PersistentClient
from agent.chroma_lock import chroma_lock as _chroma_lock  # serialize mọi ChromaDB op
from agent.nodes.responder import (
    execute_network_block_full as _exec_block_full,
    execute_block_ip as _exec_block_ip,
    execute_alert_telegram as _exec_alert,
    get_soar_mode as _get_soar_mode,
)
from api.alert_adapter import Alert, to_legacy_raw_log  # B1: hợp đồng alert + giàn giáo alert → raw_log
from core import profile as defense_profile  # B4: công tắc DEFENSE_PROFILE (off / l1 / l12 / full)

for _msg in defense_profile.startup_messages():
    if "CẢNH BÁO" in _msg:
        logger.warning(_msg)
    else:
        logger.info(_msg)


# ==========================================
# KHỞI TẠO APP & BỘ NHỚ TOÀN CỤC
# ==========================================
app = FastAPI(title="KMA SOC AI Agent API", version="2.3")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # friend's system on Tailscale
    allow_methods=["*"],
    allow_headers=["*"],
)

# TODO Week Final: Replace in-memory list with Redis/SQLite for production persistence.
GLOBAL_TIMELINE_MEMORY = []
MAX_TIMELINE_SIZE = 500
_timeline_lock = threading.Lock()   # bảo vệ GLOBAL_TIMELINE_MEMORY khỏi race condition
_batch_context = threading.local()  # flag per-thread để phân biệt batch call vs live call

# ==========================================
# CHROMADB INTEGRITY MONITOR (Phase 3 defense)
# Chạy background — poll ChromaDB mỗi 30s để phát hiện document mới
# được inject từ bên ngoài (RAG Poisoning). Nếu phát hiện → tạo
# synthetic log event và đẩy qua pipeline để agent tự cảnh báo.
# ==========================================
_CHROMA_MONITOR_INTERVAL = 30          # giây
_KNOWN_DOC_IDS: set = set()            # track IDs đã biết
_TRUSTED_SOURCE_TYPES = {"admin_sigma_rule", "mitre_framework"}

def _chroma_monitor_loop():
    """Background thread: phát hiện document lạ inject vào ChromaDB.
    Dùng retriever_instance.db (PersistentClient duy nhất) + _chroma_lock để serialize.
    """
    db = retriever_instance.db
    logger.info("[ChromaMonitor] Khởi động thành công.")

    # Baseline: chỉ fetch IDs — tránh load toàn bộ collection
    try:
        with _chroma_lock:
            all_existing = db.get(include=[])
        for doc_id in all_existing.get("ids", []):
            _KNOWN_DOC_IDS.add(doc_id)
        logger.info(f"[ChromaMonitor] Baseline: {len(_KNOWN_DOC_IDS)} documents tin cậy.")
    except Exception as e:
        logger.warning(f"[ChromaMonitor] Không thể lấy baseline: {e}")

    while True:
        time.sleep(_CHROMA_MONITOR_INTERVAL)
        try:
            # Bước 1: fetch IDs (nhanh) trong lock
            with _chroma_lock:
                id_result   = db.get(include=[])
                current_ids = set(id_result.get("ids", []))
                new_ids     = current_ids - _KNOWN_DOC_IDS
                if not new_ids:
                    continue
                # Bước 2: fetch metadata chỉ của doc mới — vẫn trong cùng lock
                meta_result   = db.get(ids=list(new_ids), include=["metadatas"])

            current_metas = {
                did: meta
                for did, meta in zip(
                    meta_result.get("ids", []),
                    meta_result.get("metadatas", [{}] * len(meta_result.get("ids", [])))
                )
            }

            # Có document mới — kiểm tra xem có đáng ngờ không
            suspicious_new = []
            for did in new_ids:
                meta  = current_metas.get(did, {})
                src   = meta.get("source_type", "")
                inj   = meta.get("injected_by", "")
                dtype = meta.get("document_type", "")
                suspicious = (
                    src not in _TRUSTED_SOURCE_TYPES
                    or inj not in (None, "", "sigma_ingest", "mitre_ingest", "admin_loader")
                    or dtype in ("policy_update", "sync_update")
                )
                if suspicious:
                    suspicious_new.append({"id": did, "source_type": src,
                                           "injected_by": inj, "document_type": dtype,
                                           "trust_score": meta.get("trust_score", 0),
                                           "source_ip": meta.get("source_ip", "N/A")})
                _KNOWN_DOC_IDS.add(did)  # đánh dấu đã biết dù suspicious

            if suspicious_new:
                logger.warning(
                    f"[ChromaMonitor] PHÁT HIỆN {len(suspicious_new)} document nghi ngờ: {suspicious_new}"
                )
                # Tạo synthetic security event → đẩy vào pipeline
                synthetic_log = {
                    "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "source_ip":  suspicious_new[0].get("source_ip", "N/A"),
                    "event_type": "rag_integrity_violation",
                    "message":    (
                        f"ChromaDB RAG Poisoning detected: {len(suspicious_new)} "
                        f"unauthorized document(s) injected. "
                        f"IDs: {[d['id'] for d in suspicious_new]}. "
                        f"Sources: {[d['source_type'] for d in suspicious_new]}."
                    ),
                    "suspicious_docs": suspicious_new,
                    "severity_hint":   "critical",
                }
                try:
                    # Gọi trực tiếp hàm trong module này (không import vòng)
                    _synthetic_input = LogInput(raw_log=synthetic_log)
                    analyze_log(_synthetic_input)
                    logger.info("[ChromaMonitor] Synthetic event đã được đẩy vào pipeline.")
                except Exception as push_err:
                    logger.error(f"[ChromaMonitor] Không thể push synthetic event: {push_err}")

        except Exception as poll_err:
            logger.warning(f"[ChromaMonitor] Lỗi poll: {poll_err}")

# GÓP Ý 2: BIẾN LƯU THỐNG KÊ INCIDENT ĐỂ DASHBOARD VẼ BIỂU ĐỒ
GLOBAL_INCIDENT_STATS = {
    "total_incidents": 0,   # LLM-analyzed logs
    "total_received": 0,    # Tất cả logs nhận được (kể cả pre-filtered)
    "noise_dropped": 0,     # Tier 0: obvious noise bị drop
    "clean_filtered": 0,    # Tier 1: clean (không có attack indicator)
    "pending_analysis": 0,  # Đang chờ LLM xử lý
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
}

# LIVE FEED: lưu tối đa 50 kết quả phân tích gần nhất để dashboard poll
RECENT_ANALYSIS_RESULTS: List[Dict[str, Any]] = []
MAX_RECENT_RESULTS = 50

# IP ACTIVITY LOG: track mọi IP xuất hiện (kể cả noise/clean-filtered)
# Đảm bảo IP đã từng thấy trong batch không bị clean-filter lần 2 → luôn vào LLM
IP_ACTIVITY_LOG: Dict[str, int] = {}

# IP ESCALATION: đếm số lần HIGH/CRITICAL mỗi IP → tự động leo thang CRITICAL sau ngưỡng
_IP_HIGH_COUNT: Dict[str, int] = {}
_IP_ESCALATION_THRESHOLD = 5  # sau 5 HIGH từ cùng IP → force CRITICAL + NETWORK_BLOCK_FULL
_SOAR_EXECUTED_IPS: set = set()  # tránh gọi iptables/Telegram nhiều lần cho cùng 1 IP

# ==========================================
# MODEL DỮ LIỆU
# ==========================================
class LogInput(BaseModel):
    raw_log: Dict[str, Any] = Field(..., description="Cục Log JSON từ SIEM/Dashboard")
    # B1: alert gốc (chỉ có khi đi qua /ingest/alerts). /analyze cũ không gửi → None.
    alert: Optional[Dict[str, Any]] = Field(default=None, description="Alert gốc theo hợp đồng Splunk")

class BatchLogInput(BaseModel):
    logs: List[Dict[str, Any]] = Field(..., description="Danh sách log JSON theo thứ tự thời gian")
    reset_memory: bool = Field(default=False, description="Reset memory trước khi xử lý batch")

class AnalysisResponse(BaseModel):
    incident_id: str
    severity: str
    confidence: float
    evidence_strength: float
    mitre_techniques: List[str]
    action_taken: str
    agent_mode: str
    knowledge_conflict: Optional[bool] = False
    attack_chain_stage: str
    attack_timeline: List[Dict[str, Any]]
    raw_ai_verdict: Dict[str, Any]
    investigation_notes: List[str]
    processing_time_ms: float
    # Ngày 2: kết quả làm giàu tất định (tài sản · tình báo IP · lịch sử) — rỗng nếu graph không có
    enrichment: Dict[str, Any] = Field(default_factory=dict)

# ==========================================
# STARTUP: KHỞI ĐỘNG BACKGROUND MONITOR
# ==========================================
@app.on_event("startup")
def start_chroma_monitor():
    t = threading.Thread(target=_chroma_monitor_loop, daemon=True, name="ChromaMonitor")
    t.start()
    logger.info("[Startup] ChromaDB Integrity Monitor đã khởi động (daemon thread).")

# ==========================================
# CÁC ENDPOINT API
# ==========================================

@app.get("/health")
def health():
    # B4: cho biết bản Agent này là profile nào, bật lớp nào, dùng kho RAG nào
    return {"status": "healthy", **defense_profile.describe()}

@app.get("/stats")
def stats():
    return {
        "timeline_size": len(GLOBAL_TIMELINE_MEMORY),
        "recent_events": GLOBAL_TIMELINE_MEMORY[-10:]
    }

@app.get("/timeline")
def get_timeline():
    with _timeline_lock:
        return {
            "size": len(GLOBAL_TIMELINE_MEMORY),
            "events": list(GLOBAL_TIMELINE_MEMORY)
        }

@app.get("/incidents")
def get_incidents_summary():
    return {**GLOBAL_INCIDENT_STATS, "timeline_size": len(GLOBAL_TIMELINE_MEMORY)}

# LIVE FEED: Trả về tối đa 50 kết quả phân tích gần nhất
@app.get("/recent")
def get_recent_results():
    return {
        "count": len(RECENT_ANALYSIS_RESULTS),
        "results": RECENT_ANALYSIS_RESULTS
    }

# [THÊM MỚI] Góp ý 1: Reset Memory cực xịn cho lúc Demo
@app.post("/reset")
def reset_memory():
    logger.warning("[RESET] Toàn bộ memory bị xóa — được gọi từ dashboard hoặc external client.")
    global GLOBAL_TIMELINE_MEMORY
    global GLOBAL_INCIDENT_STATS
    global RECENT_ANALYSIS_RESULTS
    global IP_ACTIVITY_LOG

    GLOBAL_TIMELINE_MEMORY.clear()
    RECENT_ANALYSIS_RESULTS.clear()
    IP_ACTIVITY_LOG.clear()
    _IP_HIGH_COUNT.clear()
    _SOAR_EXECUTED_IPS.clear()
    GLOBAL_INCIDENT_STATS = {
        "total_incidents": 0,
        "total_received": 0,
        "noise_dropped": 0,
        "clean_filtered": 0,
        "pending_analysis": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    return {
        "status": "success",
        "message": "Timeline memory, recent results, and incident stats cleared successfully."
    }

@app.post("/analyze", response_model=AnalysisResponse)
def analyze_log(payload: LogInput):
    global GLOBAL_TIMELINE_MEMORY
    global GLOBAL_INCIDENT_STATS

    with _analysis_lock:
        return _analyze_log_impl(payload)

def _analyze_log_impl(payload: LogInput):
    global GLOBAL_TIMELINE_MEMORY
    global GLOBAL_INCIDENT_STATS

    start_time = time.time()
    logger.info(f"Đang xử lý log mới: {payload.raw_log}")

    GLOBAL_INCIDENT_STATS["total_received"] += 1
    GLOBAL_INCIDENT_STATS["pending_analysis"] += 1
    try:
        # Khởi tạo State với bộ nhớ Timeline
        initial_state = {
            "raw_log": payload.raw_log,
            "alert": payload.alert or {},   # B1: alert gốc cho làm giàu/ticket (Ngày 2–3)
            "investigation_notes": ["API: Đã tiếp nhận Log."],
            "attack_timeline": GLOBAL_TIMELINE_MEMORY
        }

        # Kích hoạt LangGraph
        final_state = langgraph_app.invoke(initial_state)

        # Lấy severity và evidence từ Analyzer
        severity_result = final_state.get("severity", "low").lower()
        # Clamp [0,1] — LLM đôi khi trả giá trị ngoài range (vd: 8.0)
        evidence_result = max(0.0, min(1.0, float(final_state.get("evidence_strength", 0.0))))

        # ── DETERMINISTIC OVERRIDE ──────────────────────────────────────────
        # Llama 3.1 8B không follow multi-condition logic đủ tin cậy.
        # Rule: auth_success sau HIGH/CRITICAL history từ cùng IP = CRITICAL
        # Đây là rule xác định hoàn toàn — không cần LLM phán quyết.
        _raw_event_type = str(payload.raw_log.get("event_type", "")).lower()
        _critical_override_applied = False
        _current_ip = ""   # initialized here — assigned inside auth_success block if triggered
        if _raw_event_type in ("auth_success", "login_success"):
            _current_ip = final_state.get("source_ip", "") or payload.raw_log.get("source_ip", "")
            if _current_ip and _current_ip != "unknown_ip":
                _has_high_prior = any(
                    e.get("source_ip") == _current_ip
                    and e.get("severity", "").lower() in ("high", "critical")
                    for e in GLOBAL_TIMELINE_MEMORY  # history trước khi enrich event hiện tại
                )
                if _has_high_prior and severity_result != "critical":
                    logger.info(
                        f"[CRITICAL OVERRIDE] auth_success từ {_current_ip} "
                        f"có lịch sử HIGH → buộc CRITICAL (LLM trả {severity_result.upper()})"
                    )
                    severity_result = "critical"
                    evidence_result = max(evidence_result, 0.9)
                    _critical_override_applied = True

        # ── OPTION D: GHI ĐÈ REASONING khi CRITICAL override kích hoạt ────────
        # LLM 8B hallucinate "lịch sử IP trống" → thay bằng reasoning chính xác từ code
        if _critical_override_applied:
            _prior_events = [
                e for e in GLOBAL_TIMELINE_MEMORY
                if e.get("source_ip") == _current_ip
                and e.get("severity", "").lower() in ("high", "critical")
            ]
            _prior_desc = ", ".join(
                f"{e.get('event_type','?')} [{e.get('severity','?').upper()}]"
                for e in _prior_events[-3:]
            ) or "sự kiện nguy hiểm không xác định"
            _override_reasoning = (
                f"[Deterministic Override] IP {_current_ip} có {len(_prior_events)} tiền án nguy hiểm trước đó: "
                f"{_prior_desc}. Phát hiện {_raw_event_type} — Kill-chain xác nhận kẻ tấn công "
                f"đã vượt rào thành công. LLM verdict gốc bị override bởi kill-chain rule."
            )
            _mutable_ai = dict(final_state.get("raw_ai_verdict", {}))
            _mutable_ai["reasoning"] = _override_reasoning
            final_state = dict(final_state)
            final_state["raw_ai_verdict"] = _mutable_ai
        # ─────────────────────────────────────────────────────────────────────

        # ── IP THRESHOLD ESCALATION ─────────────────────────────────────────────
        # Sau N log HIGH/CRITICAL từ cùng IP → force CRITICAL, không cần LLM phán lại
        _escalation_ip = (
            final_state.get("source_ip", "") or payload.raw_log.get("source_ip", "")
        )
        if _escalation_ip and _escalation_ip not in ("", "unknown_ip", "127.0.0.1"):
            if severity_result in ("high", "critical"):
                _IP_HIGH_COUNT[_escalation_ip] = _IP_HIGH_COUNT.get(_escalation_ip, 0) + 1
            _ip_count = _IP_HIGH_COUNT.get(_escalation_ip, 0)
            if _ip_count >= _IP_ESCALATION_THRESHOLD and severity_result == "high":
                logger.info(
                    f"[IP ESCALATION] {_escalation_ip}: {_ip_count}/{_IP_ESCALATION_THRESHOLD} "
                    f"HIGH → force CRITICAL + NETWORK_BLOCK_FULL"
                )
                severity_result = "critical"
                evidence_result = max(evidence_result, 0.92)
                if not _critical_override_applied:
                    _critical_override_applied = True
                    _esc_ai = dict(final_state.get("raw_ai_verdict", {}))
                    _esc_ai["reasoning"] = (
                        f"[IP Escalation — Deterministic] IP {_escalation_ip} đã kích hoạt "
                        f"{_ip_count} cảnh báo HIGH/CRITICAL liên tiếp (ngưỡng: {_IP_ESCALATION_THRESHOLD}). "
                        f"Hệ thống tự động leo thang lên CRITICAL và cô lập mạng đầy đủ "
                        f"(INPUT + OUTPUT + FORWARD) theo chính sách tích lũy mối đe dọa."
                    )
                    final_state = dict(final_state)
                    final_state["raw_ai_verdict"] = _esc_ai
        # ─────────────────────────────────────────────────────────────────────

        # Khi override kích hoạt, Responder đã chạy với severity cũ → SOAR chưa được thực thi đúng.
        # Tính lại action VÀ thực thi SOAR ngay tại đây với severity CRITICAL đã xác nhận.
        if _critical_override_applied:
            _ov_ip   = _escalation_ip or _current_ip  # IP từ escalation hoặc auth_success
            _ov_mode = _get_soar_mode()
            if evidence_result >= 0.90:
                _action_result = "NETWORK_BLOCK_FULL"
                # Chỉ thực thi iptables + Telegram 1 lần mỗi IP
                # Các log tiếp theo từ cùng IP vẫn được đánh CRITICAL nhưng không re-block
                if _ov_ip and _ov_ip not in _SOAR_EXECUTED_IPS:
                    _SOAR_EXECUTED_IPS.add(_ov_ip)
                    _block_res = _exec_block_full(_ov_ip, _ov_mode)
                    _tele_res  = _exec_alert(
                        f"🚨 [CRITICAL — IP Escalation] IP {_ov_ip} kích hoạt "
                        f"{_IP_HIGH_COUNT.get(_ov_ip, 0)} cảnh báo HIGH/CRITICAL liên tiếp. "
                        f"Hệ thống tự động leo thang CRITICAL + NETWORK_BLOCK_FULL (INPUT+OUTPUT+FORWARD).",
                        _ov_mode
                    )
                    logger.info(f"[ACTION OVERRIDE EXEC] {_block_res}")
                    logger.info(f"[ACTION OVERRIDE EXEC] Telegram: {_tele_res}")
            elif evidence_result >= 0.70:
                _action_result = "BLOCK_IP"
                if _ov_ip and _ov_ip not in _SOAR_EXECUTED_IPS:
                    _SOAR_EXECUTED_IPS.add(_ov_ip)
                    _block_res = _exec_block_ip(_ov_ip, _ov_mode)
                    _tele_res  = _exec_alert(
                        f"🔥 [CRITICAL — Kill-chain confirmed] Đã tự động Block IP: {_ov_ip}",
                        _ov_mode
                    )
                    logger.info(f"[ACTION OVERRIDE EXEC] {_block_res}")
                    logger.info(f"[ACTION OVERRIDE EXEC] Telegram: {_tele_res}")
            else:
                _action_result = "ALERT_OPERATOR"
            logger.info(f"[ACTION OVERRIDE] CRITICAL kill-chain confirmed → {_action_result}")
        else:
            _action_result = final_state.get("action_taken", "NONE").upper()
        # ────────────────────────────────────────────────────────────────────

        # Enrich sự kiện vừa phân tích (phần tử cuối) với severity đã xác định.
        # Dùng lock để tránh race condition khi nhiều log đến cùng lúc (burst từ partner).
        # Mutate in-place (.clear + .extend) thay vì reassign (= new_list) để giữ reference.
        updated_timeline = list(final_state.get("attack_timeline", []))
        if updated_timeline:
            last_event = dict(updated_timeline[-1])
            last_event["severity"] = severity_result
            last_event["evidence_strength"] = evidence_result
            updated_timeline[-1] = last_event
        with _timeline_lock:
            # Merge: giữ các event cũ đã có, chỉ thêm event của request này
            existing_ids = {e.get("correlation_id","") + e.get("event_timestamp","")
                            for e in GLOBAL_TIMELINE_MEMORY}
            for ev in updated_timeline:
                ev_key = ev.get("correlation_id","") + ev.get("event_timestamp","")
                if ev_key not in existing_ids:
                    GLOBAL_TIMELINE_MEMORY.append(ev)
                    existing_ids.add(ev_key)
                else:
                    # Cập nhật severity/evidence cho event đã có (enrichment)
                    for i, existing in enumerate(GLOBAL_TIMELINE_MEMORY):
                        if (existing.get("correlation_id","") + existing.get("event_timestamp","")) == ev_key:
                            GLOBAL_TIMELINE_MEMORY[i] = ev
                            break
            if len(GLOBAL_TIMELINE_MEMORY) > MAX_TIMELINE_SIZE:
                del GLOBAL_TIMELINE_MEMORY[:-MAX_TIMELINE_SIZE]

        # Cập nhật số liệu thống kê Incident
        GLOBAL_INCIDENT_STATS["total_incidents"] += 1
        if severity_result in GLOBAL_INCIDENT_STATS:
            GLOBAL_INCIDENT_STATS[severity_result] += 1

        process_time = round((time.time() - start_time) * 1000, 2)
        logger.info(f"Phân tích xong trong {process_time}ms. Severity: {severity_result.upper()}")

        _notes = list(final_state.get("investigation_notes", []))
        if _critical_override_applied and _current_ip:
            # Note này chỉ dành cho auth_success override (có _current_ip)
            # IP escalation override tự set reasoning riêng trong _esc_ai
            _notes.append(
                f"[CRITICAL OVERRIDE] LLM trả {final_state.get('severity','?').upper()} "
                f"(reasoning: '{final_state.get('raw_ai_verdict',{}).get('reasoning','?')[:80]}...') "
                f"— Deterministic kill-chain rule phát hiện auth_success sau HIGH từ IP "
                f"{_current_ip} → ép CRITICAL + evidence=0.9."
            )

        _response = AnalysisResponse(
            incident_id=final_state.get("correlation_id", "Unknown"),
            severity=severity_result.upper(),
            confidence=final_state.get("confidence_score", 0.0),
            evidence_strength=evidence_result,  # dùng post-override value cho nhất quán với action
            mitre_techniques=final_state.get("mitre_mapping", []),
            action_taken=_action_result,
            agent_mode=final_state.get("agent_mode", "autonomous").upper(),
            knowledge_conflict=final_state.get("knowledge_conflict", False) is True,
            attack_chain_stage=final_state.get("attack_chain_stage", ""),
            attack_timeline=GLOBAL_TIMELINE_MEMORY,
            raw_ai_verdict=final_state.get("raw_ai_verdict", {}),        # XAI
            investigation_notes=_notes,
            processing_time_ms=process_time,
            enrichment=final_state.get("enrichment") or {},   # Ngày 2
        )

        # Lưu vào Live Feed buffer — MỌI log qua LLM đều được ghi (kể cả từ /batch)
        _live_entry = _response.dict()
        _live_entry["source_ip"] = payload.raw_log.get("source_ip", "unknown")
        _live_entry["event_type"] = payload.raw_log.get("event_type", "unknown")
        _live_entry["received_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        RECENT_ANALYSIS_RESULTS.append(_live_entry)
        if len(RECENT_ANALYSIS_RESULTS) > MAX_RECENT_RESULTS:
            RECENT_ANALYSIS_RESULTS[:] = RECENT_ANALYSIS_RESULTS[-MAX_RECENT_RESULTS:]

        return _response

    except Exception as e:
        logger.error(f"Lỗi API: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        GLOBAL_INCIDENT_STATS["pending_analysis"] = max(0, GLOBAL_INCIDENT_STATS["pending_analysis"] - 1)


# ==========================================
# BATCH MODE: PHÂN TÍCH CHUỖI LOG
# Nhận List[log], xử lý tuần tự — log trước xây timeline cho log sau.
# ==========================================
@app.post("/analyze/batch")
def analyze_batch(payload: BatchLogInput):
    global GLOBAL_TIMELINE_MEMORY, GLOBAL_INCIDENT_STATS, RECENT_ANALYSIS_RESULTS

    if payload.reset_memory:
        logger.warning("[Batch] reset_memory=True bị CHẶN — gọi /reset riêng nếu cần xóa bộ nhớ.")

    if not payload.logs:
        raise HTTPException(status_code=400, detail="Danh sách logs không được để trống.")

    # event_type luôn phải qua LLM dù không có attack indicator (vì cần check kill-chain)
    _ALWAYS_ANALYZE = {"auth_success", "login_success", "auth_attempt", "login_attempt", "rag_integrity_violation"}
    # event_type rõ ràng là noise kỹ thuật → DROP ngay, không cần Extractor
    _OBVIOUS_NOISE  = {"health_check", "heartbeat", "metric_report", "asset_sync", "ping", "keep_alive"}

    results    = []
    batch_stats: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    prefilter_stats = {"noise_dropped": 0, "clean_filtered": 0, "llm_analyzed": 0}

    for i, raw_log in enumerate(payload.logs):
        _ev_type = str(raw_log.get("event_type", "")).lower()
        _src_ip  = str(raw_log.get("source_ip", ""))
        _t0      = time.time()

        # [Option A] Ghi nhận IP vào activity log TRƯỚC mọi quyết định filter
        # Kể cả noise và clean-filtered — đảm bảo log sau từ cùng IP không bị bỏ sót
        if _src_ip:
            IP_ACTIVITY_LOG[_src_ip] = IP_ACTIVITY_LOG.get(_src_ip, 0) + 1

        # ── TIER 0: obvious noise ─────────────────────────────────────────
        if _ev_type in _OBVIOUS_NOISE:
            prefilter_stats["noise_dropped"] += 1
            GLOBAL_INCIDENT_STATS["noise_dropped"] += 1
            GLOBAL_INCIDENT_STATS["total_received"] += 1
            logger.info(f"[Batch {i+1}] PRE-FILTER NOISE DROP: {_ev_type}")
            results.append({
                "pre_filtered": True, "filter_tier": "noise",
                "severity": "LOW", "action_taken": "IGNORE",
                "source_ip": raw_log.get("source_ip", "unknown"),
                "event_type": _ev_type, "evidence_strength": 0.0,
                "mitre_techniques": [], "incident_id": f"NOISE_{i}",
                "investigation_notes": [f"Pre-filter [Tier 0]: '{_ev_type}' là noise kỹ thuật. Bỏ qua."],
                "processing_time_ms": round((time.time() - _t0) * 1000, 2),
                "attack_timeline": [], "raw_ai_verdict": {},
                "confidence": 0.0, "attack_chain_stage": "none",
                "knowledge_conflict": False, "agent_mode": "PRE_FILTERED",
            })
            continue

        # ── TIER 1: Extractor (pure Python, ~0.1s, không dùng LLM) ────────
        try:
            _ext = node_extractor({"raw_log": raw_log, "investigation_notes": [],
                                   "attack_timeline": [], "source_ip": ""})
            _indicators = _ext.get("extracted_ioc", {}).get("attack_indicators", [])
        except Exception as _err:
            logger.warning(f"[Batch {i+1}] Extractor lỗi: {_err} → chuyển sang LLM.")
            _indicators = ["extractor_error"]  # conservative: luôn pass khi không chắc

        # Kiểm tra lịch sử IP trong timeline — IP đã từng HIGH/CRITICAL thì luôn vào LLM
        # dù log hiện tại trông bình thường (tránh bỏ sót bước leo thang sau tấn công)
        _ip_has_high_history = _src_ip and any(
            e.get("source_ip") == _src_ip
            and e.get("severity", "low").lower() in ("high", "critical")
            for e in GLOBAL_TIMELINE_MEMORY
        )
        # [Option A] IP đã xuất hiện trước đó trong batch (dù bị clean-filter) → vào LLM
        _ip_seen_before = bool(_src_ip) and IP_ACTIVITY_LOG.get(_src_ip, 0) > 1

        _needs_llm = bool(_indicators) or (_ev_type in _ALWAYS_ANALYZE) or _ip_has_high_history or _ip_seen_before

        if not _needs_llm:
            # Không có attack indicator + IP chưa có tiền án + không phải event đặc biệt → CLEAN
            prefilter_stats["clean_filtered"] += 1
            GLOBAL_INCIDENT_STATS["clean_filtered"] += 1
            GLOBAL_INCIDENT_STATS["total_received"] += 1
            batch_stats["low"] = batch_stats.get("low", 0) + 1
            logger.info(f"[Batch {i+1}] PRE-FILTER CLEAN: {_ev_type} từ {raw_log.get('source_ip','?')}")
            results.append({
                "pre_filtered": True, "filter_tier": "clean",
                "severity": "LOW", "action_taken": "IGNORE",
                "source_ip": raw_log.get("source_ip", "unknown"),
                "event_type": _ev_type, "evidence_strength": 0.0,
                "mitre_techniques": [], "incident_id": f"CLEAN_{i}",
                "investigation_notes": [
                    "Pre-filter [Tier 1]: Extractor không tìm thấy attack indicator.",
                    f"event_type='{_ev_type}' không nằm trong danh sách bắt buộc phân tích.",
                    f"IP {_src_ip} chưa từng xuất hiện trước đó trong batch này và không có lịch sử HIGH/CRITICAL.",
                    "LLM pipeline bỏ qua — tiết kiệm tài nguyên.",
                ],
                "processing_time_ms": round((time.time() - _t0) * 1000, 2),
                "attack_timeline": [], "raw_ai_verdict": {},
                "confidence": 0.0, "attack_chain_stage": "none",
                "knowledge_conflict": False, "agent_mode": "PRE_FILTERED",
            })
            continue

        # ── TIER 2: Full LLM pipeline (chỉ log thực sự đáng ngờ) ──────────
        prefilter_stats["llm_analyzed"] += 1
        logger.info(
            f"[Batch {i+1}/{len(payload.logs)}] LLM PIPELINE: {_ev_type} | indicators={_indicators}"
        )
        try:
            # Đánh dấu thread-local để analyze_log KHÔNG thêm vào Live Feed buffer
            _batch_context.from_batch = True
            result = analyze_log(LogInput(raw_log=raw_log))
            result_dict = result.dict()

            # [Option E] Nếu IP đã từng thấy trước đó (dù clean-filtered),
            # ghi note vào Audit Trail — KHÔNG chen vào reasoning để giữ LLM text sạch
            if _ip_seen_before:
                _total_seen = IP_ACTIVITY_LOG.get(_src_ip, 0) - 1  # lần xuất hiện trước
                _llm_count  = sum(
                    1 for e in GLOBAL_TIMELINE_MEMORY
                    if e.get("source_ip") == _src_ip
                )
                _clean_count = _total_seen - _llm_count
                _ip_note = (
                    f"[IP Activity] IP {_src_ip} đã xuất hiện {_total_seen} lần trước trong batch: "
                    f"{_llm_count} lần qua LLM phân tích sâu, "
                    f"{_clean_count} lần bị pre-filter (không có attack indicator)."
                )
                result_dict["investigation_notes"].append(_ip_note)

            results.append(result_dict)
            batch_stats[result.severity.lower()] = batch_stats.get(result.severity.lower(), 0) + 1
        except HTTPException as e:
            logger.error(f"[Batch {i+1}] Lỗi: {e.detail}")
            results.append({"error": e.detail, "log_index": i, "raw_log": raw_log})
        finally:
            _batch_context.from_batch = False  # reset flag sau mỗi log dù lỗi hay không

    return {
        "mode": "batch_with_prefilter",
        "total": len(payload.logs),
        "processed": len([r for r in results if "error" not in r]),
        "pre_filter_stats": prefilter_stats,
        "batch_summary": batch_stats,
        "final_timeline_size": len(GLOBAL_TIMELINE_MEMORY),
        "results": results
    }


# ==========================================
# B1 (AegisSOC): CỬA VÀO ALERT TỪ SIEM — POST /ingest/alerts
# splunk_bridge.py (Ngày 7) và replay/replay_alerts.py đều gọi vào đây.
# ==========================================
class IngestPayload(BaseModel):
    alerts: List[Alert] = Field(..., min_length=1, max_length=100)


@app.exception_handler(RequestValidationError)
async def _log_rejected_alerts(request: Request, exc: RequestValidationError):
    """
    B2: ghi log alert bị từ chối vì sai hợp đồng (422) ở /ingest/alerts, để khi cắm Splunk
    (Ngày 7) biết alert "biến mất" là do trường nào.
    Chỉ ghi alert_id + vị trí trường sai + loại lỗi — KHÔNG ghi giá trị gốc (có thể do kẻ
    tấn công viết). Phản hồi 422 giữ nguyên như mặc định. Endpoint khác: hành vi mặc định.
    """
    if request.url.path == "/ingest/alerts":
        body = exc.body if isinstance(exc.body, dict) else {}
        alerts = body.get("alerts") if isinstance(body.get("alerts"), list) else []
        problems = []
        for err in exc.errors():
            loc = [str(p) for p in err.get("loc", ())]
            alert_id = "?"
            if len(loc) >= 3 and loc[:2] == ["body", "alerts"] and loc[2].isdigit():
                idx = int(loc[2])
                if idx < len(alerts) and isinstance(alerts[idx], dict):
                    alert_id = repr(str(alerts[idx].get("alert_id", "?"))[:100])
            # repr() + cắt ngắn: tên trường thừa cũng do bên gửi đặt → chống chèn xuống dòng vào log
            field = repr(".".join(loc[1:]) or "(body)")[:120]
            problems.append(f"alert_id={alert_id} trường={field} lỗi={err.get('type')}")
        logger.warning(f"[Ingest] Từ chối (422) — {len(problems)} lỗi hợp đồng: "
                       + " | ".join(problems[:20]))
    return await request_validation_exception_handler(request, exc)


def require_agent_token(authorization: Optional[str] = Header(default=None)):
    """
    Kiểm Bearer token. Chạy TRƯỚC khi đọc nội dung alert.
    Server chưa cấu hình AGENT_TOKEN → từ chối tất cả (khoá mặc định, không mở mặc định).
    """
    expected = os.getenv("AGENT_TOKEN", "")
    if not expected:
        logger.error("[Ingest] AGENT_TOKEN chưa được cấu hình — từ chối mọi alert.")
        raise HTTPException(status_code=503, detail="Server chưa cấu hình AGENT_TOKEN.")
    scheme, _, token = (authorization or "").partition(" ")
    # compare_digest: so sánh thời gian hằng định, không lộ token qua thời gian phản hồi
    if scheme.lower() != "bearer" or not secrets.compare_digest(
        token.strip().encode("utf-8"), expected.encode("utf-8")
    ):
        logger.warning("[Ingest] Từ chối request: token sai hoặc thiếu.")
        raise HTTPException(status_code=401, detail="Token không hợp lệ.",
                            headers={"WWW-Authenticate": "Bearer"})


def _process_one_alert(alert: Alert) -> Dict[str, Any]:
    # ── ① PREFILTER (Ngày 5) GẮN TẠI ĐÂY ─────────────────────────────────
    # Đứng trước mọi bước khác, đúng luồng:
    #   SIEM → prefilter → Extractor/Correlator → làm giàu → ticket → LLM → Responder
    # B1 chưa lọc: mọi alert đều vào graph.
    # ──────────────────────────────────────────────────────────────────────
    raw_log = to_legacy_raw_log(alert)   # giàn giáo cho node cũ — bỏ ở Ngày 3
    try:
        res = analyze_log(LogInput(raw_log=raw_log, alert=alert.model_dump()))
        return {
            "alert_id": alert.alert_id,
            "status": "analyzed",
            "incident_id": res.incident_id,
            "severity": res.severity,
            "mitre_techniques": res.mitre_techniques,
            "action_taken": res.action_taken,
            "processing_time_ms": res.processing_time_ms,
            "enrichment_summary": res.enrichment.get("summary", ""),   # Ngày 2
            "defense_profile": defense_profile.PROFILE,                # B4: bộ đo kiểm được đang gọi đúng bản
        }
    except HTTPException as e:
        logger.error(f"[Ingest] Alert {alert.alert_id} lỗi khi phân tích: {e.detail}")
        return {"alert_id": alert.alert_id, "status": "error", "detail": e.detail}


def _process_alerts_background(alerts: List[Alert]):
    for alert in alerts:
        r = _process_one_alert(alert)
        logger.info(f"[Ingest] {r['alert_id']} → {r['status']} "
                    f"{r.get('severity', '')} {r.get('action_taken', '')}".rstrip())


@app.post("/ingest/alerts", dependencies=[Depends(require_agent_token)])
def ingest_alerts(
    payload: IngestPayload,
    background_tasks: BackgroundTasks,
    response: Response,
    wait: bool = Query(default=False, description="true: chờ phân tích xong mới trả kết quả (dùng khi phát lại/test)"),
):
    """
    Nhận {"alerts": [...]} theo hợp đồng 10 trường.
    - Mặc định (wait=false): trả 202 ngay, phân tích chạy nền. Dành cho splunk_bridge.py —
      bridge có timeout 10s, còn Llama 8B mất vài chục giây/alert; chờ thì bridge tưởng lỗi và gửi lại.
    - wait=true: phân tích xong từng alert rồi trả kết quả — dành cho script phát lại/test.
    Kết quả luôn xem được ở /recent và trên dashboard.
    """
    alert_ids = [a.alert_id for a in payload.alerts]
    logger.info(f"[Ingest] Nhận {len(alert_ids)} alert: {alert_ids} (wait={wait})")

    if wait:
        results = [_process_one_alert(a) for a in payload.alerts]
        return {"status": "done", "received": len(alert_ids), "results": results}

    background_tasks.add_task(_process_alerts_background, list(payload.alerts))
    response.status_code = 202
    return {"status": "accepted", "received": len(alert_ids), "alert_ids": alert_ids}


# ==========================================
# INTERNAL: RAG POISON INJECTION
# phase3.py gọi endpoint này thay vì mở PersistentClient trực tiếp.
# Chạy trong cùng process → tránh chromadb 0.5.x Rust panic do multi-process SQLite.
# ==========================================
class RAGPoisonPayload(BaseModel):
    doc_id: str
    document: str
    metadata: dict

@app.post("/internal/inject-rag-poison")
def inject_rag_poison(payload: RAGPoisonPayload):
    # Dùng retriever_instance.db — PersistentClient duy nhất, không tạo thêm client mới
    # _chroma_lock serialize với mọi thao tác ChromaDB khác trong process
    try:
        with _chroma_lock:
            try:
                retriever_instance.db.delete([payload.doc_id])
            except Exception:
                pass
            retriever_instance.db.add_texts(
                texts=[payload.document],
                metadatas=[payload.metadata],
                ids=[payload.doc_id]
            )
        logger.info(f"[RAGPoison] Document injected: {payload.doc_id}")
        return {"status": "success", "doc_id": payload.doc_id}
    except Exception as e:
        logger.error(f"[RAGPoison] Inject failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))