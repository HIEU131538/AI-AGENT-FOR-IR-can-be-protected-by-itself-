from agent.state import SOCAgentState
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field, field_validator
import ast
import os

# ==========================================
# 1. PYDANTIC - BỌC THÉP ĐỊNH DẠNG (Nâng cấp Evidence Strength)
# ==========================================
class AnalyzerOutput(BaseModel):
    thought_process: str = Field(description="Chi tiết luồng tư duy: Phân tích RAG, đối chiếu log, tìm mâu thuẫn từng bước trước khi ra kết luận.")
    mitre_mapping: list[str] = Field(description="Định dạng Txxxx hoặc Txxxx.xxx (VD: 'T1190'). Log sạch BẮT BUỘC trả mảng rỗng []")
    severity: str = Field(description="low, medium, high, critical. Log hợp lệ/sạch thì gán 'low'")
    evidence_strength: float = Field(description="Độ rõ ràng của bằng chứng trong log thô (0.0 - 1.0). Độc lập với RAG.")
    confidence_score: float = Field(description="Độ tự tin tổng hợp sau khi đối chiếu cả Log và RAG (0.0 - 1.0).")
    is_suspicious: bool = Field(description="True nếu có dấu hiệu khả nghi (như tần suất lạ) cần đưa vào diện Monitor.")
    reasoning: str = Field(description="Giải thích tư duy ngắn gọn bằng tiếng Việt.")

    @field_validator("mitre_mapping", mode="before")
    @classmethod
    def coerce_mitre_list(cls, v):
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            v = v.strip()
            if not v or v == "[]":
                return []
            try:
                parsed = ast.literal_eval(v)
                return parsed if isinstance(parsed, list) else [str(parsed)]
            except Exception:
                return [v] if v else []
        return []

def _get_windows_host_ip() -> str:
    import subprocess
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
        parts = out.split()
        return parts[parts.index("via") + 1]
    except Exception:
        pass
    return "127.0.0.1"

# langchain_ollama 0.1.x đọc OLLAMA_HOST (base_url param bị bỏ qua)
if not os.getenv("OLLAMA_HOST"):
    os.environ["OLLAMA_HOST"] = f"http://{_get_windows_host_ip()}:11434"

print("[*] Đang kết nối với Bộ não Llama 3.1 (Ollama)...")
try:
    ollama_url = os.environ["OLLAMA_HOST"]
    print(f"[*] Đang gọi Ollama tại: {ollama_url}")
    llm = ChatOllama(
        model="llama3.1",
        temperature=0.0,
        request_timeout=120
    )
    structured_llm = llm.with_structured_output(AnalyzerOutput)
except Exception as e:
    print(f"[-] LỖI CRITICAL: Không thể gọi Ollama -> {e}")
    structured_llm = None

SYSTEM_PROMPT = """Bạn là Chuyên gia SOC AI Agent của Học viện Kỹ thuật Mật mã (KMA). Bạn là một cỗ máy suy luận logic khách quan.

[NGUYÊN TẮC TỐI THƯỢNG]
1. Sự thật nằm ở Log. Đọc kỹ toàn bộ "Log thô" — bao gồm mọi trường (message, payload, url, username) — để tìm payload.
2. Lịch sử IP trong phần [THÔNG TIN CHUỖI TẤN CÔNG] quyết định bối cảnh. Nếu "Lịch sử các sự kiện" ghi "TRỐNG." thì IP chưa có tiền án.
3. Nếu Incident Severity từ Correlator mâu thuẫn với bằng chứng trong Log, ưu tiên bằng chứng trong Log.

[QUY TẮC CỐT LÕI]
- Tuân theo LỆNH TỐI CAO [SYSTEM DIRECTIVE] bên dưới khi đánh giá mức độ.
- Nếu "Lịch sử các sự kiện" = "TRỐNG." thì KHÔNG ĐƯỢC phán quyết CRITICAL.

[MA TRẬN ĐÁNH GIÁ MỨC ĐỘ (SEVERITY)]
Quy tắc xếp hạng dựa trên NỘI DUNG LOG và LỊCH SỬ IP:
1. MỨC LOW: Truy cập bình thường (GET /home, normal_traffic, auth_success thuần túy) VÀ Lịch sử trống hoặc chỉ có mức LOW.
2. MỨC MEDIUM: Hành vi Dò quét (/.git/config, port_scan, web_access) chưa có payload khai thác.
3. MỨC HIGH: Phát hiện payload tấn công trong "Log thô" hoặc trong "Attack Indicators". Bao gồm:
   - SQLi trong BẤT KỲ trường nào: OR '1'='1', UNION SELECT, admin'--, DROP TABLE.
   - auth_attempt hoặc POST login CÓ payload SQLi → MỨC HIGH (dù event_type là auth_attempt).
   - Attack Indicators chứa bất kỳ giá trị nào sau: "sql_injection", "rce_attempt", "ssrf_attempt",
     "http_smuggling", "dns_tunneling", "jwt_privilege_escalation", "header_injection", "header_abuse" → MỨC HIGH.
   - "rag_poisoning" trong Attack Indicators → CRITICAL trực tiếp (ChromaDB bị inject document giả — tấn công nền tảng tri thức).
   - SSRF: file://, 169.254, gopher://, internal hostname.
   - DNS Tunneling: subdomain entropy cao, chuỗi Hex/Base64 dài trong DNS query.
   - HTTP Smuggling: request có đồng thời Content-Length và Transfer-Encoding.
   - JWT Admin: Bearer token với role=admin từ client bên ngoài.
   - Header Injection: X-Forwarded-Host trỏ nội bộ, X-Internal-Trace từ external.
   - RCE: nc -e, /bin/sh, wget|bash, curl|sh.
4. MỨC CRITICAL — CHỈ KHI ĐỦ CẢ 2 ĐIỀU KIỆN:
   ĐIỀU KIỆN A: Sự kiện hiện tại là đăng nhập thành công (auth_success, login_success).
   ĐIỀU KIỆN B: Kiểm tra "Lịch sử các sự kiện" bên dưới — không phải "TRỐNG." VÀ có ít nhất một entry với trường "severity" = "high" hoặc "critical".
   → Không đủ ĐIỀU KIỆN B → KHÔNG gán CRITICAL.
   - RAG Poisoning: hành vi insert/add vào ChromaDB/mitre_knowledge → CRITICAL.

[LỆNH TỐI CAO TỪ HỆ THỐNG (SYSTEM DIRECTIVE)]
{dynamic_rule}

[QUY TẮC ĐẦU RA JSON BẮT BUỘC]
- thought_process: (1) Log thô và Attack Indicators chứa hành vi/payload gì cụ thể? (2) Lịch sử IP trống hay có sự kiện severity cao? (3) Áp dụng Ma trận cho ra kết quả nào?
- LUẬT THÉP AUTH_SUCCESS: Nếu event_type="auth_success" VÀ "Lịch sử các sự kiện" = "TRỐNG." → BẮT BUỘC trả LOW, mitre_mapping=[].
- reasoning: Tóm tắt ngắn. auth_attempt KHÁC auth_success.
- mitre_mapping: Mã MITRE hoặc [].
- is_suspicious: true/false.

[THÔNG TIN CHUỖI TẤN CÔNG (KILL CHAIN)]
- Incident Severity: {incident_severity}
- Lịch sử các sự kiện: {attack_timeline}

[DỮ LIỆU CA ĐIỀU TRA HIỆN TẠI]
- Log thô: {raw_log}
- IOCs và Attack Indicators: {extracted_ioc}
- BÍ KÍP RAG: {rag_context}
"""
def node_analyzer(state: SOCAgentState):
    print("\n[Trạm 3 - Analyzer] Llama 3.1 đang phân tích dữ liệu...")
    
    rag_context = state.get("rag_context", "")
    raw_log = state.get("raw_log", {})
    extracted_ioc = state.get("extracted_ioc", {})
    trust_score = state.get("context_trust_score", 0.0) 
    
    # Lấy dữ liệu từ Trạm Correlator
    incident_severity = state.get("incident_severity", "low")
    current_ip = state.get("source_ip", "")
    attack_timeline = state.get("attack_timeline", [])

    # Lấy lịch sử (bỏ event hiện tại là phần tử cuối), lọc đúng IP
    full_history = attack_timeline[:-1] if len(attack_timeline) > 1 else []
    if current_ip and current_ip != "unknown_ip":
        history_only = [e for e in full_history if e.get("source_ip") == current_ip]
    else:
        history_only = full_history

    history_len = len(history_only)
    
    _SEV_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}

    if history_len == 0:
        timeline_context = "TRỐNG."
        dynamic_rule = "LỊCH SỬ IP TRỐNG. Đánh giá hoàn toàn dựa vào nội dung Log thô và Attack Indicators hiện tại. Payload tấn công trong Log là bằng chứng thực — hãy báo cáo đúng mức theo Ma trận (SQLi → HIGH, RCE → HIGH, SSRF → HIGH)."
    else:
        timeline_context = str(history_only)
        max_prior_severity = max(
            (e.get("severity", "low") for e in history_only),
            key=lambda s: _SEV_ORDER.get(s, 0),
            default="low"
        )
        dynamic_rule = (
            f"IP NÀY ĐÃ CÓ {history_len} SỰ KIỆN TRONG QUÁ KHỨ "
            f"(MỨC ĐỘ NGUY HIỂM CAO NHẤT ĐÃ XÁC NHẬN: {max_prior_severity.upper()}). "
            f"HÃY ĐỐI CHIẾU VỚI LOG HIỆN TẠI."
        )

    knowledge_conflict = state.get("knowledge_conflict", False)
    
    #notes = list(state.get("investigation_notes", []))
    notes = []
    notes.append("Analyzer: Bắt đầu suy luận Llama 3.1...")

    if not rag_context.strip() or rag_context == "No trusted context retrieved.":
        notes.append("Analyzer: [CẢNH BÁO] Không có RAG context. Kích hoạt Uncertain Mode.")
        rag_context = "RỖNG."

    if not structured_llm:
         notes.append("Analyzer: [CẢNH BÁO] Không có LLM.")
         return {
             "mitre_mapping": [], "severity": "low", 
             "confidence_score": 0.0, "is_suspicious": False,
             "knowledge_conflict": knowledge_conflict, "evidence_strength": 0.0, # Đã fix bug NameError ở đây
             "raw_ai_verdict": {}, "investigation_notes": notes
         }

    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", "Phân tích mối đe dọa. Xuất JSON đầy đủ các trường.")
    ])

    chain = prompt | structured_llm

    try:
        # [THÊM MỚI] Bơm dữ liệu Correlator vào biến Prompt
        result: AnalyzerOutput = chain.invoke({
            "rag_context": rag_context,
            "raw_log": raw_log,
            "extracted_ioc": extracted_ioc,
            "trust_score": trust_score,
            "incident_severity": incident_severity.upper(),
            "attack_timeline": timeline_context,
            "dynamic_rule": dynamic_rule
        })
        
        raw_ai_verdict = {
            "thought_process": result.thought_process,
            "severity": result.severity,
            "evidence_strength": result.evidence_strength,
            "confidence": result.confidence_score,
            "mitre": result.mitre_mapping,
            "is_suspicious": result.is_suspicious,
            "reasoning": result.reasoning
        }

        final_confidence = max(0.0, min(1.0, float(result.confidence_score)))
        valid_levels = {"low", "medium", "high", "critical"}
        final_severity = result.severity.lower().strip()
        if final_severity not in valid_levels:
            final_severity = "medium"
        final_mitre = result.mitre_mapping
        final_suspicious = result.is_suspicious

        # =========================================================================
        # TRUST PENALTY THEO SEVERITY
        # =========================================================================
        if trust_score < 0.3 and final_confidence > 0.0:
            if final_severity in ["low", "medium"]:
                final_confidence *= 0.5
                notes.append(f"Analyzer [TRUST PENALTY]: Giảm 50% Confidence (còn {final_confidence}) do Trust Score thấp.")
            elif final_severity == "high":
                final_confidence *= 0.75
                notes.append(f"Analyzer [TRUST PENALTY]: Giảm 25% Confidence (còn {final_confidence}) do Trust Score thấp.")
                
        # [ĐÃ FIX BUG Ở ĐÂY] Kẹp lại giá trị an toàn tuyệt đối
        final_confidence = max(0.0, min(1.0, final_confidence))

        # =========================================================================
        # OVERRIDE MỀM MỎNG HƠN (Giữ tối đa 0.3)
        # =========================================================================
        override_triggered = False
        if final_severity == "low" and len(final_mitre) > 0:
            override_triggered = True
            final_confidence = min(final_confidence, 0.3)
            final_mitre = []
            notes.append("Analyzer [SYSTEM OVERRIDE]: Xóa MITRE do Severity LOW, giới hạn Confidence tối đa 0.3 để phục vụ Monitor.")
            print("\n[!] CẢNH BÁO: Kích hoạt System Override (Soft Cap).")

        notes.append(f"Analyzer [Thought]: {result.reasoning}")
        if override_triggered:
            notes.append(f"Analyzer [Kết quả (Đã Override)]: Mức độ={final_severity.upper()} | MITRE={final_mitre} | Evidence={result.evidence_strength} | Tự tin={final_confidence}")
        else:
            notes.append(f"Analyzer [Kết quả cuối]: Mức độ={final_severity.upper()} | MITRE={final_mitre} | Evidence={result.evidence_strength} | Tự tin={final_confidence}")
        
        print(f"[+] Phán quyết: {final_severity.upper()} (Evidence: {result.evidence_strength} | Tự tin: {final_confidence})")

        return {
            "mitre_mapping": final_mitre,
            "severity": final_severity,
            "confidence_score": final_confidence,
            "is_suspicious": final_suspicious,
            "knowledge_conflict": knowledge_conflict,
            "evidence_strength": result.evidence_strength,
            "raw_ai_verdict": raw_ai_verdict,
            "investigation_notes": notes
        }

    except Exception as e:
        print(f"[-] Lỗi khi Llama suy luận: {e}")
        notes.append(f"Analyzer: [LỖI CRITICAL] LLM suy luận thất bại -> {e}.")
        return {
            "mitre_mapping": [], "severity": "low", "confidence_score": 0.0,
            "is_suspicious": False, "knowledge_conflict": knowledge_conflict,"evidence_strength": 0.0,
            "raw_ai_verdict": {"error": str(e)}, "investigation_notes": notes
        }