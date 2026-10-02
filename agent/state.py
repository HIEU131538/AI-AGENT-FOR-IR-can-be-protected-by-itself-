import operator
from typing import TypedDict, Annotated, List, Dict, Any

class SOCAgentState(TypedDict):
    # ==========================================
    # 1. ĐẦU VÀO & HẠ TẦNG TRI THỨC (EXTRACTOR & RETRIEVER)
    # ==========================================
    raw_log: dict             # Log thô ban đầu
    extracted_ioc: dict       # Các IOC bóc tách được (IP, Domain, Hash...)
    rag_context: str          # Tài liệu hướng dẫn từ Vector DB
    rag_docs: List[Dict[str, Any]]  # B4.3b: tài liệu đã đưa vào context (id, cách lấy, điểm) — chẩn đoán + Ngày 5
    context_trust_score: float # Điểm tin cậy của tài liệu (Chống RAG Poisoning)

    # ==========================================
    # 2. PHÂN TÍCH & SUY LUẬN (ANALYZER)
    # ==========================================
    raw_ai_verdict: dict      # "Hiện trường vụ án" gốc của AI để Reflection kiểm toán
    mitre_mapping: List[str]  # Mã kỹ thuật tấn công (VD: T1048)
    severity: str             # Mức độ nghiêm trọng (low, medium, high, critical)
    confidence_score: float   # Độ tự tin tổng hợp (0.0 - 1.0)
    evidence_strength: float  # Độ rõ ràng của bằng chứng từ log (0.0 - 1.0)
    is_suspicious: bool       # Cờ khả nghi dành cho hành vi tàng hình (DNS Tunneling)

    # ==========================================
    # 3. KIỂM TOÁN NỘI BỘ (REFLECTION)
    # ==========================================
    knowledge_conflict: bool  # Cờ báo hiệu mâu thuẫn tri thức (Autonomous Skepticism)

    # ==========================================
    # 4. QUYẾT ĐỊNH & THỰC THI (RESPONDER & ACTION TOOLS)
    # ==========================================
    agent_mode: str               # Trạng thái tự trị (VD: autonomous, human_review_required)
    action_taken: str             # Lệnh hành động đã chọn (block_ip, monitor, isolate...)
    response_reason: str          # Lý do tại sao lại chọn hành động đó
    action_result: Dict[str, Any] # Kết quả trả về từ Action Tool (chứa action_id, status)
    final_response: str           # Kết luận tóm tắt cuối cùng

    # ==========================================
    # 5. LỊCH SỬ ĐIỀU TRA (AUDIT TRAIL)
    # ==========================================
    investigation_notes: Annotated[List[str], operator.add] # Nhãn dán các bước tư duy

    # ==========================================
    # 6. CORRELATION ENGINE (TUẦN 3)
    # ==========================================
    correlation_id: str           
    event_timestamp: str                
    source_ip: str                
    destination_ip: str           
    event_type: str               
    attack_chain_stage: str       
    incident_severity: str        # [THÊM MỚI] Mức độ nghiêm trọng của toàn bộ chuỗi
    attack_chain_visual: str
    attack_timeline: Annotated[List[Dict[str, Any]], operator.add]

    # ==========================================
    # 7. ALERT GỐC (AegisSOC — B1)
    # ==========================================
    # Alert nguyên vẹn theo hợp đồng với Splunk (api/alert_adapter.py → Alert).
    # Nguồn cho node làm giàu (Ngày 2) và bộ dựng ticket (Ngày 3).
    # Gọi qua /analyze cũ thì trường này là {}.
    alert: dict

    # ==========================================
    # 8. LÀM GIÀU TẤT ĐỊNH (AegisSOC — Ngày 2)
    # ==========================================
    # Do agent/nodes/enricher.py tra ra: tài sản, tình báo IP, lịch sử. Không dùng LLM,
    # không chứa dữ liệu do kẻ tấn công viết → Ngày 3 vào phần `trusted` của ticket.
    enrichment: dict

    # ==========================================
    # 9. LỖI GỌI LLM (AegisSOC — B4.1)
    # ==========================================
    # True nếu Analyzer hoặc Reflection không gọi được / không đọc được kết quả LLM.
    # Khi đó severity "low" chỉ là giá trị lấp chỗ — API trả status "llm_error", bộ đo loại ca này.
    llm_error: bool
    llm_error_detail: str

    # ==========================================
    # 10. TICKET HAI NGĂN (AegisSOC — B5)
    # ==========================================
    # Do core/ticket.py dựng sau Enricher: {"ticket_id", "version", "trusted": {...}, "untrusted": {...}}.
    # Analyzer + Reflection CHỈ đọc ticket (không đọc raw_log). `trusted` không chứa ký tự nào từ `fields`.
    ticket: dict