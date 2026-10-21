import os
import sys

# ==========================================
# 🛑 BỘ CHỈ ĐƯỜNG BỌC THÉP
# ==========================================
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import operator
from typing import TypedDict, Annotated, List
from langgraph.graph import StateGraph, END

from agent.state import SOCAgentState
from agent.nodes.extractor import node_extractor
from agent.nodes.correlator import node_correlator
from agent.nodes.enricher import node_enricher   # Ngày 2: làm giàu tất định
from core.ticket import node_ticket_builder       # B5: ticket hai ngăn (trusted / untrusted)
from agent.nodes.retriever import node_retriever
from agent.nodes.analyzer import node_analyzer
from agent.nodes.reflection import node_reflection
from agent.nodes.responder import node_responder
from core import attack_kb                         # B10: mitigation ATT&CK cũng kèm ở nhánh người duyệt

# ==========================================
# TRẠM HUMAN REVIEW & ĐỊNH TUYẾN
# ==========================================
def _human_review_reasons(state) -> list:
    """B4.3a — lý do chuyển người duyệt (lõi, áp cho mọi profile). Ngày 4 (Lớp 1) sẽ thêm lý do
    theo bảng quyết định; khi đó chỉ cần đặt agent_mode = "human_review_required" trước Reflection."""
    reasons = []
    if state.get("llm_error"):
        reasons.append(f"LLM lỗi, kết luận chỉ là giá trị lấp chỗ ({(state.get('llm_error_detail') or '')[:120]})")
    if state.get("knowledge_conflict"):
        reasons.append("Reflection thấy tài liệu RAG mâu thuẫn với bằng chứng trong log")
    if state.get("agent_mode") == "human_review_required" and not reasons:
        reasons.append("được yêu cầu người duyệt")
    return reasons


def node_human_review(state: SOCAgentState):
    print("\n[Trạm 5.5 - Human Review] 🛑 HỆ THỐNG TẠM DỪNG: CẦN SỰ PHÊ DUYỆT CỦA ADMIN!")
    reason = "; ".join(_human_review_reasons(state)) or "được yêu cầu người duyệt"
    _mitigations, _mit_note = attack_kb.recommend(state)
    # B4.3a: chỉ trả ghi chú MỚI — investigation_notes cộng dồn bằng operator.add, trả lại cả danh
    # sách cũ (như trước) sẽ nhân đôi toàn bộ nhật ký. Không thực thi hành động nào ở nhánh này.
    return {
        "agent_mode": "human_review_required",
        "action_taken": "human_review",
        "response_reason": f"Chờ người duyệt: {reason}. Chưa thực thi hành động nào.",
        "final_response": "Pending Human Approval",
        "mitigations": _mitigations,   # B10
        "investigation_notes": [f"System [Human-in-the-Loop]: Chuyển người duyệt — {reason}. "
                                f"Chưa thực thi hành động nào.", _mit_note],
    }

def route_after_reflection(state: SOCAgentState) -> str:
    # B4.3a: trước đây chỉ đọc agent_mode mà không trạm nào đặt → nhánh này không bao giờ chạy.
    return "human_review" if _human_review_reasons(state) else "responder"

# ==========================================
# DỰNG SƠ ĐỒ THẦN KINH (THE GRAPH)
# ==========================================
workflow = StateGraph(SOCAgentState)

workflow.add_node("extractor", node_extractor)
workflow.add_node("correlator", node_correlator)
workflow.add_node("enricher", node_enricher)
workflow.add_node("ticket_builder", node_ticket_builder)
workflow.add_node("retriever", node_retriever)
workflow.add_node("analyzer", node_analyzer)
workflow.add_node("reflection", node_reflection)
workflow.add_node("human_review", node_human_review) 
workflow.add_node("responder", node_responder)

workflow.set_entry_point("extractor")          
workflow.add_edge("extractor", "correlator")          
workflow.add_edge("correlator", "enricher")           # Ngày 2: làm giàu đứng ngay sau Correlator
workflow.add_edge("enricher", "ticket_builder")      # B5: làm giàu → TICKET → RAG → LLM (kế hoạch mục 3)
workflow.add_edge("ticket_builder", "retriever")
workflow.add_edge("retriever", "analyzer")            
workflow.add_edge("analyzer", "reflection")           

workflow.add_conditional_edges(
    "reflection",              
    route_after_reflection,    
    {"human_review": "human_review", "responder": "responder"}
)

workflow.add_edge("human_review", END)
workflow.add_edge("responder", END)                   

soc_app = workflow.compile()

# Xuất bản vẽ đồ thị (Dành cho Slide/Báo cáo)
print("\n[+] SƠ ĐỒ ĐỒ THỊ (COPY MÃ NÀY VÀO TRANG MERMAID.LIVE ĐỂ VẼ ẢNH):")
try:
    print(soc_app.get_graph().draw_mermaid())
except Exception as e:
    print("- Không thể xuất sơ đồ Mermaid:", e)

# ==========================================
# TRẠM KIỂM THỬ TƯƠNG TÁC ĐỘC LẬP
# ==========================================
if __name__ == "__main__":
    print("\n=======================================================")
    print("=== TRẠM KIỂM THỬ ĐỘC LẬP KMA AI SOC AGENT (WEEK 3) ===")
    print("=======================================================")
    
    global_timeline_memory = []
    
    while True:
        print("\n[1] Log sạch - Truy cập bình thường")
        print("[2] Log bẩn - SSRF (Web Attack)")
        print("[3] Log bẩn - DNS Tunneling (Tuồn dữ liệu)")
        print("[4] Log bẩn - Command Injection (RCE shell)")
        print("[q] Thoát vòng lặp")
        
        choice = input("Nhập lựa chọn của bạn: ").strip().lower()
        if choice == 'q':
            break
            
        # FIX BỞI CỐ VẤN: Đổi client_ip thành source_ip cho chuẩn
        fake_log = {
            "timestamp": "2026-06-12T13:00:00Z",
            "source_ip": "192.168.1.99"
        }
        
        if choice == "1":
            fake_log["event_type"] = "normal_traffic"
            fake_log["message"] = "User accessed /api/v1/users/profile successfully"
        elif choice == "2":
            fake_log["event_type"] = "web_attack"
            fake_log["message"] = "Cảnh báo WAF: Phát hiện SSRF tại /api/v1/tools/export-pdf"
        elif choice == "3":
            fake_log["event_type"] = "dns_query"
            fake_log["message"] = "Cảnh báo Suricata: Truy vấn TXT chứa chuỗi mã hóa"
        elif choice == "4":
            fake_log["event_type"] = "rce_attempt"
            fake_log["message"] = "Cảnh báo: Lệnh nc -e /bin/sh trong User-Agent"
        else:
            continue

        initial_state = {
            "raw_log": fake_log,
            "attack_timeline": global_timeline_memory, 
            "investigation_notes": [f"System: Nhận log sự kiện {fake_log.get('event_type')}"]
        }
        
        print(f"\n[*] Đang đẩy Log vào băng chuyền LangGraph...")
        result = soc_app.invoke(initial_state)
        
        # FIX BỞI CỐ VẤN: Lấy toàn bộ mảng đã cập nhật và cắt lấy 100 log mới nhất (Chống phình RAM)
        global_timeline_memory = result.get("attack_timeline", [])[-100:]
        
        print("\n[+] BÁO CÁO NHẬT KÝ ĐIỀU TRA CHI TIẾT:")
        for note in result.get("investigation_notes", []):
            print(f"  -> {note}")
            
        print("\n[+] KẾT QUẢ ĐẦU RA:")
        print(f"  - CHUỖI ID: {result.get('correlation_id', 'None')}")
        print(f"  - LỘ TRÌNH: {result.get('attack_chain_visual', 'None')}")
        print(f"  - MỨC ĐỘ RỦI RO: {result.get('incident_severity', 'Unknown').upper()}")
        print(f"  - ĐỘ TỰ TIN CỦA AI: {result.get('confidence_score', 0.0)}")
        print("=======================================================")