"""
agent/nodes/retriever.py — Trạm 2: lấy tài liệu tham khảo từ kho RAG (B4.3b: bản v2)

Khác bản cũ:
  - Câu truy vấn ghép từ TÊN LUẬT + NỘI DUNG BẰNG CHỨNG (URI, User-Agent, CommandLine, Image, truy vấn DNS…).
    Bỏ IP và số cổng — chúng không mang nghĩa, trước đây kéo luật "IP/Port Scanner" lên đầu ở 11/40 kịch bản.
  - Truyền rule_name + attack_ids của alert để tra đúng luật đã bắn và kỹ thuật ATT&CK (xem rag_engine/retriever.py).
  - Trả thêm `rag_docs` (danh sách tài liệu đã dùng: id, cách lấy, điểm) — cho chẩn đoán và khối `rag` ở Ngày 5.
  - Trust score lấy từ metadata tài liệu, không dò chuỗi "Trust Score:" trong văn bản nữa.
"""
from agent.state import SOCAgentState
from rag_engine.retriever import SOCRetriever

print("[*] Đang khởi động kết nối Trạm 2 với ChromaDB...")
try:
    retriever_instance = SOCRetriever()
except Exception as e:
    print(f"[-] LỖI CRITICAL: Không thể khởi tạo Thủ thư -> {e}")
    retriever_instance = None

# Trường mang nội dung bằng chứng (theo thứ tự ưu tiên). Tên trường gốc trùng hợp đồng có tiền tố orig_.
EVIDENCE_KEYS = [
    "request_method", "request_uri", "uri", "url", "query_string", "request_body", "body",
    "http_user_agent", "user_agent",
    "Image", "CommandLine", "ParentImage", "ParentCommandLine", "TargetObject", "Details",
    "QueryName", "dns_query", "query", "rrname", "signature", "app_proto",
]
NO_CONTEXT_TRUST = 0.5   # không có tài liệu → trung tính: không phạt ở Analyzer, không bật luật mâu thuẫn ở Reflection


def _flat_values(raw: dict):
    out = {}
    for k, v in (raw or {}).items():
        key = k[5:] if k.startswith("orig_") else k
        if isinstance(v, dict):          # vd. Suricata: alert.signature, dns.rrname
            for k2, v2 in v.items():
                if not isinstance(v2, (dict, list)):
                    out.setdefault(k2, v2)
        elif not isinstance(v, list):
            out.setdefault(key, v)
    return out


def build_query(state) -> str:
    alert = state.get("alert") or {}
    raw = state.get("raw_log") or {}
    rule = alert.get("rule_name") or raw.get("rule_name") or ""
    vals = _flat_values(raw)
    parts = []
    for k in EVIDENCE_KEYS:
        v = str(vals.get(k) or "")[:200]
        if v and v not in parts:        # B5.1: uri và request_uri (khoá chuẩn thêm vào) trùng giá trị → lấy 1 lần
            parts.append(v)
    if not rule and not parts:                      # đường /analyze cũ không có gì khác
        parts = [str(raw.get("message", ""))]
    return (f"{rule}. " + " ".join(parts))[:600].strip(" .")


def node_retriever(state: SOCAgentState):
    print("\n[Trạm 2 - Retriever] Đang gọi Thủ thư RAG lấy tài liệu tham khảo...")
    alert = state.get("alert") or {}
    raw = state.get("raw_log") or {}
    rule_name = alert.get("rule_name") or raw.get("rule_name")
    attack_ids = alert.get("attack_ids") or raw.get("attack_ids") or []
    query = build_query(state)
    notes = [f"Retriever: truy vấn = '{query[:90]}' · luật = {rule_name or '-'} · ATT&CK = {attack_ids or '-'}"]

    rag_context, rag_docs, trust = "No matching reference documents.", [], NO_CONTEXT_TRUST
    rag_block = {}
    if retriever_instance:
        try:
            res = retriever_instance.retrieve(query, rule_name=rule_name, attack_ids=attack_ids, k_related=2)
            rag_context, rag_docs = res["context"], res["docs"]
            rag_block = res.get("rag") or {}
            if rag_block.get("injected_in_context"):
                notes.append(f"Retriever [Lớp 5]: CẢNH BÁO — tài liệu lạ LỌT vào context: {rag_block['injected_in_context']}")
            elif rag_block.get("injected_rejected"):
                notes.append(f"Retriever [Lớp 5]: đã LOẠI tài liệu lạ (không có trong manifest): {rag_block['injected_rejected']}")
            if rag_docs:
                trust = max(d.get("trust_score", 0.0) for d in rag_docs)
            how = ", ".join(f"{d['how']}:{d['id']}" for d in rag_docs) or "không có"
            notes.append(f"Retriever: {len(rag_docs)} tài liệu ({how})")
        except Exception as e:
            print(f"[-] Lỗi khi truy vấn ChromaDB: {e}")
            notes.append(f"Retriever: [CẢNH BÁO] RAG Engine lỗi -> {e}")
    else:
        notes.append("Retriever: [CẢNH BÁO] Bỏ qua truy xuất do Database không khả dụng.")

    return {
        "rag_context": rag_context,
        "rag_docs": rag_docs,
        "rag": rag_block,
        "context_trust_score": trust,
        "investigation_notes": notes,
    }
