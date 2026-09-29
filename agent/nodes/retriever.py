import re  # [VŨ KHÍ MỚI] Thư viện Regex để quét chữ
from agent.state import SOCAgentState
from rag_engine.retriever import SOCRetriever

print("[*] Đang khởi động kết nối Trạm 2 với ChromaDB...")
# BẢO MẬT 1: Try/Except ngay lúc khởi tạo để hệ thống không sập nếu mất file DB
try:
    retriever_instance = SOCRetriever()
except Exception as e:
    print(f"[-] LỖI CRITICAL: Không thể khởi tạo Thủ thư -> {e}")
    retriever_instance = None

def node_retriever(state: SOCAgentState):
    print("\n[Trạm 2 - Retriever] Đang gọi Thủ thư RAG lấy bí kíp phòng thủ...")
    
    extracted_ioc = state.get("extracted_ioc", {})
    raw_log = state.get("raw_log", {})
    
    ips = extracted_ioc.get("ips", [])
    domains = extracted_ioc.get("domains", [])
    ports = extracted_ioc.get("ports", [])
    
    # BẢO MẬT 2: Tối ưu Query cho mô hình MiniLM (Concise Semantic Phrases)
    event_msg = raw_log.get("message", "Suspicious activity")
    
    query_parts = [event_msg]
    if ips: query_parts.append(f"IP {' '.join(ips)}")
    if domains: query_parts.append(f"domain {' '.join(domains)}")
    if ports: query_parts.append(f"port {' '.join(map(str, ports))}")
    
    # NÂNG CẤP: Ép về chữ thường (lowercase) để MiniLM đối chiếu ngữ nghĩa mượt hơn
    search_query = " | ".join(query_parts).lower()
    
    print(f"[*] Truy vấn Semantic đã tối ưu: '{search_query}'")
    
    rag_context = "No trusted context retrieved." # Giá trị mặc định nếu Fallback
    notes = [f"Retriever: Tạo truy vấn Semantic -> '{search_query[:70]}...'"]
    
    # [THÊM MỚI] Biến lưu điểm số cao nhất
    trust_score_max = 0.0 
    
    # BẢO MẬT 3: Fallback an toàn (Try/Except) khi truy vấn
    if retriever_instance:
        try:
            # Engine bên dưới (SOCRetriever) ĐÃ BAO GỒM logic Trust-Score Reranking
            rag_context = retriever_instance.retrieve_context(search_query, top_k=3)
            notes.append("Retriever: Trích xuất thành công Context qua lọc Trust Score.")
            
            # ==========================================
            # [THÊM MỚI] MÁY QUÉT ĐIỂM SỐ TỰ ĐỘNG BẰNG REGEX
            # ==========================================
            # Quét toàn bộ văn bản để tìm các con số sau chữ "Trust Score: "
            scores = re.findall(r"Trust Score:\s*([0-9.]+)", rag_context)
            if scores:
                # Lấy điểm cao nhất (VD: giữa 1.0 và 0.8 thì lấy 1.0)
                trust_score_max = max([float(s) for s in scores])
                notes.append(f"Retriever: Đã chốt Trust Score cao nhất = {trust_score_max}")
                
        except Exception as e:
            print(f"[-] Lỗi khi truy vấn ChromaDB: {e}")
            notes.append(f"Retriever: [CẢNH BÁO] RAG Engine lỗi -> {e}")
    else:
        notes.append("Retriever: [CẢNH BÁO] Bỏ qua truy xuất do Database không khả dụng.")

    return {
        "rag_context": rag_context,
        "context_trust_score": trust_score_max,  # [THÊM MỚI] Lưu điểm vào State để các Trạm sau không bị "Ngáo"
        "investigation_notes": notes
    }