import os
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from agent.chroma_lock import chroma_lock as _chroma_lock

# Cấu hình đường dẫn
current_dir = os.path.dirname(os.path.abspath(__file__))
# B4 (Ngày 3): kho RAG chọn theo DEFENSE_PROFILE — mỗi bản Agent một kho riêng (core/profile.py).
# Chưa tạo kho riêng thì core/profile.py tự lùi về kho gốc chroma_db/ như trước.
from core.profile import RAG_STORE_DIR
CHROMA_PATH = RAG_STORE_DIR
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

class SOCRetriever:
    def __init__(self):
        print("[*] Đang khởi tạo Người Thủ Thư (SOC Retriever)...")
        print(f"[*] Kho RAG đang dùng: {CHROMA_PATH}")
        self.embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL_NAME)
        self.db = Chroma(persist_directory=CHROMA_PATH, embedding_function=self.embeddings)
        print("[+] Kết nối kho tri thức thành công!")
        
        # ====================================================
        # MÁY QUÉT X-QUANG: Kiểm kê xem DB có Sigma Rule không
        # ====================================================
        try:
            sigma_docs = self.db.get(where={"source_type": "admin_sigma_rule"})
            ids_data = sigma_docs.get('ids', [])
            
            # FIX LỖI LEN(): Nếu là số thì lấy luôn, nếu là mảng thì mới đếm
            sigma_count = ids_data if isinstance(ids_data, int) else len(ids_data)
            print(f"[+] KHO KIỂM KÊ: Chẩn đoán thấy {sigma_count} mảnh ghép Sigma Rule trong DB.")
            if sigma_count == 0:
                print("[-] BÁO ĐỘNG ĐỎ: Không có Sigma Rule nào trong DB! Chắc chắn file Ingest nạp lỗi!")
        except Exception as e:
            print(f"[-] LỖI KIỂM KÊ: Không thể đếm được Sigma Rule -> {e}")

    def retrieve_context(self, query: str, top_k: int = 3) -> str:
        """
        [KIẾN TRÚC MỚI] FEDERATED SEARCH - TRUY VẤN PHÂN LUỒNG ĐỘC LẬP
        """
        # Serialize toàn bộ DB access — tránh concurrent PersistentClient → Rust panic
        with _chroma_lock:
            # LUỒNG 1: Ép Thủ thư mò vào đúng ngăn chứa Sigma Rule (Bốc 2 cuốn)
            try:
                sigma_results = self.db.similarity_search(
                    query,
                    k=2,
                    filter={"source_type": "admin_sigma_rule"}
                )
            except:
                sigma_results = []

            # LUỒNG 2: Ép Thủ thư mò vào ngăn chứa MITRE Framework (Bốc 5 cuốn)
            try:
                mitre_results = self.db.similarity_search(
                    query,
                    k=5,
                    filter={"source_type": "mitre_framework"}
                )
            except:
                mitre_results = []

        # BƯỚC 3: Gộp hai luồng lại thành 1 mảng chung
        raw_results = sigma_results + mitre_results
        
        if not raw_results:
            return "Không tìm thấy thông tin hướng dẫn nào trong hệ thống RAG."

        # BƯỚC 4: Cuộc chiến sinh tử - Sắp xếp theo Trust Score (1.0 vs 0.8)
        raw_results.sort(key=lambda x: x.metadata.get("trust_score", 0.0), reverse=True)
        
        # Cắt lấy đúng số lượng cần thiết
        final_results = raw_results[:top_k]

        # ── SOURCE INTEGRITY CHECK ──────────────────────────────────────────
        # Chỉ tin tài liệu từ nguồn đã kiểm duyệt. Bất kỳ document nào claim
        # source_type hợp lệ nhưng có metadata lạ (injected_by, policy_update,
        # source_service không phải ingest chính thức) đều bị loại bỏ.
        _TRUSTED_SOURCES   = {"admin_sigma_rule", "mitre_framework"}
        _TRUSTED_INJECTORS = {None, "", "sigma_ingest", "mitre_ingest", "admin_loader"}
        _SUSPECT_KEYS      = {"injected_by", "document_type"}
        _SUSPECT_VALUES    = {"policy_update", "sync-service", "policy_sync"}

        clean_results = []
        for doc in final_results:
            meta = doc.metadata
            src  = meta.get("source_type", "")
            # Loại nếu không phải nguồn tin cậy
            if src not in _TRUSTED_SOURCES:
                print(f"[Retriever GUARD] Loại bỏ document có source_type='{src}' (không tin cậy)")
                continue
            # Loại nếu có metadata đáng ngờ (dấu hiệu RAG Poisoning)
            injected_by = meta.get("injected_by", None)
            doc_type    = meta.get("document_type", None)
            if injected_by not in _TRUSTED_INJECTORS:
                print(f"[Retriever GUARD] Loại bỏ document có injected_by='{injected_by}'")
                continue
            if doc_type in _SUSPECT_VALUES:
                print(f"[Retriever GUARD] Loại bỏ document có document_type='{doc_type}'")
                continue
            # Loại nếu trust_score do document tự khai vượt quá ngưỡng hợp lý
            # (admin sigma luôn = 1.0, mitre = 0.8 — giá trị 0.88-0.97 là bất thường)
            claimed_score = float(meta.get("trust_score", 0.0))
            if src == "mitre_framework" and claimed_score > 0.85:
                print(f"[Retriever GUARD] Kẹp trust_score mitre {claimed_score}→0.80 (bất thường)")
                # Không loại bỏ, chỉ kẹp xuống để không ảnh hưởng ranking
                doc.metadata["trust_score"] = 0.80
            clean_results.append(doc)
        # ────────────────────────────────────────────────────────────────────

        context_text = ""
        for i, doc in enumerate(clean_results):
            source = doc.metadata.get("source_type", "Unknown")
            tech_id = doc.metadata.get("technique_id", "N/A")
            score = doc.metadata.get("trust_score", 0.0)

            context_text += f"\n--- TÀI LIỆU {i+1} (Nguồn: {source.upper()} | ID: {tech_id} | Trust Score: {score}) ---\n"
            context_text += doc.page_content + "\n"

        return context_text if context_text else "Không tìm thấy thông tin hướng dẫn nào trong hệ thống RAG."

# --- TEST THỬ NGƯỜI THỦ THƯ ---
if __name__ == "__main__":
    retriever = SOCRetriever()
    
    test_query = "cảnh báo waf: phát hiện ssrf tại /api/v1/tools/export-pdf | ip 192.168.1.99"
    print(f"\n[*] Đang truy vấn: '{test_query}'")
    
    ai_context = retriever.retrieve_context(test_query, top_k=5)
    
    print("\n[ KẾT QUẢ ĐÃ QUA BỘ LỌC TRUST SCORE ]")
    print(ai_context)