from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

def test_retrieval():
    print("[*] Đang kết nối vào ChromaDB...")
    # Load lại đúng model đã dùng để embed
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    
    # Kết nối vào thư mục database có sẵn
    db = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)
    
    # Câu hỏi thử nghiệm (Nhắm thẳng vào Giai đoạn 2 của Master Attack Chain)
    query = "Hacker is using DNS port 53 to exfiltrate data to hacker-domain.com. How to detect it?"
    
    print(f"[*] Câu hỏi truy vấn: '{query}'\n")
    
    # Tìm 2 kết quả sát nghĩa nhất
    results = db.similarity_search(query, k=2)
    
    if not results:
        print("[-] Không tìm thấy kết quả nào!")
        return

    for i, doc in enumerate(results):
        print(f"=== KẾT QUẢ SỐ {i+1} ===")
        print(f"- Nguồn (Source): {doc.metadata.get('source_type')}")
        print(f"- Kỹ thuật (Technique): {doc.metadata.get('technique_id', 'N/A')}")
        print(f"- Trust Score: {doc.metadata.get('trust_score')}")
        print(f"- Nội dung trích xuất (Preview):\n{doc.page_content[:200]}...\n")

if __name__ == "__main__":
    test_retrieval()