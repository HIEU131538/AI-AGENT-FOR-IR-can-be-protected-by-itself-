import json
import os
import hashlib
import yaml
import shutil
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

current_dir = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(current_dir, "../data"))
MITRE_FILE = os.path.join(DATA_DIR, "mitre_cti.json")
SIGMA_DIR = os.path.join(DATA_DIR, "sigma_rules")
CHROMA_PATH = "./chroma_db"

EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
ATTACK_VERSION = "v19"

def parse_mitre_graph_v2(filepath):
    if not os.path.exists(filepath):
        print(f"[-] Không thấy file MITRE tại {filepath}")
        return []

    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    objects = data.get('objects', [])
    mitigations_dict = {obj['id']: f"[{obj.get('name', 'N/A')}] {obj.get('description', '')}" 
                        for obj in objects if obj.get('type') == 'course-of-action'}

    tech_to_miti = {}
    for obj in objects:
        if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates':
            s, t = obj.get('source_ref'), obj.get('target_ref')
            if t not in tech_to_miti: tech_to_miti[t] = []
            if s in mitigations_dict: tech_to_miti[t].append(mitigations_dict[s])

    docs = []
    seen_hashes = set()

    for obj in objects:
        if obj.get('type') == 'attack-pattern' and not (obj.get('revoked') or obj.get('x_mitre_deprecated')):
            t_id = next((r['external_id'] for r in obj.get('external_references', []) if r['source_name'] == 'mitre-attack'), "N/A")
            
            # Khai thác tối đa Metadata theo lời khuyên chuyên gia
            platforms_list = obj.get('x_mitre_platforms', [])
            if not platforms_list: platforms_list = ["Unknown"]
            
            data_sources_list = obj.get('x_mitre_data_sources', [])
            if not data_sources_list: data_sources_list = ["Unknown"]
            
            tactics_list = [p['phase_name'].replace('-', ' ').title() for p in obj.get('kill_chain_phases', []) if p['kill_chain_name'] == 'mitre-attack']
            if not tactics_list: tactics_list = ["Unknown"]
            
            is_sub = obj.get('x_mitre_is_subtechnique', False)
            mitigations = "\n".join(tech_to_miti.get(obj['id'], [])) or "No specific mitigation."

            # Vẫn giữ trong page_content để model đọc ngữ nghĩa
            content = (
                f"Technique: {obj.get('name')} ({t_id})\n"
                f"Tactics: {', '.join(tactics_list)}\n"
                f"Platforms: {', '.join(platforms_list)}\n"
                f"Data Sources: {', '.join(data_sources_list)}\n"
                f"Description: {obj.get('description')}\n"
                f"Mitigations: {mitigations}"
            )
            
            c_hash = hashlib.sha256(content.encode()).hexdigest()
            if c_hash not in seen_hashes:
                seen_hashes.add(c_hash)
                docs.append(Document(
                    page_content=content,
                    metadata={
                        "technique_id": t_id, 
                        "tactics": tactics_list,             # Cực mạnh cho filter
                        "platforms": platforms_list,         # Cực mạnh cho filter
                        "data_sources": data_sources_list,   # Truy vết log liên quan
                        "is_subtechnique": is_sub,           # Tách biệt kỹ thuật cha/con
                        "trust_score": 0.8, 
                        "source_type": "mitre_framework",
                        "attack_version": ATTACK_VERSION,
                        "embedding_model": EMBEDDING_MODEL_NAME,
                        "hash": c_hash
                    }
                ))
    return docs

def parse_sigma_rules_v2(folder_path):
    docs = []
    if not os.path.exists(folder_path): return docs

    for file in os.listdir(folder_path):
        if file.endswith((".yml", ".yaml")):
            with open(os.path.join(folder_path, file), 'r', encoding='utf-8') as f:
                try:
                    # [VŨ KHÍ MỚI]: Đọc raw_text và bọc thêm lớp vỏ Tiếng Việt
                    raw_text = f.read()
                    f.seek(0)
                    rule = yaml.safe_load(f)
                    
                    # Bỏ qua file rỗng
                    if not rule or not isinstance(rule, dict): 
                        print(f"  [!] Bỏ qua {file} vì file đang trống hoặc không hợp lệ.")
                        continue

                    title = rule.get('title', 'Unknown')
                    level = str(rule.get('level', 'medium'))
                    
                    # Phiên dịch YAML sang văn bản tự nhiên để AI hiểu ngữ nghĩa
                    content = f"Tài liệu hướng dẫn phát hiện tấn công (Sigma Rule): {title}.\n"
                    content += f"Mức độ rủi ro: {level.upper()}.\n"
                    content += f"Nếu thấy các từ khóa hoặc dấu hiệu sau trong log, đây chắc chắn là cuộc tấn công:\n{raw_text}"
                    
                    c_hash = hashlib.sha256(content.encode()).hexdigest()
                    docs.append(Document(
                        page_content=content,
                        metadata={
                            "title": title, 
                            "level": level,
                            "trust_score": 1.0, # Điểm tuyệt đối
                            "source_type": "admin_sigma_rule",
                            "embedding_model": EMBEDDING_MODEL_NAME,
                            "hash": c_hash
                        }
                    ))
                except yaml.YAMLError as e:
                    print(f"[-] Lỗi cú pháp YAML tại file {file}: {e}")
                    continue
    return docs

def run_ingestion():
    # Dọn dẹp Database cũ trước khi Ingest (LỜI KHUYÊN SỐ 5)
    if os.path.exists(CHROMA_PATH):
        print(f"[*] Đang dọn dẹp Database cũ tại {CHROMA_PATH} để tránh trùng lặp vector...")
        shutil.rmtree(CHROMA_PATH)

    print("[*] GIAI ĐOẠN 1: Đang parse dữ liệu...")
    all_docs = parse_mitre_graph_v2(MITRE_FILE) + parse_sigma_rules_v2(SIGMA_DIR)
    if not all_docs:
        print("[-] LỖI NGHIÊM TRỌNG: Không tìm thấy bất kỳ tài liệu nào!")
        print(f"[*] Vui lòng kiểm tra file tại: {MITRE_FILE}")
        return # Dừng lại luôn, không chạy tiếp xuống ChromaDB
    print(f"[+] Tổng cộng: {len(all_docs)} tài liệu gốc.")

    print("[*] GIAI ĐOẠN 2: Đang băm nhỏ (Chunking)...")
    splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=120)
    chunks = splitter.split_documents(all_docs)
    
    # Tạo Deterministic IDs cho từng chunk (LỜI KHUYÊN SỐ 6)
    for i, chunk in enumerate(chunks):
        chunk_hash = hashlib.sha256((chunk.page_content + str(chunk.metadata)).encode()).hexdigest()
        chunk.metadata["chunk_id"] = chunk_hash
    
    print(f"[+] Đã băm thành {len(chunks)} chunks.")

    print("[*] GIAI ĐOẠN 4: Đang nhúng Vector và lưu ChromaDB...")
    embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL_NAME)
    
    # Bơm cả list ID vào ChromaDB
    chunk_ids = [chunk.metadata["chunk_id"] for chunk in chunks]
    for chunk in chunks: # Lưu ý: Nếu biến chứa dữ liệu của cậu tên là 'docs' hoặc 'splits', hãy thay chữ 'chunks' nhé
        for key, value in chunk.metadata.items():
            if isinstance(value, list):
            # Ép kiểu danh sách thành một chuỗi liên tục
                chunk.metadata[key] = ", ".join([str(v) for v in value])
    vector_db = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory=CHROMA_PATH,
        ids=chunk_ids
    )
    print(f"[+] THÀNH CÔNG! Database cực sạch đã sẵn sàng tại: {CHROMA_PATH}")

if __name__ == "__main__":
    run_ingestion()