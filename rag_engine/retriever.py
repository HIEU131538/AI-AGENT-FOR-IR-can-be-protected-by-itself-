"""
rag_engine/retriever.py — B4.3b: TRA CỨU v2 = tra đúng + tìm lai (từ khoá BM25 + ngữ nghĩa), có ngưỡng

Thứ tự lấy tài liệu cho một alert:
  1. TRA ĐÚNG luật đã bắn alert (theo rule_name) → mô tả + falsepositives của chính luật đó.
  2. TRA ĐÚNG kỹ thuật ATT&CK mà luật gắn (theo attack_ids) → tổng quan + cách phát hiện.
  3. TÌM LAI để bổ sung tối đa k_related tài liệu liên quan:
       - BM25 (khớp từ khoá: certutil, w3wp.exe, -urlcache, T1059.001…) — tự viết, không thêm thư viện;
       - ngữ nghĩa (MiniLM, cosine);
       - gộp 2 bảng xếp hạng bằng RRF; bỏ tài liệu ngữ nghĩa dưới ngưỡng RAG_MIN_COS (mặc định 0.35).
  Không còn "ép luật Sigma lên đầu theo trust score" như bản cũ.
Kho vẫn chọn theo DEFENSE_PROFILE (core/profile.py). Bộ lọc nguồn tin cậy giữ nguyên như bản cũ.
"""
import math
import os
import re
from collections import Counter

from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from agent.chroma_lock import chroma_lock as _chroma_lock
from core.profile import RAG_STORE_DIR

CHROMA_PATH = RAG_STORE_DIR
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
MIN_COS = float(os.getenv("RAG_MIN_COS", "0.35"))
RRF_K = 60
# Trần độ dài context: prompt của Llama có giới hạn cửa sổ (num_ctx) — thêm tài liệu theo thứ tự ưu tiên
# (luật → kỹ thuật → liên quan) cho tới khi chạm trần; tài liệu đầu tiên luôn được giữ.
MAX_CONTEXT_CHARS = int(os.getenv("RAG_MAX_CONTEXT_CHARS", "3500"))

_TRUSTED_SOURCES = {"admin_sigma_rule", "mitre_framework"}
_TRUSTED_INJECTORS = {None, "", "sigma_ingest", "mitre_ingest", "admin_loader"}
_SUSPECT_VALUES = {"policy_update", "sync-service", "policy_sync"}
_STOP = {"the", "of", "and", "or", "to", "in", "for", "is", "on", "with", "by", "via", "from",
         "as", "be", "are", "this", "that", "it", "at", "may", "can", "not", "n/a", "none"}
_HOW_LABEL = {
    "exact_rule": "the rule that fired this alert",
    "exact_technique": "ATT&CK technique of the rule",
    "related": "related (found by content search - may not match exactly)",
}


def _tokens(text: str):
    # tách cả theo \ và / để "C:\Windows\System32\w3wp.exe" cho ra "w3wp.exe" — khớp mẫu "\w3wp.exe" của luật Sigma
    return [t for t in re.findall(r"[a-z0-9][a-z0-9_.-]*[a-z0-9]|[a-z0-9]", (text or "").lower())
            if t not in _STOP and len(t) > 1]


class _BM25:
    """BM25 Okapi tối giản (k1=1.5, b=0.75) trên toàn bộ tài liệu của kho."""

    def __init__(self, docs, k1=1.5, b=0.75):
        self.k1, self.b = k1, b
        self.tf = [Counter(_tokens(d)) for d in docs]
        self.len = [sum(c.values()) for c in self.tf]
        self.avg = (sum(self.len) / len(self.len)) if self.len else 1.0
        df = Counter(t for c in self.tf for t in c)
        n = len(docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def top(self, query, k=10):
        q = set(_tokens(query))
        scores = []
        for i, c in enumerate(self.tf):
            s = 0.0
            for t in q:
                f = c.get(t)
                if f:
                    s += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.len[i] / self.avg))
            if s > 0:
                scores.append((s, i))
        scores.sort(reverse=True)
        return scores[:k]


def _trusted(meta) -> bool:
    meta = meta or {}
    return (meta.get("source_type") in _TRUSTED_SOURCES
            and meta.get("injected_by") in _TRUSTED_INJECTORS
            and meta.get("document_type") not in _SUSPECT_VALUES)


def _name(meta) -> str:
    if meta.get("source_type") == "admin_sigma_rule":
        return f"Sigma: {meta.get('title', '?')} (rule level {meta.get('level', '?')})"
    kind = "detection" if meta.get("doc_kind") == "mitre_detection" else "overview"
    return f"ATT&CK {meta.get('technique_id', '?')} {meta.get('technique_name', '')} — {kind}"


class SOCRetriever:
    def __init__(self):
        print("[*] Đang khởi tạo Người Thủ Thư (SOC Retriever v2)...")
        print(f"[*] Kho RAG đang dùng: {CHROMA_PATH}")
        self.embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL_NAME,
                                                encode_kwargs={"normalize_embeddings": True})
        self.db = Chroma(persist_directory=CHROMA_PATH, embedding_function=self.embeddings)
        self.space = (self.db._collection.metadata or {}).get("hnsw:space", "l2")
        self._n = -1
        self._ensure_index()
        n_sigma = sum(1 for m in self._metas if m.get("source_type") == "admin_sigma_rule")
        v2 = any(m.get("ingest_version") == "v2" for m in self._metas)
        print(f"[+] KHO KIỂM KÊ: {self._n} tài liệu · {n_sigma} luật Sigma · không gian {self.space}"
              + ("" if v2 else " · CẢNH BÁO: kho bản cũ, chưa nạp lại bằng ingest v2"))

    def _ensure_index(self):
        """Dựng lại chỉ mục BM25 khi số tài liệu đổi (vd. thí nghiệm đầu độc RAG thêm tài liệu lúc chạy)."""
        with _chroma_lock:
            n = self.db._collection.count()
            if n == self._n:
                return
            got = self.db.get(include=["documents", "metadatas"])
        self._ids, self._docs = got["ids"], got["documents"]
        self._metas = [m or {} for m in got["metadatas"]]
        self._pos = {d: i for i, d in enumerate(self._ids)}
        self._by_text = {t: d for d, t in zip(self._ids, self._docs)}
        self._bm25 = _BM25(self._docs)
        self._n = n

    def _cos(self, dist: float) -> float:
        # cosine: khoảng cách = 1 − cos. l2 (Chroma dùng bình phương L2, vector đã chuẩn hoá): d = 2 − 2·cos
        return 1.0 - dist if self.space == "cosine" else 1.0 - dist / 2.0

    def _get(self, where):
        with _chroma_lock:
            got = self.db.get(where=where, include=["documents", "metadatas"])
        rows = [(i, d, m or {}) for i, d, m in zip(got["ids"], got["documents"], got["metadatas"])]
        rows = [r for r in rows if _trusted(r[2])]
        rows.sort(key=lambda r: (not r[2].get("base_rule", False), r[0]))
        return rows

    def retrieve(self, query: str, rule_name: str = None, attack_ids=None, k_related: int = 2) -> dict:
        self._ensure_index()
        picked, used = [], set()

        def add(doc_id, text, meta, how, score):
            if doc_id not in used:
                used.add(doc_id)
                picked.append({"id": doc_id, "text": text, "meta": meta, "how": how, "score": score})

        # 1. luật đã bắn alert
        if rule_name and rule_name.strip():
            for doc_id, text, meta in self._get({"$and": [{"source_type": {"$eq": "admin_sigma_rule"}},
                                                          {"title_norm": {"$eq": rule_name.strip().lower()}}]})[:1]:
                add(doc_id, text, meta, "exact_rule", 1.0)
        # 2. kỹ thuật ATT&CK của luật: tổng quan cho 2 mã đầu, cách phát hiện cho mã đầu
        tids = [t.strip().upper() for t in (attack_ids or []) if isinstance(t, str) and t.strip()]
        for n, tid in enumerate(tids[:2]):
            for kind in (["mitre_overview", "mitre_detection"] if n == 0 else ["mitre_overview"]):
                for doc_id, text, meta in self._get({"$and": [{"technique_id": {"$eq": tid}},
                                                              {"doc_kind": {"$eq": kind}}]})[:1]:
                    add(doc_id, text, meta, "exact_technique", 1.0)
        # 3. tìm lai: ngữ nghĩa (có ngưỡng) + BM25, gộp bằng RRF
        if query and query.strip() and k_related > 0:
            with _chroma_lock:
                dense = self.db.similarity_search_with_score(query, k=20)
            dense_rank, cos_of = [], {}
            for doc, dist in dense:
                doc_id = getattr(doc, "id", None) or self._by_text.get(doc.page_content)
                if doc_id is None:
                    continue
                cos_of[doc_id] = self._cos(dist)
                if cos_of[doc_id] >= MIN_COS:
                    dense_rank.append(doc_id)
            bm = self._bm25.top(query, k=10)
            best = bm[0][0] if bm else 0.0
            bm_rank = [self._ids[i] for s, i in bm if s >= max(1.0, 0.3 * best)]
            fused = Counter()
            for rank_list in (dense_rank, bm_rank):
                for r, doc_id in enumerate(rank_list):
                    fused[doc_id] += 1.0 / (RRF_K + r + 1)
            n_related = 0
            for doc_id, _ in fused.most_common():
                i = self._pos.get(doc_id)
                if i is None or doc_id in used or not _trusted(self._metas[i]):
                    continue
                add(doc_id, self._docs[i], self._metas[i], "related",
                    round(cos_of[doc_id], 3) if doc_id in cos_of else None)
                n_related += 1
                if n_related >= k_related:
                    break

        kept, total = [], 0
        for p in picked:
            if kept and total + len(p["text"]) > MAX_CONTEXT_CHARS:
                continue
            kept.append(p)
            total += len(p["text"])
        picked = kept

        context = ""
        for n, p in enumerate(picked, 1):
            context += f"\n--- DOCUMENT {n} [{_HOW_LABEL[p['how']]}] ({_name(p['meta'])}) ---\n{p['text']}\n"
        return {
            "context": context or "No matching reference documents.",
            "docs": [{"id": p["id"], "how": p["how"], "score": p["score"],
                      "source_type": p["meta"].get("source_type"), "doc_kind": p["meta"].get("doc_kind"),
                      "name": _name(p["meta"]), "trust_score": float(p["meta"].get("trust_score", 0.0))}
                     for p in picked],
        }

    def retrieve_context(self, query: str, top_k: int = 3) -> str:
        """Tương thích ngược với code cũ gọi retrieve_context(query, top_k)."""
        return self.retrieve(query, k_related=top_k)["context"]
