# CLAUDE.md — Quy tắc làm việc cho đề tài AegisSOC

> Đọc file này TRƯỚC khi làm bất cứ việc gì trong repo. Người làm: Hiếu (một mình phần AI; bạn khác làm dataset và Splunk).

## 1. Bối cảnh

- Repo `KMA_AI_AGENT`: lõi AI Agent SOC — LangGraph + Llama 3.1 8B chạy cục bộ qua Ollama, API FastAPI (`api/main.py`), dashboard Streamlit (`dashboard/app.py`), RAG ChromaDB (`rag_engine/`).
- Kế hoạch chi tiết: `AegisSOC_00_tong-quan-va-ke-hoach.md` (trong Project, hoặc được gửi kèm). Bám đúng kiến trúc:
  `alert → prefilter 2 làn → Extractor → Correlator → làm giàu thủ công → ticket → LLM (Analyzer + Reflection) → Responder`
  và lịch 7 ngày ở mục 10 của file đó.
- Từ ngữ: nguồn ghi ra là **log**; Splunk xuất ra **alert**; LLM chỉ đọc **ticket**. Làm giàu là **tất định, không dùng LLM**.

## 2. Môi trường

- Windows, PowerShell, Python 3.12 trong `venv`, Ollama chạy native (`OLLAMA_HOST=http://127.0.0.1:11434`).
- Chạy mọi lệnh từ thư mục gốc repo. API: `uvicorn api.main:app --port 8000`. Dashboard: `streamlit run dashboard/app.py`.
- Cổng: Agent 8000 · Splunk Web 8001 · bridge 9000.

## 3. Cách làm việc

1. **Mỗi phiên chỉ làm MỘT bước** trong lịch.
2. **Trước khi sửa:** đọc các file liên quan, nói ngắn gọn định sửa gì, ở file nào. Hiếu đồng ý rồi mới viết code.
3. Việc cần chạy trên máy Hiếu (cài đặt, chạy Ollama/uvicorn/dashboard, test) → đưa lệnh PowerShell cụ thể và chờ Hiếu gửi kết quả.
4. **Không đọc, in hay commit `.env`.** SOAR luôn ở `SIMULATION`.
5. Việc có thể xoá dữ liệu (ví dụ `rag_engine/ingest.py` xoá `chroma_db`) → **hỏi trước**, nhắc sao lưu.
6. Không đổi tên trường hay cấu trúc state cũ nếu chưa cần — tránh vỡ code đang chạy. Sửa nhỏ, từng chỗ.
7. Không nâng phiên bản thư viện trong `requirements.txt` trừ khi có lỗi cụ thể và Hiếu đồng ý.

## 4. BẮT BUỘC sau mỗi lần sửa code — báo cáo thay đổi

Sau mỗi lần sửa (dù nhỏ), phải làm đủ hai việc:

### 4.1 Tóm tắt trong câu trả lời, theo mẫu

```
### Đã sửa gì
| File | Hàm / đoạn code | Thay đổi | Tác dụng |
|---|---|---|---|
| agent/nodes/xxx.py | tên_hàm() (dòng ~A–B) | thêm / sửa / xoá gì | để làm gì, ảnh hưởng tới phần nào của pipeline |

### Vì sao sửa như vậy
- 1–3 gạch ngắn: lý do, liên quan mục nào trong kế hoạch.

### Cách tự kiểm tra
- Lệnh chạy + kết quả mong đợi.

### Rủi ro / việc còn dở
- Chỗ nào chưa xong, chỗ nào có thể ảnh hưởng code cũ.

### Commit message gợi ý
- `Bx.y: ...`
```

### 4.2 Ghi thêm vào file `TIEN_DO.md` ở gốc repo

Thêm một mục MỚI lên đầu danh sách (mới nhất ở trên), theo mẫu:

```
## [YYYY-MM-DD] Bx.y — tên bước
- Trạng thái: xong / đang dở / lỗi chờ xử lý
- File đã sửa: ...
- Tóm tắt: sửa gì, tác dụng gì (2–4 dòng, viết để Hiếu đọc lại hiểu được)
- Kiểm tra: đã test chưa, kết quả
- Việc tiếp theo: ...
```

Không xoá hay viết lại các mục cũ trong `TIEN_DO.md`.

## 5. Khi xong một bước

- Đưa cách tự kiểm tra và commit message.
- Cập nhật `TIEN_DO.md`.
- Nhắc bước tiếp theo theo lịch.
