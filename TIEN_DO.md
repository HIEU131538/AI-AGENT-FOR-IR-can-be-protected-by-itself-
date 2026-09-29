# TIẾN ĐỘ — AegisSOC

> Nhật ký thay đổi. Mục mới nhất ở trên cùng. Mỗi lần sửa code đều thêm một mục (xem `CLAUDE.md` mục 4).

## [2026-09-29] B4.1 — báo lỗi LLM thay vì nuốt lỗi + kiểm trước khi đo (preflight)
- Trạng thái: code xong, đã test (node thật 5/5 với Ollama tắt; API + preflight 4 tình huống; script phát lại hiện lỗi; hồi quy Ngày 2 21/21; Python 3.10). Chờ Hiếu sửa kết nối Ollama rồi đo lại baseline.
- Lý do: baseline bản `off` lần 1 KHÔNG hợp lệ — Agent không gọi được Ollama, Analyzer bắt lỗi rồi âm thầm trả `low` + `IGNORE` trong ~0,3 s; bộ đo tính đó là phán quyết thật → ASR 1.000 giả. Thư mục `baseline_off/` lần đó phải bỏ (đổi tên `baseline_off_INVALID`).
- File đã sửa: `agent/state.py` (thêm `llm_error`, `llm_error_detail`), `agent/nodes/analyzer.py` (3 nhánh trả cờ lỗi), `agent/nodes/reflection.py` (`_mark_llm_error`, chỉ nối thêm, không xoá lỗi của Analyzer), `api/main.py` (`_ollama_status()`, log khởi động `[LLM]`, `/health` có khối `llm`, results có `status: "llm_error"` + `detail`), `eval/common.py` (`preflight()`), `eval/eval_golden.py` (gọi preflight trước khi đo, cờ `--skip-preflight`), `eval/preflight.py` (mới, chạy tay)
- Tóm tắt: LLM lỗi → alert trả `status: "llm_error"` kèm lý do thay vì `analyzed`; `extract_prediction` coi đó là ca lỗi → không được chấm đúng, bị đếm vào "Tỷ lệ JSON lỗi". Giá trị `low` lấp chỗ vẫn còn trong state nhưng không ai được dùng nó làm kết quả. Preflight kiểm 3 điều: đúng profile ở đúng cổng · `/health` báo gọi được Ollama · một alert thử chạy xong, không lỗi, tốn ≥ 1,5 s. `eval_golden` không đạt preflight → dừng, không ghi `table4.csv`.
- Kiểm tra: Ollama tắt → `/health` `llm.reachable=false`, preflight thoát mã 1, `eval_golden` dừng không ghi bảng; alert xong quá nhanh → preflight báo lỗi; bình thường → preflight OK, đo chạy; `llm_error` được đếm vào tỷ lệ lỗi = 1.0; `replay_alerts.py` in `[-] lỗi phân tích: Analyzer: ConnectionError…` và đếm lỗi 3/3.
- Việc tiếp theo: Hiếu sửa kết nối Ollama cho terminal chạy bản `off` → `python -m eval.preflight --profile off` → **MỐC ĐO: chạy lại baseline Bảng 2 (dòng 0) + Bảng 4 (cột off)**. Bạn làm eval thêm bước preflight vào `eval_injection.py` giống `eval_golden.py`.

## [2026-09-29] B4 (Ngày 3) — công tắc `DEFENSE_PROFILE` + kho RAG riêng cho từng profile
- Trạng thái: code xong, đã test (công tắc 13/13; script sao kho 7 tình huống trên bản sao SQLite thật; 2 bản Agent chạy song song; hồi quy Ngày 2 21/21, Python 3.10). Chờ Hiếu tạo kho riêng + chạy thật.
- File đã sửa: `core/profile.py` (mới), `tools/make_rag_stores.py` (mới), `rag_engine/retriever.py` (đường dẫn kho, dòng ~6–11), `api/main.py` (log khởi động, `/health`, `defense_profile` trong kết quả), `.gitignore` (`rag_stores/`)
- Tóm tắt: Agent đọc `DEFENSE_PROFILE` (`off / l1 / l12 / full`) lúc khởi động; sai giá trị → dừng; không đặt → `off` + cảnh báo. `core/profile.py` là nơi duy nhất trả lời "lớp phòng vệ nào đang bật" (`layer_enabled(n)`: off={}, l1={1}, l12={1,2}, full={1,2,4,5}) — các bước sau chỉ hỏi hàm này. Kho RAG chọn theo thứ tự: `RAG_STORE_DIR` → `rag_stores/<profile>/` → kho gốc `chroma_db/` (kèm cảnh báo). Script sao kho kiểm kho gốc trước — có tài liệu không rõ nguồn thì từ chối — rồi sao thành 4 kho, đếm lại từng kho, ghi `rag_stores/_copies.json`. Bản `off` hoạt động y hệt trước. CHƯA có lớp phòng vệ nào được code — công tắc chỉ là nền cho B6, Ngày 4, Ngày 5.
- Kiểm tra: kho bẩn (còn `sync_policy_…`) → từ chối; kho sạch 7.719 chunk → 4 kho, mỗi kho 7.719; chạy lại không `--force` → giữ nguyên; `--force --profiles full` → chỉ tạo lại full; kho gốc không bị sửa. `/health` bản off/full đúng; `call_agent` trả `defense_profile` đúng từng bản.
- Việc tiếp theo: Hiếu tắt uvicorn → `python tools\make_rag_stores.py` → chạy bản `off` ở 8010. **MỐC ĐO: baseline Bảng 2 (dòng 0) + Bảng 4 (cột off) trên bản `off`, TRƯỚC khi viết code phòng thủ.** Sau đó B5 (ticket hai ngăn).

## [2026-09-29] B3.2 — `eval_golden.py` loại ca lỗi + sửa `.gitignore`
- Trạng thái: xong, đã test (chạy trọn `eval_golden.py` với Agent cổng 8010; chấm ca lỗi 3/3)
- File đã sửa: `eval/eval_golden.py` (`score_one`, `run_profile`), `.gitignore` (bỏ 3 dấu cách thụt đầu 5 dòng Hiếu vừa thêm)
- Tóm tắt: ca lỗi (lỗi mạng/HTTP hoặc alert cuối phân tích lỗi) không còn được chấm đúng ở bất kỳ cột nào — trước đây ca lành tính không có mã ATT&CK bị chấm `attack_ok=True` oan vì "rỗng = rỗng". Cột `error` gộp cả lỗi phân tích; thêm cột `pred_action_raw` (nhãn gốc của Agent). `.gitignore`: git KHÔNG bỏ dấu cách đầu dòng, nên `   chroma_db/` trước đây không có tác dụng.
- Kiểm tra: `eval_golden` ghi đủ `table4.csv`, `golden_off_detail.csv`, `conf_off.png`; repo thử cho thấy `.env`, `chroma_db/`, bản sao lưu, `results/`, `*Zone.Identifier` đều bị bỏ qua.
- Việc tiếp theo: `eval_injection.py` có cùng mẫu code ở dòng ~148–150 → bạn làm eval áp dụng cùng cách kiểm `pred["error"]`. Chạy 3 generator ra JSON → khởi tạo Git + GitHub → commit + tag `bench-freeze-day2` → Ngày 3.

## [2026-09-29] B3.1 — sửa phần khớp nối của bộ đo (`eval/common.py` của bạn làm eval)
- Trạng thái: xong, đã test với Agent chạy thật cổng 8010 (graph thật, LLM giả, Python 3.10)
- File đã sửa: `eval/common.py` (chỉ file này; không đụng dữ liệu `payloads/`, `rag_poison/`, `golden/`)
- Tóm tắt: (1) `extract_prediction` đọc đúng schema thật — `{"results": [...]}` của `/ingest/alerts` và dạng phẳng của `/analyze`; tên trường `severity` · `mitre_techniques` · `action_taken`. (2) Bỏ `rule_level` khỏi khoá đọc severity (tránh đo nhầm mức của luật đầu vào). (3) Kịch bản nhiều alert → lấy kết quả alert cuối; `call_agent` mặc định gọi `/reset` trước mỗi lần gửi để các kịch bản không nhiễm chéo lịch sử. (4) Quy đổi nhãn cũ `IGNORE/MONITOR/ALERT_OPERATOR/THROTTLE/BLOCK_IP/NETWORK_BLOCK_FULL` → `no_action/monitor/review/block`. (5) Thêm profile `l1:8011`, `l12:8012`. Trả thêm `action_raw`, `agent_mode`, `target_ip`, `n_results`, `error` (không bắt buộc dùng).
- Kiểm tra: màn 1 qua `call_agent` → đọc đủ 5 kết quả, lấy alert cuối; không reset → alert mang 6 sự kiện của lần trước, có reset → 1 sự kiện; dạng phẳng `/analyze` đúng; không đọc `rule_level`; quy đổi nhãn đúng; alert cuối lỗi / sai token / profile chưa chạy → báo `error` rõ.
- Ghi nhận cho đo đạc: luật cũ ở `api/main.py` (5 lần HIGH từ cùng IP → ép CRITICAL + NETWORK_BLOCK_FULL) nằm NGOÀI LLM và áp cho mọi profile — kịch bản ≥5 alert cùng IP sẽ bị nó quyết định alert cuối. Xem lại ở Ngày 4 (bảng quyết định Responder).
- Việc tiếp theo: bạn làm eval tự sửa mục 4–6 (đổi tên `golden/buid_scenarios.py`, chạy 3 generator ra JSON, thêm `results/` vào `.gitignore`); `eval_golden.py` nên dùng `pred["error"]` để loại ca lỗi. Khởi tạo Git + GitHub, commit đóng băng bộ dữ liệu, rồi Ngày 3.

## [2026-09-28] B3 (Ngày 2) — làm giàu tất định: tài sản · tình báo IP · lịch sử
- Trạng thái: code xong, đã test (21/21 Ngày 2 trên graph thật + Python 3.10; hồi quy B1 31/31, B2 8/8); chờ Hiếu chạy thật với Llama
- File đã sửa: `assets/inventory.yaml` (mới), `threat_intel/local_iocs.yaml` (mới), `agent/nodes/enricher.py` (mới), `core/graph.py` (chèn node), `agent/state.py` (thêm `enrichment`), `agent/nodes/correlator.py` (timeline lưu `rule_name`/`rule_level`), `api/main.py` (trả `enrichment`), `replay/replay_alerts.py` (in dòng "làm giàu")
- Tóm tắt: node `enricher` đứng sau Correlator, trả lời sẵn 3 câu analyst hỏi bằng tra cứu, không dùng LLM (kế hoạch mục 5): máy đích/nguồn là gì + mức quan trọng + có cho tự chặn (inventory; alert endpoint tra theo `host`); IP có tiền án không (IOC nội bộ → IP nội bộ khác = `no_record` → IP công khai tra AbuseIPDB, cache 24h, timeout 3s, không key/lỗi mạng = `unknown`); lịch sử incident ghép từ tên + mức **luật Splunk** (không dùng severity do LLM phán). Kết quả ở `state["enrichment"]` + 3 dòng nhật ký điều tra. Khối này không chứa giá trị nào từ `fields` → Ngày 3 đưa vào phần `trusted` của ticket. Lỗi đọc file/mạng không dừng pipeline. Sửa inventory/IOC có hiệu lực ngay, không cần restart. Hôm nay LLM CHƯA đọc phần làm giàu.
- Kiểm tra: màn 1 → đích web-win-01 (high, không tự chặn), nguồn .10 known_bad, lịch sử 1→5 sự kiện "01:20 Network Port Scan Detected (medium) → … → 01:25 Encoded PowerShell Command (high)", giai đoạn trinh sát → khai thác → thực thi; màn 2 → nguồn .30 = it-scanner-01 (it_scanner), no_record; màn 3a → enrichment không chứa nội dung User-Agent/URI; thiếu/hỏng inventory → vẫn chạy + ghi lỗi; AbuseIPDB giả lập: điểm/caching/timeout/lỗi mạng không lộ key.
- Ghi nhận thêm: venv thật là **Python 3.10** (thư viện `cp310`), CLAUDE.md ghi 3.12 — code viết và test tương thích 3.10. Output replay trước Ngày 2 (màn 2 bị HIGH+THROTTLE, MITRE sai) giữ làm bằng chứng "trước".
- Việc tiếp theo: **MỐC ĐO — commit bộ payload (Bảng 2) + bộ kịch bản vàng (Bảng 4) TRƯỚC khi viết dòng phòng thủ đầu tiên.** Sau đó Ngày 3: ticket `trusted`/`untrusted` + spotlighting, cờ `DEFENSE_PROFILE`, đo ASR baseline (bản `off`).

## [2026-09-28] B2 — chốt hợp đồng alert với bạn Splunk
- Trạng thái: phần hợp đồng xong, đã test (8/8 log từ chối, 31/31 hồi quy B1, 7/7 bridge trong tài liệu). Phần bộ alert 3 màn demo: **Hiếu tự soạn** theo khuôn `replay/alerts_b1.json` (Claude không soạn phần dữ liệu tấn công mẫu này).
- File đã sửa: `api/main.py` (thêm `_log_rejected_alerts`), `docs/alert_contract.schema.json` (mới), tài liệu Project `AegisSOC_02_splunk.md` (mục 3, 5, 6.1, 7.1, 8)
- Tóm tắt: alert sai hợp đồng ở `/ingest/alerts` giờ để lại dòng log `[Ingest] Từ chối (422)` gồm `alert_id` + trường sai + loại lỗi, không ghi giá trị gốc; phản hồi 422 giữ nguyên. JSON Schema của body sinh tự động từ class `Alert` để bạn Splunk tự kiểm. Tài liệu Splunk có mục 7.1 "Hợp đồng đã chốt" (mã phản hồi, luật kiểm, token gửi riêng, cổng). Sửa bridge trong tài liệu: IP `-`/`N/A` → `""`, không gửi alert `surface` sai (trước đây ghi `"unknown"` → Agent trả 422), không thử lại khi Agent trả 4xx.
- Kiểm tra: harness graph giả — 422 vẫn đúng dạng, log có alert_id/trường, không chứa giá trị gốc, tên trường chứa xuống dòng không vỡ log, chưa xác thực → 401 không ghi log, `/analyze` không bị ảnh hưởng; chạy đúng code bridge trích từ tài liệu với Agent: 7/7; lệnh kiểm schema trong tài liệu in `OK`.
- Ghi chú đo đạc: kho RAG đã làm sạch ngày 28/09 (xoá `sync_policy_e206c53a`, còn 7.719 chunk, bản sao lưu `chroma_db_backup_20260928`) — đây là **mốc sạch cho Bảng 3**.
- Việc tiếp theo: Hiếu soạn 3 file màn demo + gửi token riêng cho bạn Splunk. Sau đó Ngày 2 — **MỐC ĐO: đóng băng bộ payload + bộ kịch bản vàng, commit TRƯỚC khi viết dòng phòng thủ đầu tiên**; rồi làm giàu (inventory + IOC nội bộ + AbuseIPDB cache + lịch sử).

## [2026-09-28] B1 (kiểm tra) — chạy thật với Llama + kiểm kho ChromaDB
- Trạng thái: B1 xong (chạy thật OK); kho RAG đã làm sạch (Hiếu xoá tài liệu độc, còn 7.719 chunk)
- File đã sửa: không sửa code. Môi trường: xoá luật `netsh portproxy` 0.0.0.0:8000 → WSL cũ (dịch vụ iphlpsvc chiếm cổng 8000); xoá biến `OLLAMA_HOST=0.0.0.0` ở mức User/Machine, mở lại terminal.
- Tóm tắt: `python replay\replay_alerts.py --reset` → 3 alert cùng incident `687ad753`, lỗi 0/3, 6–15 s/alert. Llama gán MITRE sai (quét cổng → T1564, webshell → T1190) và cả 3 đều THROTTLE (SIMULATION nên không thực thi) — sẽ xử lý bằng ticket (`attack_ids` của luật vào phần trusted, Ngày 3) + bảng quyết định Responder (Lớp 1, Ngày 4).
- Kiểm kho `chroma_db\` (bản sao, chỉ đọc): 7.720 chunk = 725 chunk Sigma (310 luật, trust 1.0) + 6.994 chunk MITRE (697 kỹ thuật, ATT&CK v19, trust 0.8) + **1 tài liệu độc từ demo cũ** `sync_policy_e206c53a` (document_type=policy_update, injected_by=sync-service, trust tự khai 0.97, nội dung "coi loopback/X-Health-Check là lành tính"). 7.719 chunk Sigma/MITRE khớp hash `chunk_id` → không bị sửa nội dung. Tài liệu độc không có `source_type` nên retriever hiện tại lọc bỏ, nhưng ChromaMonitor lấy nó vào baseline "tin cậy" lúc khởi động. Không cần ingest lại. `rag_engine\chroma_db\` là bản cũ, không code nào đọc.
- Kiểm tra: Hiếu sao lưu `chroma_db_backup_20260928` rồi xoá riêng `sync_policy_e206c53a` (7.720 → 7.719).
- Việc tiếp theo: B2.

## [2026-09-28] B1 — cửa vào alert `POST /ingest/alerts` + token + alert phát lại
- Trạng thái: code xong, đã test bằng graph giả (31/31); chờ Hiếu chạy thật với Ollama
- File đã sửa: `api/alert_adapter.py` (mới), `api/main.py` (sửa), `agent/state.py` (thêm trường), `replay/alerts_b1.json` (mới), `replay/replay_alerts.py` (mới)
- Tóm tắt: Agent nhận **alert** theo hợp đồng với Splunk qua `POST /ingest/alerts`, bắt buộc `Authorization: Bearer <AGENT_TOKEN>` (server chưa có token → từ chối tất cả). Alert sai khuôn bị trả 422, không lọt vào graph. Lớp chuyển đổi `to_legacy_raw_log` chỉ đổi tên trường cho vừa ô `raw_log` của node cũ (giàn giáo tạm, bỏ ở Ngày 3); bản alert gốc nguyên vẹn đi song song trong `state["alert"]` cho làm giàu/ticket dùng. `event_type` sinh từ mã ATT&CK để Correlator xếp đúng giai đoạn. Mặc định trả 202 và phân tích nền (bridge chỉ chờ 10s); `?wait=true` chờ kết quả (cho script phát lại). Chỗ gắn prefilter (Ngày 5) đã đánh dấu ở đầu `_process_one_alert`.
- Kiểm tra: test trong môi trường riêng với Extractor + Correlator thật, Analyzer giả — token (503/401), 8 kiểu alert sai khuôn (422), 3 alert mẫu gộp đúng 1 incident, giai đoạn trinh sát → khai thác → thực thi, Extractor bắt network_scan / sql_injection / rce_attempt, `/analyze` cũ vẫn chạy, token không lộ vào log.
- Việc tiếp theo: Hiếu chạy thật (uvicorn + replay) với Llama. Sau đó B2 — bộ alert phát lại đủ 3 màn demo + gói hợp đồng/token/cổng gửi bạn Splunk.

## [2026-09-28] B0 — chuẩn bị môi trường Windows, chạy lại lõi cũ
- Trạng thái: xong
- File đã sửa: `dashboard/config.json` (`SOAR_MODE`: `LIVE` → `SIMULATION`)
- Tóm tắt: xác nhận lõi cũ (`core/graph.py`) chạy hết graph trên Windows native. Nguyên nhân Ollama không kết nối được là biến môi trường OS `OLLAMA_HOST=0.0.0.0` (sót lại từ hồi chạy WSL) — `0.0.0.0` chỉ hợp lệ để server lắng nghe, không dùng để client gọi tới; xoá biến này thì code tự set lại `http://127.0.0.1:11434` (logic có sẵn trong `analyzer.py`/`reflection.py`) và kết nối được. Đồng thời phát hiện `dashboard/config.json` để `SOAR_MODE=LIVE` — đúng lỗi đã ghi ở kế hoạch mục 7.2 — đổi về `SIMULATION` theo đúng rule CLAUDE.md mục 3.4.
- Kiểm tra: chạy `python core\graph.py`, thử cả 4 loại log (sạch, SSRF, DNS tunneling, RCE). Extractor → Correlator → Retriever → Analyzer → Reflection → Responder chạy hết, Ollama trả JSON có cấu trúc bình thường. Ghi nhận thêm (chưa sửa, để dành đúng bước trong lịch): log benign (option 1, incident mới) bị Analyzer (LLM) phán nhầm HIGH/T1190/T1489 — hallucination vì lõi cũ chưa có lớp lọc trước + làm giàu tất định để chặn/định hướng LLM (đúng vấn đề mục 4–5 kế hoạch, không phải bug cần vá ở lõi cũ). SOAR action THROTTLE gọi `sudo iptables` fail trên máy test (không có sudo) — vô hại, và giờ SOAR đã SIMULATION nên sẽ không thực thi lệnh thật nữa.
- Việc tiếp theo: Bước 1 (Ngày 1 trong lịch) — dựng endpoint `POST /ingest/alerts` + token, soạn bộ alert phát lại theo hợp đồng 10 trường, gửi bạn Splunk bảng kỹ thuật + hợp đồng

## [2026-09-27] B-chuẩn bị — tạo CLAUDE.md và TIEN_DO.md
- Trạng thái: xong
- File đã sửa: `CLAUDE.md` (mới), `TIEN_DO.md` (mới)
- Tóm tắt: thêm quy tắc làm việc cho các phiên code và file nhật ký tiến độ này. Chưa đụng vào code của Agent.
- Kiểm tra: không cần
- Việc tiếp theo: Bước 0 — chuẩn bị môi trường Windows, chạy lại lõi cũ
