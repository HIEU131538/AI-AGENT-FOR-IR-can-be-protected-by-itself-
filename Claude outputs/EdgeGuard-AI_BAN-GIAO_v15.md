# EdgeGuard-AI — Bàn giao ngữ cảnh sang cuộc trò chuyện mới (v15)

> **CÁCH DÙNG FILE NÀY:** Mở cuộc trò chuyện mới → đính kèm/dán file này → nói:
> *"Đây là ngữ cảnh đề tài NCKH của tớ. Nhóm giờ 5 người, tớ là P1 làm toàn bộ nhánh thị giác và là người duyệt code. Đọc kỹ phần 'Đã chốt' và đừng bàn lại những thứ đó. Hôm nay tớ cần làm: [việc cụ thể]."*
>
> Cập nhật lần cuối: **26/09/2026** (v15) · Bản trước: v14 ngày 19/09 · Thời gian còn lại: ~3–4 tháng
>
> **Đổi gì so với v14:** nhóm lên 5 người (mục 2) · thêm quy trình Git + GitHub + Trello theo yêu cầu của thầy (mục 2b) · cập nhật số liệu thật của nhánh thị giác đã đo (mục 4.1) · thêm tóm tắt lõi Agent cũ KMA_AI_AGENT và 8 lỗ hổng đã rà (mục 4.3b) · thêm quan hệ với đề tài AegisSOC (mục 1) · thêm tài liệu mới vào index (mục 9)

---

## 1. Đề tài là gì (1 đoạn)

**EdgeGuard-AI** — đề tài NCKH (Học viện Kỹ thuật Mật mã), phản ứng sự cố tự động cho mạng AIoT biên. Hai nguồn phát hiện độc lập đổ về **một AI Agent** duy nhất để ra quyết định:

1. **Nhánh thị giác** — phát hiện tấn công đối kháng (adversarial patch) làm người "tàng hình" trước camera AI.
2. **Nhánh OS/mã độc** — phát hiện fileless malware trên Gateway qua Sysmon → Splunk.

Agent nhận alert từ cả hai, làm giàu dữ liệu, suy luận có RAG, rồi tự động phản ứng (cô lập thiết bị, chặn IP...) hoặc leo thang cho người.

**KHÔNG còn liên quan tới WISE-IoT / InnoWorks** — đã bỏ hoàn toàn, chỉ làm NCKH.

**Mục tiêu định hướng:** sát thực tiễn doanh nghiệp nhất có thể — nên các khoản đầu tư vào độ chịu tải, khả năng triển khai, chỉ số kiểu SOC đều được coi là đáng làm.

**Vị trí trên bản đồ ngành AI** (chi tiết ở tài liệu #12):

| Trục | EdgeGuard-AI |
|---|---|
| Nơi model chạy | **Edge + on-prem**, không gọi API cloud (hybrid: biên phản ứng, SOC tổng hợp) |
| Serving | **Ollama** cho LLM · nhúng thẳng thư viện cho YOLO (vLLM là đường nâng cấp khi cần thông lượng) |
| Tối ưu | LLM **lượng tử hoá 4-bit GGUF** · YOLO11s cỡ nhỏ (chưa xuất TensorRT/ONNX — cơ hội tăng FPS) |
| Đưa tri thức vào | **RAG** cho Agent · **fine-tune** cho DeBERTa · **ML cổ điển** cho LR/RF — ba kỹ thuật cho ba bài toán |
| Điều phối | **LangGraph state graph**, một agent + tool use + guardrail tất định (không multi-agent — dễ kiểm toán hơn) |
| Vận hành | golden set + MTTR + audit log · **chưa có** tracing & drift monitoring (ghi vào hướng phát triển) |
| Loại RAG | **Naive RAG**, chunk theo cấu trúc tài liệu · nâng cấp đề xuất: hybrid search (vì corpus đầy mã T1078) + re-ranker → Agentic RAG |

**Quan hệ với đề tài thứ hai (AegisSOC):** cùng lõi Agent, nhưng AegisSOC là đề tài môn học (rồi thành đồ án tốt nghiệp 11/2027) cho SOC doanh nghiệp: log web + endpoint + mạng, trọng tâm là Agent tự phòng vệ trước prompt injection. **Hai đề tài tách riêng — trong chat EdgeGuard đừng trộn việc của AegisSOC vào.**

---

## 2. Phân công nhóm 5 người (cập nhật 26/09 — thay bản 3 người)

| Người | Nhóm | Phụ trách |
|---|---|---|
| **P1 — TỚ** | Thị giác + trưởng nhóm | **Toàn bộ nhánh thị giác** (YOLO11s, Grad-CAM, C/D/E, LR, Jedi/LGS, benchmark B1→B3, 6 bảng). Người duyệt Pull Request, quản board Trello. ML Pre-filter + AI Agent vẫn thuộc P1 nhưng **làm sau thị giác** |
| P2, P3 | SIEM | Sysmon + Splunk: Universal Forwarder, HEC nhận alert thị giác, correlation search Sigma → SPL ra khối (B), database hệ thống, `asset_inventory.yaml` + NTP, dashboard Splunk |
| P4, P5 | Dataset + Demo | Bộ ảnh composite cho thị giác (sạch vs có patch) + manifest; dữ liệu telemetry cho Pre-filter (Atomic Red Team + nền bình thường); làm sạch/chuẩn hoá; kịch bản demo A/B/C từng giây + quay video dự phòng; bộ N = 30–50 kịch bản có đáp án để chấm Agent |

**Luật "ai xong trước thì nhận việc tiếp":** cột Backlog trên Trello xếp theo ưu tiên từ trên xuống. Ai rảnh thì kéo thẻ **trên cùng** mà mình làm được (ưu tiên thẻ nhãn "Ai cũng nhận được"), tự gán tên, chuyển sang "Đang làm". P1 là người sắp thứ tự Backlog. Mỗi người tối đa 2 thẻ ở "Đang làm".

**Việc có thể đẩy sang người rảnh (đề xuất, chưa chốt):** nhóm SIEM rảnh → `asset_inventory.yaml`, node làm giàu gọi AbuseIPDB, đẩy kết quả ticket ngược vào Splunk; nhóm Dataset/Demo rảnh → bộ N kịch bản chấm Agent, script sinh tải cho bảng chịu tải, viết chương báo cáo. **Lõi reasoning của Agent và model Pre-filter giữ ở P1.**

Lộ trình phạm vi: **làm trọn hệ 2 nhánh trước** (thị giác + mã độc). Xong xuôi mới tính nhánh thứ 3 (module phát hiện botnet/bất thường mạng cho VLAN camera). VLM giữ trong kế hoạch nhưng xếp sau khi xương sống + các bảng số đã xong.

---

## 2b. Quản lý tiến độ: Git + GitHub + Trello (thầy yêu cầu, chốt 26/09)

Hướng dẫn đầy đủ từ số 0 ở file **HUONGDAN_Git-GitHub-Trello.html** (xem mục 9). Tóm tắt những gì đã chốt:

| Hạng mục | Quyết định |
|---|---|
| Repo | **Một repo private duy nhất** `edgeguard-ai` trên GitHub, P1 là chủ. Thư mục theo nhóm: `vision/` (P1) · `siem/` (P2, P3) · `dataset/` + `demo/` (P4, P5) · `prefilter/` + `agent/` (P1, làm sau) · `docs/` (chung). Code cũ `edgeguard-vision` chuyển vào `vision/` |
| Nhánh | GitHub Flow: `main` luôn chạy được · mỗi thẻ Trello = 1 nhánh `<nhóm>/<mô-tả>` (vd `vision/bang-f-suy-giam`) · gộp vào `main` **chỉ qua Pull Request**, P1 duyệt |
| Bảo vệ `main` | GitHub Free **không** bật được protected branch cho repo private → P1 đăng ký **GitHub Student Developer Pack** (được GitHub Pro) rồi bật "Require a pull request before merging". Trong lúc chờ: quy ước không push thẳng `main` |
| Không bao giờ commit | Dataset, ảnh train, `*.pt`/`*.onnx`, `runs/`, `.env`, token Splunk HEC / AbuseIPDB / Telegram, file `.evtx`. Dataset để Google Drive (đã có Colab Pro), repo chỉ giữ script + manifest. GitHub chặn file > 100 MB |
| Lộ secret | Lỡ commit token → **thu hồi token ngay**, xoá bằng commit mới không đủ vì lịch sử vẫn còn |
| Trello | Workspace free (tối đa 10 người, nhóm 5 + thầy = 6). Board "EdgeGuard-AI — Tiến độ", cột: Tài liệu & quy ước · Backlog · Tuần này · Đang làm · Chờ review · Xong. Nhãn theo nhóm + "Bị chặn" + "Ai cũng nhận được". Bật Power-Up GitHub để gắn PR vào thẻ |
| Nhịp họp | 15 phút đầu tuần, cả nhóm nhìn board: cái gì xong, cái gì bị chặn, kéo thẻ cho tuần này |

Khung repo tạo sẵn: **edgeguard-ai_khung-repo.zip** (README, `.gitignore`, `CONTRIBUTING.md`, mẫu Pull Request, README cho từng thư mục).

---

## 3. ĐÃ CHỐT — đừng bàn lại

| Hạng mục | Quyết định |
|---|---|
| Model detector | **YOLO11s** (KHÔNG phải 11n — patch white-box không chuyển được giữa 2 cỡ model) |
| SIEM | **Splunk** (không dùng Wazuh). Chỉ có **1 SIEM trung tâm** duy nhất |
| Thu thập dữ liệu vào Splunk | **Giữ cả 2**: HEC (alert thị giác, JSON) + Universal Forwarder (log Sysmon) |
| Toàn vẹn alert | **HMAC ký ở tầng ứng dụng** — HEC token lo "ai được gửi", HMAC lo "nội dung có bị sửa không". Hai việc khác nhau, giữ cả hai |
| Hệ điều hành | Gateway = **Windows Server** (chạy VMS kiểu Milestone/Genetec) · Camera = **Linux nhúng** (không cài Sysmon, giám sát qua mạng) |
| KT1 đổi tên | **DirectShow/WMF buffer hooking** (KHÔNG phải V4L2/GStreamer — đó là API Linux, mâu thuẫn với Gateway Windows) |
| **Kịch bản tấn công liên nhánh** ⭐ | **KT1 chính là đường tiêm patch số**: hook buffer video = sửa được khung hình trước khi YOLO nhìn thấy. Chuỗi: KT2 (brute-force RTSP) hoặc KT1 (hook buffer) → kiểm soát luồng video → tiêm patch → cả 2 nhánh cùng nổ alert → Agent tương quan thành **1 ticket**. Luật: cùng `device_id` + cửa sổ ±30–60s |
| **Kế hoạch demo** ⭐ | **3 demo theo thứ tự A → B → C**: A = chỉ thị giác · B = chỉ mã độc (+ ca âm tính ~1 phút) · C = liên nhánh. Thứ tự bắt buộc — xem C trước thì nó chỉ là "hai alert cùng nổ". Quay video cả ba làm dự phòng |
| ML Pre-filter | **Phương án C** — OR-gate: `is_always_analyze_type OR proba > THRESHOLD` |
| **Hợp đồng dữ liệu** ⭐ | 4 khối cố định **(A)** alert thị giác → **(B)** alert Sysmon sau correlation search → **(C)** = alert + 3 trường quyết định của Pre-filter → **(D)** ticket. Chi tiết trường: mục 05 file kiến trúc. Nguyên tắc: Pre-filter **chỉ thêm trường, không sửa/xoá** trường của alert gốc |
| **Alert thị giác KHÔNG qua model cây** ⭐ | Model cây (RF/LightGBM) train trên feature log OS — không đọc được `suspicion_score`. Alert thị giác đi **cửa trái** của OR-gate (`is_always_analyze_type = true`, luôn cho qua) vì đã qua bộ lọc gắt hơn ở biên. Không có gì để benchmark ở đây |
| **Gộp ticket liên nhánh** ⭐ | **"Cho nhập sau", KHÔNG chờ gom**: alert tới muộn thì ghép vào ticket đang mở (cửa sổ 5 phút), đẩy status về `reasoning`, chạy lại kết luận. Theo đúng Microsoft Sentinel (*re-open closed matching incidents*) và Splunk ITSI (episode chỉ cắt sau 2 giờ ngừng sự kiện). Bắt buộc: giới hạn 3 lần đánh giá lại + hành động idempotent + thêm status `merged` |
| **Định tuyến alert** ⭐ | Dùng **`severity_id` (1–5) + `confidence_id` (1–3) chuẩn hoá kiểu OCSF** trong cả (A) và (B). `is_always_analyze_type` thành trường **dẫn xuất**, Pre-filter tính từ **bảng chính sách YAML** — KHÔNG hardcode `source == "vision"` |
| **HMAC sai chữ ký** ⭐ | **Khoá với tự động hoá, mở với hiển thị**: sinh sự kiện `integrity_violation`, giữ payload gốc từng byte làm bằng chứng, đẩy thẳng lên người, không gọi LLM, không bao giờ vứt. Ánh xạ NIST SP 800-53 **AU-9(3) · SI-7(2) · SI-7(5)**. So chữ ký bằng `hmac.compare_digest()` chứ không phải `==` |
| **Bật Pre-filter** ⭐ | **Chạy shadow mode trước** (tính quyết định, ghi log, vẫn cho mọi alert đi tiếp), rồi mới bật thật + **giữ mẫu đối chứng ngẫu nhiên 5%** số alert đáng lẽ bị loại để đo tỷ lệ bỏ lọt liên tục. Mốc đối chiếu: AACT giảm 61% alert với 1,36% bỏ lọt trong SOC thật |
| **Vị trí VLM** ⭐ | **Đặt ở biên, trong nhánh thị giác** — VLM ăn *ảnh*, Agent ăn *ticket*. Gọi VLM ngay trên khung hình còn trong bộ nhớ, rồi nhét kết luận **dạng chữ** vào trường `vlm_verdict` của (A). Splunk/Agent không bao giờ thấy ảnh; ticket không phải sửa |
| LLM của Agent | **Llama 3.1 8B chạy cục bộ qua Ollama** (không dùng API cloud — giữ câu chuyện "tự chủ ở biên" + không để hình ảnh giám sát rời thiết bị) |
| Lớp an toàn 2 tầng | Là **2 cơ chế khác nhau**: Tier 1 = Reflection (LLM tự phản biện) → Tier 2 = Deterministic Override (luật cứng ngoài LLM) → leo thang cho người qua Telegram |
| "Injection/Jailbreak Classifier" | Đã **đổi tên thành Log-injection Guard** — không có kịch bản jailbreak vì hệ không có giao diện chat; mối đe doạ thật là *indirect prompt injection* qua field log. Ưu tiên THẤP nhưng có thật |
| IoT-23 / N-BaIoT | **Không dùng cho Pre-filter** — network flow, không phải host telemetry, sai modality. Để dành cho model NIDS riêng ở tương lai |
| Nền tảng train | **Colab Pro** đã mua. **Pro KHÔNG chạy nền** (đó là Pro+) → PS-GAN để máy nhà chạy nền, Colab Pro lo job ngắn |

---

## 4. Ba khối của tớ — trạng thái & việc tiếp theo

### 4.0 · Hợp đồng dữ liệu (chốt 19/09 — đưa cho nhóm SIEM P2, P3 đọc trước khi ai code)

Ba người code song song ba khối; không chốt định dạng trước thì ráp vào mới lộ lệch. Bản đầy đủ từng trường nằm ở **mục 05 file kiến trúc**; đây là bản rút gọn:

| Khối | Nhận vào | Xuất ra | Ai làm |
|---|---|---|---|
| Nhánh thị giác | khung hình RTSP | **(A)** `device_id`, `timestamp`, `source="vision"`, `event_type`, `suspicion_score`, `metrics{C,D,E}`, `purification{jedi,lgs}`, `vlm_verdict?`, `evidence_ref`, `model_version`, `hmac_signature` | **tớ (P1)** |
| Sysmon | sự kiện HĐH | log thô — *chưa phải alert* | P2, P3 |
| Splunk | (A) qua HEC · log Sysmon qua Forwarder | **(B)** `device_id`, `timestamp`, `source="sysmon"`, `event_type`, `mitre_technique`, `rule_name`, `is_always_analyze_type`, `features{...}`, `raw_log` · còn (A) thì **giữ nguyên, chỉ index lại** || P2, P3 |
| ML Pre-filter | (A) hoặc (B) | **(C)** = alert gốc + `pre_filter_decision`, `pre_filter_reason`, `pre_filter_proba` | **tớ (P1)** |
| Agent | (C) | **(D)** ticket — (C) đặt nguyên vẹn vào `alert_goc` | **tớ (P1)** |

**Điểm bất đối xứng cố ý:** Splunk **không phân tích lại (A)** — alert thị giác tới nơi đã có kết luận sẵn, Splunk chỉ lưu + index để tra cứu/tương quan. Log Sysmon thì ngược lại: phải qua correlation search mới thành alert (B).

**⚠️ Hai cái bẫy làm hỏng tương quan liên nhánh mà KHÔNG báo lỗi gì cả:**
1. **ID lệch** — thị giác ghi `"cam-01"`, Sysmon ghi `"GATEWAY-HANOI-01"` cho *cùng một thiết bị* → không bao giờ khớp, demo C không nổ. Chặn bằng: một bảng ánh xạ ID chung trong `asset_inventory.yaml`, cả hai nhánh cùng đọc từ đó.
2. **Lệch đồng hồ** — camera biên và Gateway là hai máy khác nhau; lệch 2 phút thì cửa sổ ±30–60s không bao giờ trùng. Bắt buộc **NTP cùng một nguồn** + timestamp luôn kèm timezone.

Hai bẫy này nên nêu thẳng trong phần "điều kiện triển khai" của báo cáo — cho thấy nhóm hiểu hệ phân tán thật.

**Cập nhật 19/09 sau khi tra thực tiễn ngành — hai điểm đổi so với bản đầu:**

- **Định tuyến: bỏ hardcode `source == "vision"`.** Cả (A) và (B) cùng mang `severity_id` (1–5) và `confidence_id` (1=Low, 2=Medium, 3=High) theo thang chuẩn hoá kiểu **OCSF**. `is_always_analyze_type` **không còn là trường truyền đi** — nó là trường *dẫn xuất*, do Pre-filter tính từ một **bảng chính sách để trong file YAML** (vd: `severity_id >= 4` → luôn phân tích; `source == "vision" AND confidence_id >= 2` → luôn phân tích). Lợi: không còn quy ước ngầm giữa P1 và P2, đổi chính sách chỉ là sửa file cấu hình. **Cần thống nhất với P2 ý nghĩa từng mức của hai thang này trước khi code.**
- **HMAC sai chữ ký — chính sách "khoá với tự động hoá, mở với hiển thị".** Alert sai chữ ký *không bao giờ* dẫn tới hành động tự động, nhưng cũng *không bao giờ* bị vứt: sinh sự kiện riêng loại `integrity_violation` (payload bị sửa tự nó đã là một phát hiện), giữ nguyên payload gốc từng byte làm bằng chứng, đẩy thẳng lên người qua đường bypass đã có, không gọi LLM. Ánh xạ chuẩn để viết báo cáo: **AU-9(3)** (bảo vệ bản ghi kiểm toán bằng mật mã) · **SI-7(2)** (bắt buộc thông báo cho người khi phát hiện sai lệch toàn vẹn) · **SI-7(5)** (phản ứng tự động khi phát hiện vi phạm). Chi tiết code: so chữ ký bằng `hmac.compare_digest()` chứ **không** dùng `==` (tránh timing attack).

### 4.1 · Nhánh thị giác

**Pipeline runtime:** YOLO11s → Grad-CAM (tự viết, hook `model[22]`) → 3 chỉ số **C/D/E** → Logistic Regression → `suspicion_score` → đối chứng độc lập bằng **Jedi** (entropy → inpaint) và **LGS** (gradient smoothing).

**Số liệu ĐÃ ĐO THẬT (dùng được khi báo cáo / phỏng vấn — đừng thổi phồng):**

| Việc | Kết quả | Ghi chú |
|---|---|---|
| Đổi YOLO11n → 11s | forward GPU 13,15 ms → 13,52 ms (~3% chậm hơn) · COCO mAP50-95 39,5 → 47,0 (số của Ultralytics) | chậm không đáng kể, chính xác hơn rõ |
| Chọn layer Grad-CAM (99 ảnh) | layer 22 trung vị **1,546** (tốt nhất) · layer 19 trung vị 1,101 · layer 16 trung bình 2,164 nhưng trung vị 0,989 (bị kéo bởi 1 ngoại lai 106,99) | chỉ số = tỉ lệ năng lượng heatmap trong bbox / tỉ lệ diện tích bbox. Bài học: **nhìn trung vị, không nhìn trung bình** |
| 5 ảnh 1 người (đúng kịch bản demo) | layer 22 trung bình 2,20 · tệ nhất 0,87 | trước đó layer 9 có lần tụt 0,00 |
| Hiệu ứng patch lên heatmap | không patch 1,14 / 1,26 vs có patch 0,011 / 0,223 | **chỉ 2 + 2 ảnh đối chứng — chỉ cho thấy xu hướng, chưa phải kết quả thống kê** |
| Sửa hàm mục tiêu khi train patch | `avg_conf_drop` 0,071 → 0,375 | đo trên **yolo11n**, ảnh composite số; **patch cho 11s chưa train lại** |
| `suspicion_score` hiện tại | ảnh sạch vẫn ra 0,70–1,00 | vì LR **chưa train** (`trained=false`, đang dùng heuristic tạm) — không phải bug |

**Mock làm sạch:** 4 cách — che xám, inpaint Telea (tốt nhất trong mock), inpaint Navier–Stokes, LGS. Tham số LGS hay dùng: block 15–30 px, overlap 5, ngưỡng 0,1, λ = 2,3 (sẽ chọn lại bằng thí nghiệm).

**Code nằm ở đâu:** repo `edgeguard-vision` trên máy tớ (**không** nằm trong thư mục `KMA_AI_AGENT` đang kết nối). Khi dựng Git sẽ chuyển vào `vision/` của repo `edgeguard-ai`. Các quyết định kiến trúc ghi ở `decisions.md` (ADR-09: pipeline kiểm **mọi** người nghi ngờ, không chỉ `best_candidate` — sửa lỗ hổng người bị patch đứng cạnh người có confidence cao hơn).

**Benchmark ablation — 4 pipeline, phải đo chứ không đoán:**

| Pipeline | Gồm gì |
|---|---|
| B1 | Grad-CAM + Jedi (baseline) |
| B2 | + MS-GradCAM (trung bình N=12 heatmap nhiễu — *nhóm tự đặt tên & định nghĩa*) |
| B2a | + EMA (làm mượt heatmap theo thời gian) |
| B3 | + Tracking (IoU) + Temporal Jedi |

Đo C/D/E + **S** (Temporal Stability) → xuất **6 bảng**: (A) định vị XAI · (B) ổn định thời gian · (C) xác minh Jedi · (D) end-to-end P/R/F1/FPR · (E) độ trễ/FPS · **(F) đường cong độ bền suy giảm** ⭐ *(mới 19/09)*.

**⭐ Bảng F — trả lời cho vấn đề patch vật lý:** nhóm thiếu thiết bị để chụp patch in ra, nhưng đó là hạn chế **thiết bị**, không phải lỗ hổng khoa học — Thys et al. 2019 đã chứng minh patch in đánh lừa được detector, nên tính khả thi vật lý là thứ **trích dẫn** được. Thay vào đó: mô phỏng suy giảm vật lý ngay trên ảnh composite ở **thời điểm đánh giá** (nhiễu cảm biến, nén JPEG, mờ chuyển động, méo phối cảnh, đổi sáng) theo 4 mức *không → nhẹ → vừa → nặng*, đo lại chỉ số phát hiện ở từng mức → được một đường cong độ bền, không cần máy ảnh. **Phải ghi rõ trong phần hạn chế: đây là proxy, không tương đương thực nghiệm vật lý.**

Ngoài ra, patch tiêm bằng đường số giờ **không còn là "giải pháp chữa cháy"** mà là một mô hình đe doạ chính đáng — chính là kịch bản KT1 hook buffer (xem mục 3).

**Việc tiếp theo:**
- [ ] Train lại 4 patch cổ điển cho **yolo11s** (code còn trỏ `yolo11n.pt` — sửa trong `classic_patch.py` và `configs/thresholds.yaml`)
- [ ] Dựng bộ dữ liệu composite (ảnh sạch vs ảnh đã ghép patch)
- [ ] **Code hàm suy giảm theo mức** (tách biệt với EOT lúc train) → chạy Bảng F
- [ ] Chạy benchmark B1→B3, xuất 6 bảng
- [ ] Train Logistic Regression trên C/D/E (vài phút, CPU máy nhà)
- [ ] PS-GAN (rủi ro cao, có thể bỏ — có fallback "so sánh khái niệm")

### 4.2 · ML Pre-filter

Bài toán **nhị phân duy nhất**: *"alert này có đáng tốn 1 lượt LLM không?"* — KHÔNG phải phân loại mã độc gì.

**Feature set:** `has_sigma_match`, `sigma_rule_severity`, `event_freq_5min`, `cmdline_length`, `cmdline_entropy`, `ip_history_score`, `is_always_analyze_type`.

**⭐ Hai đường đi khác nhau — đừng gộp làm một (làm rõ 19/09):**
- **Alert thị giác (A)**: KHÔNG qua model cây. Đi cửa trái OR-gate (`is_always_analyze_type = true`). Lý do: model cây train trên feature log OS, không đọc được `suspicion_score` — ép nó chấm là chấm sai loại dữ liệu. Mà alert thị giác cũng đã qua bộ lọc gắt hơn nhiều ở biên rồi.
- **Alert Sysmon (B)**: qua model cây như thiết kế gốc.

**⭐ `co_alert_cheo_nhanh` là một CỘT cho phía Sysmon, không phải đường tránh cho thị giác:** nó trả lời *"alert Sysmon này có alert thị giác đi kèm, cùng thiết bị, cùng cửa sổ thời gian không?"* — tính cho **mọi** alert Sysmon. Giá trị: alert mơ hồ (DLL lạ nạp vào tiến trình video — có thể chỉ là cập nhật codec) được model tự học là đáng ngờ hơn hẳn khi cột này bật, tức *tín hiệu nhánh này nâng chất lượng quyết định của nhánh kia ngay từ khâu lọc*. **Đo được** (train có/không có cột này, so recall) → thêm một bảng. **Ưu tiên: tuỳ chọn, làm sau bake-off** — chỉ là thêm một cột vào bộ dữ liệu đã có.

**Thuật toán:** bake-off **Random Forest vs LightGBM**, tối ưu theo **recall lớp malicious** (`StratifiedKFold` + `scoring="recall"`). Không kịp thì dùng RF.

**⭐ Bảng chịu tải (mới 19/09):** script sinh tải N alert/giây, đo thông lượng + độ trễ end-to-end **ở 2 chế độ bật/tắt Pre-filter**. Nút thắt gần như chắc chắn là **lượt gọi LLM** (Llama 8B trên GPU 8GB mất vài giây–hơn chục giây/ticket, Tier 1 Reflection còn nhân đôi số lượt gọi). Bảng này chứng minh Pre-filter xứng đáng tồn tại **bằng số** — đúng logic ablation. Phép đo rất rẻ (bấm giờ quanh từng node); Prometheus/Grafana chỉ là bản "chuẩn production" của cùng con số.

**⭐ Cách bật Pre-filter (chốt 19/09):** **không bật thẳng**. Giai đoạn 1 chạy **shadow mode** — tính quyết định, ghi log, nhưng vẫn cho mọi alert đi tiếp; cho ngay bảng "nếu bật thì đã loại bao nhiêu, có alert độc nào bị loại nhầm không" mà không chịu rủi ro nào. Giai đoạn 2 bật thật nhưng **giữ mẫu đối chứng ngẫu nhiên 5%** số alert đáng lẽ bị loại vẫn đi tiếp lên Agent → cho ước lượng *không thiên lệch* của tỷ lệ bỏ lọt, đo liên tục chứ không phải một lần. Mốc đối chiếu ngoài đời: hệ AACT trong một SOC thật giảm **61% alert** với tỷ lệ bỏ lọt **1,36%** trên hàng triệu alert.

**Việc tiếp theo:**
- [ ] Viết `extract_features()` — **làm được ngay** khi chốt schema alert với nhóm SIEM (P2, P3)
- [ ] Chờ dataset sạch từ nhóm dataset (P4, P5) → train → bake-off → chọn ngưỡng
- [ ] Tích hợp vào Tier 4, benchmark confusion matrix cũ vs mới
- [ ] Chạy bảng chịu tải

### 4.3 · AI Agent Core

**Nền tảng:** LangGraph state graph (1 service) + Llama 3.1 8B qua Ollama.

**Chuỗi node:** mở ticket → làm giàu → reasoning + RAG → Tier 1 Reflection → Tier 2 Deterministic Override → function calling → audit log → (nếu cần) leo thang cho người.

**Ticket JSON:** `ticket_id`, `status`, `alert_goc`, `cac_alert_lien_quan` (*tóm tắt người đọc được, không chỉ ID*), `enrichment_data`, `rag_result`, `llm_conclusion`, `action_da_thuc_hien`, `audit_log`.

**3 loại enrichment** (đều có timeout + fail-open): lịch sử alert gần đây (SQLite) · `asset_inventory.yaml` · AbuseIPDB.
**+ Luật tương quan chéo nhánh** ⭐: alert thị giác + alert Sysmon cùng `device_id` trong ±30–60s → gộp 1 ticket.

**⚠️ Lỗ hổng thời điểm (phát hiện khi rà soát 19/09):** hai alert của cùng một vụ **không tới cùng lúc**. Nếu Agent mở ticket rồi chạy thẳng một mạch trong vài giây, thì alert thứ hai tới ở giây thứ 40 sẽ **không còn ticket nào để gộp vào** — luật tương quan không bao giờ kích hoạt, demo C ra hai ticket rời, *mà không báo lỗi gì cả*.

**Chốt: làm "cho nhập sau", bỏ hẳn phương án chờ gom.** Tra lại thì sản phẩm thật đều làm vậy — Microsoft Sentinel có sẵn tuỳ chọn *"Re-open closed matching incidents"* (incident đã đóng mà có alert mới thuộc về nó thì mở lại chính nó), còn Splunk ITSI giữ một *episode* mở cho tới khi **"dòng sự kiện ngừng chảy trong 7200 giây (2 giờ)"** mới cắt — không hề có bước chờ gom ở đầu vào. Ba lý do chọn: đúng cách ngành làm; không cộng giây chết vào **MTTR** (chỉ số nhóm đang hứa đo); và **diễn hay hơn hẳn** — giám khảo thấy ticket tự nhận thêm bằng chứng rồi nâng kết luận, thay vì nhìn màn hình đứng im 30 giây.

**Cách làm:** trước khi mở ticket mới, tra DB tìm ticket cùng `device_id` còn trong cửa sổ gộp (**5 phút**); có thì ghép vào `cac_alert_lien_quan`, đẩy status về `reasoning`, chạy lại kết luận, ghi `audit_log` một dòng. **Hai chốt chặn bắt buộc:** giới hạn tối đa **3 lần** đánh giá lại (chống lặp vô hạn) và **hành động phải idempotent** (IP đã chặn thì không chặn lại). Thêm status `merged`. Rủi ro "hành động sớm" gần như không có vì mọi hành động có hậu quả vốn đã phải qua người duyệt.

**RAG:** MITRE **ATT&CK** (tấn công hạ tầng) + MITRE **ATLAS** (tấn công vào AI) + case-cards. Cần vector DB (Chroma/Qdrant/FAISS).

**AI tự vệ — 3 trụ:** Log-injection Guard · chống RAG poisoning · (tương lai) chống visual prompt injection nếu thêm VLM.

**⭐ Bộ kịch bản đánh giá Agent + MTTR (khoảng trống vừa nhận diện, 19/09):** hiện Agent **chưa có cách đo** — hội đồng chắc chắn hỏi "làm sao biết Agent quyết định đúng?". Cách lấp: dựng **N = 30–50 kịch bản sự cố có đáp án đúng** (ca phải cô lập / chặn IP / leo thang / false positive phải đóng), đo 4 chỉ số:
1. Tỷ lệ chọn đúng hành động
2. Tỷ lệ leo thang (quá cao = Agent vô dụng, quá thấp = nguy hiểm — cần một dải hợp lý, *không phải càng thấp càng tốt*)
3. **Số lần Tier 2 bắt lỗi Tier 1** — chỉ số quý nhất, chứng minh lớp an toàn 2 tầng xứng đáng tồn tại
4. **MTTR** (Mean Time To Respond) — thời gian trung bình từ alert đến hành động hoàn tất, đối chiếu quy trình thủ công. Chỉ số SOC dùng thật, nói bằng ngôn ngữ doanh nghiệp quen nghe

**QUAN TRỌNG — Agent hiện có của tớ nhận raw log, không phải ticket:** việc chuyển đổi **chỉ đổi ĐẦU VÀO của lõi reasoning**, giữ nguyên Retriever/Analyzer, bọc thêm node mới xung quanh. Không viết lại từ đầu.

### 4.3b · Lõi Agent cũ `KMA_AI_AGENT` — đã đọc code thật (thư mục `E:\Download\KMA_AI_AGENT`)

- **Luồng LangGraph:** extractor → correlator → retriever → analyzer → reflection → (human_review | responder). State là `SOCAgentState` (TypedDict). FastAPI v2.3 (`/analyze`, `/analyze/batch`) + dashboard Streamlit 3 tab.
- **LLM:** `ChatOllama(model="llama3.1", temperature=0.0, request_timeout=120)`, ép đầu ra Pydantic (`AnalyzerOutput` 7 trường, `ReflectionOutput` 3 trường). **Chưa đặt `num_ctx`** → Ollama mặc định ngữ cảnh ngắn, prompt dài có thể bị cắt âm thầm.
- **RAG:** embedding `all-MiniLM-L6-v2` (384 chiều) · corpus MITRE ATT&CK + 311 luật Sigma · `RecursiveCharacterTextSplitter(800, overlap 120)` · ChromaDB **7.720 chunk** (6.994 MITRE + 725 Sigma) · retriever lấy 2 Sigma + 5 MITRE, xếp theo `trust_score`, giữ top-3, có khoá luồng quanh ChromaDB. **Chưa có ATLAS** — phải nạp thêm cho nhánh thị giác.
- **Responder:** ma trận severity × evidence → ignore/monitor/alert/throttle/block_ip/...; iptables gọi bằng list (không shell), kiểm IP bằng `ipaddress`, so token bằng `hmac.compare_digest()`.
- **8 lỗ hổng đã rà (phải sửa khi chuyển sang ticket):** (1) log thô đổ thẳng vào system prompt · (2) đầu ra LLM dẫn thẳng tới hành động · (3) nhánh `human_review` không bao giờ chạy vì `agent_mode` không được đặt · (4) phòng thủ RAG tin metadata tự khai · (5) endpoint `/internal/inject-rag-poison` không xác thực + CORS `*` · (6) SOAR để chế độ LIVE mặc định · (7) `OutputSanitizer`/`ActionTools` không nằm trên luồng chạy thật (chỉ trong `test2.py`) · (8) `pending_review.jsonl` (1.048 mẫu) là nhãn do LLM tự sinh, **không dùng làm ground truth**.

**Việc tiếp theo:**
- [ ] Sửa node đầu vào: đọc ticket thay vì raw_log
- [ ] Thêm node enrich + 2 tầng an toàn + function calling + audit
- [ ] Dựng vector DB, nạp ATT&CK + ATLAS
- [ ] Dựng bộ N kịch bản đánh giá + đo MTTR
- [ ] (Tuỳ chọn) VLM — xem điều kiện gọi ở mục 7

---

## 4.4 · Toàn bộ phép đo của đề tài — 10 cái, đừng sót cái nào

Trước đây các phép đo nằm rải khắp nơi nên rất dễ sót lúc viết báo cáo. Bản đầy đủ ở **mục 09 file kiến trúc**; danh sách ngắn:

| # | Phép đo | Khối |
|---|---|---|
| 1 | Bảng A–E · ablation B1→B3 | Thị giác |
| 2 | Bảng F · đường cong suy giảm | Thị giác |
| 3 | Confusion matrix cũ (chỉ Sigma) vs mới | OS/mã độc |
| 4 | Bake-off RF vs LightGBM | Pre-filter |
| 5 | Bảng chịu tải bật/tắt Pre-filter | Pre-filter + Agent |
| 6 | Có/không cột `co_alert_cheo_nhanh` *(tuỳ chọn)* | Pre-filter |
| 7 | Bộ N kịch bản + MTTR | AI Agent |
| 8 | ASR tiêm lệnh có/không Guard | Log-injection Guard |
| 9 | **Tỷ lệ bỏ lọt của Pre-filter** (shadow mode + mẫu đối chứng 5%) | Pre-filter |
| 10 | Có/không gọi VLM *(nếu làm VLM)* | Thị giác |

**Câu để nói trong buổi bảo vệ:** mười phép đo hỏi mười câu khác nhau nhưng cùng một kiểu — *"bỏ thành phần này đi thì hệ thống tệ đi bao nhiêu?"*. Thành phần nào bỏ đi mà số không đổi thì không xứng đáng nằm trong kiến trúc.

---

## 5. Thuật ngữ riêng của nhóm (để Claude mới không hiểu nhầm)

| Từ | Nghĩa trong đề tài này |
|---|---|
| **B1 / B2 / B2a / B3** | 4 pipeline thị giác trong benchmark ablation |
| **Bảng A–F** | 6 bảng kết quả nhánh thị giác (F = đường cong độ bền suy giảm) |
| **C / D / E / S** | Concentration · Positional shift · Entropy · Temporal Stability |
| **MS-GradCAM** | Trung bình N=12 Grad-CAM trên ảnh nhiễu — **nhóm tự đặt tên, không phải paper có sẵn** (phải nói minh bạch) |
| **KT1 / KT2 / KT3** | DirectShow/WMF buffer hooking · brute-force credential RTSP · chiếm quyền PTZ/OSD qua ONVIF. Nối nhau bằng T1078 Valid Accounts. **KT1 cũng là đường tiêm patch số** |
| **KT4** | Đã nhận diện, chưa làm: tấn công dữ liệu lưu trữ (T1486) — có case thật Akira ransomware qua webcam |
| **Demo A / B / C** | chỉ thị giác · chỉ mã độc · liên nhánh (thứ tự trình diễn bắt buộc) |
| **Phương án C** | Cách ghép OR-gate của Pre-filter |
| **(A) / (B) / (C) / (D)** | 4 khối của hợp đồng dữ liệu: alert thị giác · alert Sysmon · alert sau Pre-filter · ticket (xem mục 4.0) |
| **`co_alert_cheo_nhanh`** | Một **cột feature cho model cây phía Sysmon** (có alert thị giác đi kèm không) — KHÔNG phải cơ chế cho alert thị giác đi qua Pre-filter |
| **P1 … P5** | 5 thành viên (xem mục 2): P1 thị giác + trưởng nhóm · P2, P3 SIEM · P4, P5 dataset + demo. *Tài liệu cũ trước 26/09 dùng P2 = SIEM, P3 = dataset/demo* |

---

## 6. Ràng buộc kỹ thuật phải nhớ

- GPU máy nhà: **RTX 4060 8GB** — không chạy được Llama 8B + VLM 11B cùng lúc
- **Colab Pro không chạy nền** → job dài phải checkpoint ra Drive + resume được, hoặc để máy nhà
- Hệ thống chạy **near-real-time ở biên** → pipeline chính xác nhất chưa chắc được chọn; phải cân với FPS
- Font: **IBM Plex Mono làm rơi dấu tiếng Việt** — chỉ dùng cho code/định danh ASCII, chữ tiếng Việt dùng Archivo

---

## 7. Quyết định còn mở

1. Thuật toán Pre-filter cuối cùng (RF hay LightGBM) — chờ bake-off
2. Ngưỡng `THRESHOLD` của Pre-filter — chờ đường precision-recall
3. Pipeline thị giác triển khai thật (B2a hay B3) — chờ bảng benchmark
4. **Viết kịch bản demo từng giây cho 3 demo** ⭐ — cấu trúc A/B/C đã chốt nhưng chưa có văn bản mô tả giây nào attacker làm gì, alert nào nổ lúc nào, màn hình nào chiếu. **Nên làm sớm** — viết ra sẽ lộ lỗ hổng thực thi trước khi tốn công code
5. **Tra cứu mã MITRE cho "tiêm/sửa giữa luồng media"** ⭐ — chưa gán mã khi chưa kiểm chứng, không bịa
6. **Điều kiện gọi VLM (nếu làm VLM)** ⭐ — *vị trí đặt VLM đã chốt: ở biên, xuất `vlm_verdict` dạng chữ (mục 3)*; còn lại đúng một câu hỏi **khi nào gọi**. Đề xuất: `suspicion_score` rơi dải sát ngưỡng (vd 0.35–0.65), **hoặc** Jedi và LGS bất đồng kết luận (điều kiện này hay hơn vì tận dụng cơ chế đối chứng chéo đã có). **Bắt buộc benchmark cả trường hợp KHÔNG gọi VLM** — phải đo: (a) tỷ lệ alert rơi vào vùng phải hỏi VLM, (b) độ chính xác tăng thêm *riêng trên tập mập mờ*, (c) độ chính xác tổng thể (sẽ chỉ nhích nhẹ — cần nói trước để không bị hiểu nhầm kỳ vọng). VLM demo được **bên trong Demo A**, không cần kịch bản riêng
7. **Chốt quy ước `device_id` + đồng bộ đồng hồ camera↔Gateway** ⭐ — việc nhỏ nhưng là điều kiện sống còn của luật tương quan; sai thì demo C không nổ *mà cũng không báo lỗi*. Bảng ánh xạ ID chung trong `asset_inventory.yaml` + NTP cùng nguồn
8. **Chốt danh sách cột `features` của khối (B) với nhóm SIEM** ⭐ — phải chốt **trước khi** train, vì thêm/bớt cột sau là train lại từ đầu. Quyết định luôn có đưa `co_alert_cheo_nhanh` vào hay không
9. Có làm Log-injection Guard bằng DeBERTa không — ưu tiên thấp
10. PS-GAN giữ hay bỏ — chốt cuối Tuần 2

---

## 8. Nâng cấp "tính ứng dụng" — đã bàn, chưa làm

**Nên làm (rẻ, tăng uy tín rõ):** Docker Compose cho toàn hệ · quản lý secret bằng `.env` (đề tài an ninh mà hardcode key là mất điểm nặng) · audit log dạng **chuỗi hash** (mỗi bản ghi chứa hash bản ghi trước — ~10 dòng code, nối liền mạch với lập luận HMAC) · ghi phiên bản model vào ticket · chống trùng lặp alert (idempotency).

**Cân nhắc:** SQLite → PostgreSQL theo kiểu **phân tầng** (SQLite *trên Gateway* cho ticket cục bộ, sống được khi mất mạng — đúng tinh thần tự chủ ở biên; PostgreSQL ở *SOC trung tâm* gom nhiều gateway), viết qua **SQLAlchemy** ngay từ đầu để đổi chỉ là đổi chuỗi kết nối · hàng đợi Redis giữa Splunk và Agent · metrics Prometheus/Grafana · suy giảm có kiểm soát khi Ollama chết.

**Bỏ thẳng:** Kubernetes · tách microservices · multi-tenancy · Kafka · tự code lại giao diện tìm kiếm log kiểu Splunk.

**Về dashboard:** Splunk đã có dashboard riêng — **không tự code lại**. Khoảng trống thật là tầng SOAR (ticket, kết luận Agent, audit) mà Splunk không biết. Cách rẻ: **đẩy ngược kết quả ticket vào Splunk qua HEC** (đã có sẵn đường) → dựng dashboard Splunk, **không viết dòng frontend nào**. Cách đắt hơn: trang console nhỏ hiển thị *chuỗi suy luận của Agent*. Hoặc: Telegram bot kèm nút duyệt — cũng là một giao diện hợp lệ, rẻ, demo sống động.

**Backend ≠ database:** database là nơi dữ liệu nằm im; backend là code chạy logic. **AI Agent service chính là backend** của hệ này — đang thiếu *cái cửa* (API), không thiếu nhân viên.

---

## 9. Index tài liệu (13 file, mở lại được bất cứ lúc nào)

| # | Tài liệu | Cho ai | Link |
|---|---|---|---|
| 0 | **Kiến trúc tổng quan** (file mẹ, 12 mục — **v14**: hợp đồng dữ liệu + định tuyến OCSF + chính sách HMAC (mục 05) · gộp ticket "cho nhập sau" (mục 06) · hai đường qua Pre-filter + shadow mode (mục 08) · bảng tổng kết 10 phép đo (mục 09) · vị trí VLM (mục 10)) | cả nhóm | https://claude.ai/artifact/QP6gN3D99sW8PhTY98QD7z |
| 1 | Phòng thủ bao quát (kỹ thuật + kế hoạch) | cả nhóm | https://claude.ai/artifact/QYEofWSTyRt17finEYApoq |
| 2 | SIEM / Splunk — giao nhiệm vụ | **P2, P3** | https://claude.ai/artifact/Xw4FN2Tb1QkxNWpZBeadw1 |
| 3 | Yêu cầu dataset + chuẩn hoá | **P4, P5** | https://claude.ai/artifact/Gz4uuCcC4KkHcBRddSwJ2k |
| 4 | Kế hoạch AI đầy đủ | **P1 (tớ)** | https://claude.ai/artifact/2CGjXyqaiyUzsxXzWq5Kvz |
| 5 | Guide thị giác (dễ hiểu + composite) | P1 | https://claude.ai/artifact/WAkh9qCffnQT5uha4eFRTq |
| 6 | Kiến thức nền — nhánh thị giác | P1 | https://claude.ai/artifact/UNT6Y46MqNdW5vTgycBQFN |
| 7 | Kế hoạch train & thuê GPU | P1 | https://claude.ai/artifact/1tMPFoXa9vMdQEkd1VsLXS |
| 8 | Guide code ML Pre-filter | P1 | https://claude.ai/artifact/HEp1w3rKXbg2UUFUJJMuNj |
| 9 | Guide chuyển Agent sang mô hình ticket | P1 | https://claude.ai/artifact/LWFL4dxvxK8F5jhtd5YBxu |
| 10 | Setup Colab Pro cho thị giác + vụ nhìn loss | P1 | https://claude.ai/artifact/MBuYz848d7MaGv3CWpuunX |
| 11 | Nền tảng ML & An ninh (kiến thức nền phần 2 — **v3**: thêm hộp phân biệt LR vs RF/LightGBM, và vì sao không dùng Ridge/Lasso) | P1 | https://claude.ai/artifact/K1iWWVy7kniwqSnfhWH6Nm |
| 12 | **Bản đồ tổng quan ngành AI** (6 trục · cloud vs edge · 3 thế hệ RAG · chunking · mẫu agent · LLMOps) | P1 | https://claude.ai/artifact/GChQqPpZxkasJKWrDAbsjg |

**Tài liệu thêm sau v14:**

| Tài liệu | Cho ai | Ở đâu |
|---|---|---|
| **Hướng dẫn Git + GitHub + Trello từ số 0** | cả nhóm 5 người | https://claude.ai/artifact/EZMQCpWCuDKFdqyJbumosa · bản file: `HUONGDAN_Git-GitHub-Trello.html` (thư mục `Claude outputs`) |
| **Khung repo `edgeguard-ai`** (README, .gitignore, CONTRIBUTING, mẫu PR) | P1 dựng repo | file `edgeguard-ai_khung-repo.zip` |
| Bộ ôn phỏng vấn AI Security (hỏi đáp đề tài, đào sâu, ý tưởng, theo CV, bản đồ ngành) | riêng tớ | các file `PHONGVAN_*.html`, `DINHHUONG_*.html`, `KYTHUAT_*.html` trong `Claude outputs` |

> **Lưu ý:** Claude ở chat mới **không tự dò tìm** artifact — nó chỉ biết những gì có link trong file này (hoặc tớ dán vào). Mỗi khi có tài liệu mới, **phải thêm dòng vào bảng này**, nếu không nó coi như vô hình.

---

## 10. Cách tớ muốn làm việc (nói luôn cho Claude mới)

- Trả lời **tiếng Việt**, xưng "tớ/cậu"
- Kiến thức nền tớ còn **chắp vá**, đặc biệt computer vision — giải thích từ gốc, đừng giả định tớ biết sẵn
- **Kiểm chứng bằng nguồn thật** (paper/tài liệu chính thức) trước khi khẳng định, đừng đoán. **Không bịa mã MITRE/số liệu cho đẹp báo cáo**
- Tài liệu dài thì **xuất thành artifact HTML** (mở lại được, share cho nhóm được), đừng viết hết vào chat
- Tớ hay bắt được lỗi/thiếu sót trong tài liệu — **nếu tớ nói thiếu thì kiểm tra lại thật, đừng vội đồng ý cho xong**
- Khi viết câu trả lời để tớ nói (phỏng vấn, bảo vệ): **dạng đoạn văn, xưng "em"**, thuật ngữ đúng nhưng dễ hiểu; phần chưa làm thì nói "em đã thiết kế / hướng phát triển", **không bịa con số cho phần chưa chạy** — nói "em sẽ chọn bằng thí nghiệm"
- Chữ ký phương pháp của đề tài: **mỗi thành phần thêm vào phải tự chứng minh bằng một phép đo có/không có nó** (ablation B1→B3 · bake-off RF/LightGBM · bảng chịu tải Pre-filter · số lần Tier 2 bắt lỗi Tier 1 · benchmark VLM có điều kiện). Giữ nhất quán nguyên tắc này khi đề xuất thêm bất cứ thứ gì
