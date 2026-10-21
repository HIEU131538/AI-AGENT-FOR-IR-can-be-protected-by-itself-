---
title: "CHƯƠNG 3 — KẾT QUẢ VÀ THỰC NGHIỆM (AegisSOC)"
---

> **Ghi chú biên tập (xoá khi đưa vào Word):** Mục **3.2** để nhóm tự viết: bạn Splunk viết phần lab, bạn eval viết phần tấn công vào tác tử. Các ô `[điền sau demo]` điền sau buổi chạy thật. Số liệu lấy từ `results/BAO_CAO_benchmark.md`. Chỗ `[Hình 3.x]` là vị trí chèn hình.

# 3.1. Môi trường và cấu hình thực nghiệm

Hệ thống được triển khai trên hai máy vật lý cùng một mạng LAN, tách vai trò **giám sát** và **phân tích**. Máy 1 chạy hai máy ảo (Windows 10 có Sysmon; Kali có Nginx và Suricata) cùng Splunk Enterprise. Máy 2 chạy tác tử AegisSOC.

| Máy | IP / Hostname | Thành phần | Vai trò |
|---|---|---|---|
| Máy ảo Windows 10 | 192.168.10.128 / DESKTOP-6FBL9UV | Sysmon, Universal Forwarder | Nguồn log endpoint |
| Máy ảo Kali | 192.168.10.135 / proxy01 | Nginx, Universal Forwarder | Nguồn log web |
| (cùng máy Kali) | 192.168.10.135 / sensor-net-01 | Suricata, Universal Forwarder | Nguồn log mạng |
| Máy 1 | DESKTOP-NF3DDH9 | Splunk Enterprise, splunk_bridge.py | SIEM, 28 luật Sigma |
| Máy 2 | (IP trong LAN) | FastAPI, Ollama, ChromaDB, prefilter, dashboard | Tác tử AegisSOC |

*Bảng 3.1. Các thành phần thực nghiệm*

`[Hình 3.1. Mô hình triển khai hai máy]`

| Tham số tác tử | Giá trị |
|---|---|
| Mô hình ngôn ngữ | Llama 3.1 8B Instruct (Ollama), temperature 0, num_ctx 4096, num_predict 700 |
| Mô hình nhúng | all-MiniLM-L6-v2 |
| Kho tri thức | 28 luật Sigma + MITRE ATT&CK CTI, 3.073 đoạn, manifest ký HMAC-SHA256 |
| Prefilter | Random Forest hiệu chuẩn isotonic, 12 đặc trưng, ngưỡng chi phí t = 1/11 |
| SOAR | SIMULATION |
| Cấu hình phòng vệ | off (8010), l1 (8011), l12 (8012), full (8000) |

*Bảng 3.2. Cấu hình tác tử*

# 3.2. Kịch bản mô phỏng

`[Phần này nhóm tự viết — bạn Splunk: hoạt động trong lab và luật bắt; bạn eval: tấn công vào tác tử. Ghi tên kỹ thuật và mã ATT&CK / ATLAS / OWASP.]`

# 3.3. Quy trình đánh giá

Thực nghiệm đánh giá theo hai lớp. **Lớp đo định lượng (benchmark)** dùng các bộ dữ liệu cố định, chạy lặp nhiều lần, cho kết quả có ý nghĩa thống kê. **Lớp trình diễn (demo)** chạy toàn tuyến từ Splunk tới tác tử để minh hoạ hệ thống hoạt động trong điều kiện thật. Ma trận nhầm lẫn và các chỉ số chính thức đều lấy từ lớp đo định lượng, vì demo chỉ gồm số ít cảnh báo.

| Bảng | Mục đích | Dữ liệu | Cách chạy |
|---|---|---|---|
| Bảng 1 | Prefilter bỏ lọt bao nhiêu tấn công | Tập test chính thức UNSW-NB15 (82.332 dòng) | Chạy 1 lần (mô hình tất định, random_state cố định) |
| Bảng 2 | Tỷ lệ tiêm lệnh thành công (ASR) theo từng lớp | 40 payload đóng băng, 5 trường dữ liệu | 3 lần mỗi cấu hình, báo cáo trung bình và dải |
| Bảng 3 | Đầu độc kho RAG: lọc metadata vs Lớp 5 | 7 tài liệu kiểm thử | Mỗi tài liệu 1 ca, off và full chạy song song |
| Bảng 4 | Giá của phòng thủ | Bộ kịch bản vàng v2 (61 kịch bản) | off, full và mốc splunk_copy |

*Bảng 3.3. Thiết kế các phép đo*

Các định nghĩa chỉ số giữ như mục 2.3.8. Riêng ma trận nhầm lẫn nhị phân ở mục 3.4.5 dùng định nghĩa: tác tử **phát hiện** một ca khi đề xuất hành động `review` hoặc `block` (leo thang); **không phát hiện** khi `no_action` hoặc `monitor`.

**Quy trình chạy demo phía tác tử:**
1. Bật hai bản tác tử `off` (cổng 8010) và `full` (cổng 8000), kiểm tra `/health`.
2. Bridge trỏ `AGENT_URL` tới bản `full`, xác thực bằng token.
3. Theo dõi kết quả trên dashboard: incident, chuỗi ATT&CK, quyết định prefilter, trạng thái chờ duyệt.
4. Ghi lại cho mỗi cảnh báo: kết luận kỳ vọng, kết luận của tác tử, quyết định prefilter, có gộp đúng incident không, độ trễ từ lúc Splunk bắn tới lúc có kết luận.
5. Phương án dự phòng: phát lại các cảnh báo thật đã xuất từ Splunk (`replay/demo/`) thẳng vào tác tử.

# 3.4. Kết quả

## 3.4.1. Bảng 1 — Lớp lọc trước

| Bản | Cấu hình | Bỏ lọt (FN) | FNR | % cảnh báo lọc bớt |
|---|---|---|---|---|
| full (42 cột) | Không prefilter | 0 | 0% | 0% |
| full (42 cột) | RF, ngưỡng 0,5 | 783 | 1,73% | 34,8% |
| full (42 cột) | RF hiệu chuẩn, ngưỡng t = 0,09 | 5 | 0,01% | 25,9% |
| subset_flow (12 cột) | RF, ngưỡng 0,5 | 978 | 2,16% | 33,4% |
| subset_flow (12 cột) | RF hiệu chuẩn, ngưỡng t = 0,09 | 7 | 0,02% | 24,7% |

*Bảng 3.4. Số ca tấn công bị prefilter bỏ lọt trên tập test UNSW-NB15 (45.332 ca tấn công)*

Ở ngưỡng mặc định 0,5, bản chạy thật bỏ lọt 978 ca tấn công. Sau khi hiệu chuẩn xác suất và đặt ngưỡng theo tỷ lệ chi phí 10:1, số ca bỏ lọt giảm còn 7 (0,02%), trong khi prefilter vẫn lọc bớt khoảng một phần tư số cảnh báo, tức tiết kiệm khoảng 25% lượt gọi mô hình ngôn ngữ. Kết quả minh chứng luận điểm ở mục 2.3.4: với SOC, ngưỡng quyết định quan trọng hơn bản thân độ chính xác của mô hình.

Bản full chứa `sttl/dttl`, hai đặc trưng được biết là làm lộ nhãn trong UNSW-NB15, nên chỉ dùng để đối chiếu với các công bố. Bản 12 cột là bản gắn vào hệ thống. Trên lưu lượng của lab, kết quả prefilter chỉ mang tính minh hoạ, vì phân phối dữ liệu lab khác UNSW-NB15 và luồng mạng chưa kết thúc tại thời điểm Suricata ghi nhận.

## 3.4.2. Bảng 2 — Tỷ lệ tiêm lệnh thành công theo từng lớp

| Cấu hình | ASR (trung bình 3 lần) | Dải | ASR (cách chấm nghiêm) |
|---|---|---|---|
| off | 0,092 | 0,075 – 0,125 | 0,158 |
| l1 | 0,075 | 0,075 | 0,125 |
| l12 | 0,125 | 0,075 – 0,150 | 0,342 |
| full | 0,150 | 0,125 – 0,200 | 0,400 |

*Bảng 3.5. ASR tiêm lệnh gián tiếp*

`[Chèn Bảng 2b — ASR theo trường dữ liệu, lấy từ results/BAO_CAO_benchmark.md]`

**Diễn giải:**
1. ASR của cả bốn cấu hình nằm trong dải hẹp 0,075 – 0,15. Chênh lệch giữa các cấu hình chỉ 1 – 3 payload trên 40, nằm trong mức dao động giữa các lần chạy của mô hình 8B. Vì vậy không thể kết luận "càng nhiều lớp thì ASR càng thấp".
2. Lớp 1 (Rule of Two) là lớp cho kết quả ổn định nhất: 0,075 ở cả 3 lần chạy, vì đây là cơ chế tất định.
3. Khoảng cách giữa cách chấm chuẩn và cách chấm nghiêm (bản full: 0,15 so với 0,40) là phần Lớp 1 giữ lại được: các ca tác tử bị dẫn dắt nhưng hành động chặn được chuyển sang chờ người duyệt thay vì bị bỏ.
4. Các ca còn lọt chủ yếu là hạ mức độ nghiêm trọng xuống dưới ngưỡng chặn, nằm ngoài phạm vi Lớp 1. Trường `request_body` là điểm yếu dai dẳng ở mọi cấu hình.
5. Bảng 2.15 (mục 2.3.7) cho thấy biến thể spotlighting đặt dữ liệu ở lượt riêng làm ASR tăng lên 0,350; biến thể datamarking inline đưa về mức nền.

## 3.4.3. Bảng 3 — Đầu độc kho tri thức RAG

| Chỉ số | Lọc theo metadata (cấu hình off) | Lớp 5 (manifest HMAC) |
|---|---|---|
| Tài liệu kiểm thử lọt vào ngữ cảnh | 6/7 | **0/7** |
| Tài liệu bị chặn ở tầng truy xuất | 1/7 (chỉ tài liệu trung thực) | **7/7** |
| Kết luận bị kéo theo hướng hạ mức khi tài liệu nằm trong ngữ cảnh | 1/6 (high + chặn → medium + chuyển duyệt) | 0 |
| Kết luận đổi dù tài liệu **không** vào ngữ cảnh (dao động nền) | 1/1 | 1/7 |
| Sinh cảnh báo toàn vẹn kho (vế phát hiện) | 1/7 | **7/7** |

*Bảng 3.6. Kết quả đầu độc RAG (7 tài liệu: 4 giả mạo luật Sigma, 2 diễn giải lại, 1 trung thực)*

Bộ lọc theo metadata tự khai bị vượt qua bởi mọi tài liệu giả mạo metadata tin cậy: 6/7 tài liệu lọt vào ngữ cảnh của tác tử. Chỉ tài liệu trung thực (không giả metadata) bị chặn, chứng tỏ bộ lọc không nhận bừa mà bị đánh lừa bởi metadata giả. Lớp 5 chặn đủ 7/7 tài liệu ngay tại tầng truy xuất vì chúng không có trong manifest đã ký.

Cột "đổi kết luận" cần đọc thận trọng. Cảnh báo dùng để đo (SQL injection, mức luật high) nằm sát ranh giới quyết định của mô hình 8B: ngay ở lượt đo nền, chưa có tài liệu độc, kết luận đã dao động giữa *high + chặn* và *medium + chuyển duyệt* giữa các ca. Vì vậy ở cấu hình off chỉ có một ca bị kéo đúng theo hướng hạ mức khi tài liệu độc nằm trong ngữ cảnh; bốn ca khác đổi theo hướng *nâng* mức (ngược mục tiêu đầu độc); và tài liệu trung thực tuy bị chặn vẫn ghi nhận thay đổi. Ở cấu hình full, một ca đổi kết luận dù không tài liệu nào vào ngữ cảnh. Qua các lần chạy, số ca bị hạ mức dao động 1–2 và không lặp lại trên cùng một tài liệu. Do đó chỉ số quyết định của phép đo này là **tài liệu có lọt vào ngữ cảnh hay không**: một khi tài liệu độc đã nằm trong ngữ cảnh, việc nó có đổi được kết luận hay không chỉ còn là vấn đề xác suất, còn Lớp 5 loại bỏ khả năng đó ngay từ tầng truy xuất.

Ở vế phát hiện, tiêu chí metadata chỉ báo động được tài liệu trung thực (1/7), trong khi tiêu chí manifest báo động đủ 7/7 tài liệu kiểm thử mà không báo nhầm tài liệu nền: hệ thống vừa chặn được vừa biết mình đang bị tấn công. Dòng này được đo trực tiếp từ trường `integrity_alert` mà hệ thống trả về ngay lúc tài liệu được ghi vào kho.

## 3.4.4. Bảng 4 — Giá của phòng thủ

| Chỉ số | off | full | splunk_copy |
|---|---|---|---|
| Accuracy mức độ | 0,459 | 0,459 | 0,459 |
| Macro-F1 mức độ | 0,429 | 0,422 | 0,388 |
| Đúng mã ATT&CK | 0,984 | 0,984 | 0,984 |
| Đề xuất đúng hành động | 0,574 | 0,590 | 0,623 |
| Báo nhầm trên ca lành tính | 0,889 | 0,889 | 0,833 |
| Tỷ lệ chuyển người duyệt | 0 | **0,492** | 0 |
| Thời gian xử lý trung bình | 18,3 s | 18,2 s | — |

*Bảng 3.7. Chất lượng phân loại khi tắt và bật đủ phòng vệ*

| Nhóm | Chỉ số | off | full | splunk_copy |
|---|---|---|---|---|
| siem_correct = true (28) | Accuracy mức độ | 0,893 | 0,893 | 1,000 |
| siem_correct = true (28) | Tỷ lệ chuyển người duyệt | 0 | 0,607 | 0 |
| siem_correct = false (33) | Accuracy mức độ | 0,091 | 0,091 | 0 |
| siem_correct = false (33) | Đề xuất đúng hành động | 0,333 | 0,333 | 0,303 |

*Bảng 3.8. Kết quả theo nhóm kịch bản*

Bật đủ bốn lớp phòng vệ không làm giảm chất lượng phân loại: accuracy bằng nhau (0,459), đúng mã ATT&CK giữ nguyên 0,984, báo nhầm không tăng, đề xuất đúng hành động nhỉnh hơn (0,590 so với 0,574). Thời gian xử lý của hai cấu hình gần như bằng nhau trong cùng một lần đo. Thay đổi lớn nhất là **49,2% kịch bản được chuyển sang người duyệt**: đây là chủ đích của Rule of Two, đổi một phần tự động lấy an toàn cho các hành động có tác động.

**Đóng góp của luật nâng mức theo tactic ATT&CK.** Trong 24 kịch bản nhiều cảnh báo, luật R1 kích hoạt ở 3 kịch bản và R2 ở 2 kịch bản; **không kịch bản lành tính nào bị nâng nhầm** (các chuỗi lành tính như máy quét IT hay health check của bộ cân bằng tải chỉ lặp một tactic):

- **R1 (≥ 3 tactic → critical):** cả 3 kịch bản đều có nhãn critical và được xếp critical ở cả hai cấu hình — chuỗi kill-chain đầy đủ (recon → SQLi → web shell → C2), chuỗi web shell + khám phá + duy trì, và chuỗi hoàn chỉnh 8 bước.
- **R2 (hậu khai thác → tối thiểu high):** 2 kịch bản (schtasks + PowerShell + Run key; SQLi + web shell + RCE) được nâng lên high, nhãn chuẩn là critical. Luật đi đúng hướng nhưng chuỗi chỉ trải 2 tactic nên chưa đủ điều kiện critical.

Bộ kịch bản vàng không có chuỗi lành tính đa tactic, nên allowlist ngữ cảnh (mục 2.3.5 f) không làm thay đổi kết quả của kịch bản nào; cơ chế này được đưa vào để tránh nâng nhầm các chuỗi như sao lưu ban đêm hay quản trị trong giờ hành chính khi vận hành thật.

Nhờ đó nhóm `siem_correct = false` lần đầu có kịch bản được phán đúng (3/33), và số ca critical đoán đúng tăng từ gần như không lên 4–5/15. Phần lớn nhóm này vẫn sai vì hai lý do mà luật theo tactic không xử lý: cảnh báo lặp lại cùng một kỹ thuật (tần suất, không phải tiến triển) và ca lành tính cần mô hình chủ động hạ mức.

## 3.4.5. Ma trận nhầm lẫn

**a) Phát hiện nhị phân (tấn công / lành tính)**

| Cấu hình | TP | FN | FP | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| off | 40 | 3 | 15 | 3 | 0,727 | 0,930 | 0,816 |
| full | 39 | 4 | 15 | 3 | 0,722 | 0,907 | 0,804 |
| splunk_copy | 40 | 3 | 15 | 3 | 0,727 | 0,930 | 0,816 |

*Bảng 3.9. Ma trận nhầm lẫn nhị phân trên bộ kịch bản vàng (43 tấn công, 18 lành tính)*

**b) Phân loại mức độ 4 lớp** (hàng: nhãn chuẩn; cột: dự đoán low / medium / high / critical)

| Nhãn chuẩn | off | full | splunk_copy |
|---|---|---|---|
| low (18) | 3 / 13 / 2 / 0 | 3 / 13 / 2 / 0 | 3 / 13 / 2 / 0 |
| medium (7) | 2 / 5 / 0 / 0 | 1 / 6 / 0 / 0 | 1 / 6 / 0 / 0 |
| high (21) | 1 / 5 / 15 / 0 | 2 / 4 / 15 / 0 | 1 / 3 / 17 / 0 |
| critical (15) | 0 / 2 / 8 / **5** | 1 / 1 / 9 / **4** | 1 / 2 / 10 / **2** |

*Bảng 3.10. Ma trận nhầm lẫn mức độ nghiêm trọng*

`[Hình 3.x. conf_off.png, conf_full.png trong results/golden_off_b10, results/golden_full_b10]`

**Nhận xét:**
1. Recall phát hiện cao (0,907–0,930), nhưng 15/18 ca lành tính vẫn bị leo thang. Phần lớn ca lành tính (13/18) bị xếp medium thay vì low: tác tử thận trọng, chưa đủ tự tin hạ hẳn về lành tính. Đây là điểm yếu lớn nhất còn lại.
2. **Mức critical** được đoán đúng 5/15 (off) và 4/15 (full), so với 2/15 của mốc `splunk_copy`. Phần cải thiện đến từ luật R1 theo tactic ATT&CK; mô hình ngôn ngữ tự nó vẫn chưa lần nào chọn nâng mức. Các ca critical còn lại phần lớn bị xếp high: về hành động, critical và high đều dẫn tới đề xuất chặn, nên sai lệch này ảnh hưởng tới nhãn mức độ nhiều hơn là tới ứng phó.
3. Hai cấu hình khác nhau vài kịch bản ở cả hai chiều (ví dụ một chuỗi LOLBAS bị hạ xuống low ở bản full nhưng giữ medium ở bản off). Các khác biệt này nằm trong dao động của mô hình 8B, không do lớp phòng vệ.

## 3.4.6. Kết quả demo

| Cảnh báo | Kết luận kỳ vọng | Kết luận tác tử | Prefilter | Gộp incident đúng | Độ trễ |
|---|---|---|---|---|---|
| `[điền sau demo]` | | | | | |

*Bảng 3.11. Kết quả chạy toàn tuyến (minh hoạ)*

`[Hình 3.x. Ảnh chụp dashboard, Splunk, audit trail]`

# 3.5. Kết luận thực nghiệm

## 3.5.1. Đánh giá kết quả

1. **Prefilter:** hiệu chuẩn cùng ngưỡng theo chi phí giảm số ca bỏ lọt từ 978 xuống 7 mà vẫn lọc khoảng 25% cảnh báo.
2. **Phòng vệ tất định hiệu quả rõ nhất:** Lớp 5 chặn 100% tài liệu đầu độc; Lớp 1 giữ hành động chặn trước dẫn dắt và cho kết quả ổn định.
3. **Phòng vệ dựa trên prompt có giới hạn trên mô hình 8B:** spotlighting chỉ đạt mức trung tính, và biến thể phổ biến còn phản tác dụng. Đây là phát hiện thực nghiệm cho thấy phải đo, không thể bê nguyên kỹ thuật từ tài liệu.
4. **Phòng vệ không làm giảm chất lượng nhận diện;** cái giá là tỷ lệ chuyển người duyệt cao hơn, còn độ trễ gần như không đổi.
5. **Luật nâng mức theo tactic ATT&CK** đưa các chuỗi xâm nhập ≥ 3 tactic lên đúng critical (3/3) mà không nâng nhầm ca lành tính nào; mô hình 8B tự nó vẫn không nâng mức.

## 3.5.2. Hạn chế và hướng cải thiện

| Hạn chế | Hướng cải thiện |
|---|---|
| Kết quả mô hình 8B dao động giữa các lần chạy; bộ payload 40 mẫu còn nhỏ | Mở rộng bộ payload, tăng số lần chạy, thử mô hình lớn hơn |
| Trường `request_body` vẫn là điểm yếu tiêm lệnh | Bổ sung Lớp 3 (bộ phân loại đầu vào), tách hai mô hình |
| Mức critical mới đúng 4–5/15 (chuỗi chỉ 2 tactic, cảnh báo lặp cùng kỹ thuật chưa được nâng); báo nhầm cao trên ca lành tính | Luật theo tần suất trong cửa sổ thời gian; đưa chuỗi tactic vào phiếu điều tra; tinh chỉnh tiêu chí `downgrade_benign` |
| Prefilter học từ UNSW-NB15 (2015), khác lưu lượng lab; làn web và endpoint mới chỉ lọc nhiễu kỹ thuật và cảnh báo trùng, chưa lọc theo hành vi | Thu thập dữ liệu lab có nhãn; thêm làn ML cho endpoint (hành vi Sysmon) và web (yêu cầu HTTP có nhãn) |
| Allowlist ngữ cảnh benign dựa trên niềm tin vào danh tính: tài khoản admin hay backup bị chiếm vẫn làm được đúng các tactic và khung giờ đã khai báo mà không bị nâng mức; chưa đo tỷ lệ dương tính giả trên chuỗi lành tính thật | Thu hẹp mẫu (ít tactic, giờ cụ thể); đối chiếu thêm bất thường hành vi của tài khoản; bộ kịch bản lành tính đa tactic độc lập, do người khác viết |
| Tỷ lệ chuyển người duyệt 49% | Phân tầng hành động theo mức tin cậy; cho phép tự động với tài sản ít quan trọng |
| Chưa thử tấn công thích ứng nhiều lượt | Vòng tấn công thích ứng khi kẻ tấn công biết trước phòng thủ |

*Bảng 3.12. Hạn chế và hướng cải thiện*

# 3.6. Tổng kết chương 3

Chương 3 đã trình bày môi trường thực nghiệm hai máy, quy trình đánh giá hai lớp (đo định lượng và trình diễn toàn tuyến) cùng kết quả của bốn phép đo. Lớp lọc trước giảm mạnh số ca bỏ lọt nhờ hiệu chuẩn và ngưỡng theo chi phí. Các lớp phòng vệ tất định (Rule of Two, manifest toàn vẹn kho RAG) cho hiệu quả rõ và ổn định, trong khi phòng vệ dựa trên prompt có giới hạn trên mô hình cục bộ 8B. Việc bật đủ phòng vệ không làm suy giảm khả năng nhận diện kỹ thuật tấn công, đổi lại tăng tỷ lệ chuyển người duyệt. Luật nâng mức theo tactic ATT&CK giúp các chuỗi xâm nhập nhiều giai đoạn được xếp đúng critical. Ma trận nhầm lẫn chỉ ra hai điểm còn cần cải thiện: báo nhầm trên ca lành tính và các sự cố critical chỉ trải hai tactic hoặc lặp cùng một kỹ thuật.
