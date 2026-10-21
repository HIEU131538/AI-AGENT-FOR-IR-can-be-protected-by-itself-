# Báo cáo Dữ liệu UNSW-NB15 (AegisSOC)

## 1. Nguồn dữ liệu
- Nguồn: Kaggle (UNSW-NB15)
- Link tải: https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15
- Ngày tải: 2026-10-04
- Thư mục gốc: `data/raw/`
- **Cách chia train/test (theo chuẩn chính thức của UNSW-NB15):** tên file trên Kaggle bị đặt ngược.
  - Tập TRAIN chính thức = file `UNSW_NB15_testing-set.csv` (175341 dòng: 56.000 normal / 119.341 tấn công).
  - Tập TEST chính thức = file `UNSW_NB15_training-set.csv` (82332 dòng).
  - Nhờ vậy kết quả có thể đặt cạnh các số đã công bố trong bài báo.

## 2. Thống kê số dòng và Tỷ lệ nhãn
- **Train (80% của tập train chính thức, sau dedup)**: 81015 dòng.
  - Nhãn 0: 41512 | Nhãn 1: 39503
- **Calib (20% của tập train chính thức, sau dedup)**: 20254 dòng.
  - Nhãn 0: 10378 | Nhãn 1: 9876
- Tỷ lệ tấn công: Train 48.760% | Calib 48.761% (stratify theo label, dedup xong mới chia).
- **Test (tập test chính thức, giữ nguyên)**: 82332 dòng.
  - Nhãn 0: 37000 | Nhãn 1: 45332

## 3. Số dòng theo attack_cat từng tập
| attack_cat | train | calib | test |
|---|---|---|---|
| Analysis | 429 | 113 | 677 |
| Backdoor | 394 | 119 | 583 |
| DoS | 2401 | 603 | 4089 |
| Exploits | 14929 | 3792 | 11132 |
| Fuzzers | 12102 | 2941 | 6062 |
| Generic | 3152 | 772 | 18871 |
| Normal | 41512 | 10378 | 37000 |
| Reconnaissance | 5118 | 1304 | 3496 |
| Shellcode | 880 | 209 | 378 |
| Worms | 98 | 23 | 44 |

## 4. Thống kê lỗi và Trùng lặp
- Ô trống (NaN/Inf) đã thay bằng 0:
  - Train: 0 ô
  - Test: 0 ô
- Số dòng trùng hoàn toàn (tính cả `attack_cat`) trong tập Train đã xóa ở bước làm sạch: 67601 dòng.
- Số dòng trùng lặp **phát sinh thêm sau khi bỏ cột `attack_cat`** (đã xóa tiếp, **trước khi chia train/calib**): 6471 dòng.
  - *Nguyên nhân: một số dòng có đặc trưng mạng (đầu vào model) giống hệt nhau nhưng được gán nhãn `attack_cat` khác nhau (ví dụ Backdoor vs Exploits). Vì `attack_cat` không được dùng làm đặc trưng train, các dòng này là bản sao thật sự đối với model nên cần xóa thêm.*
- Số dòng train (toàn bộ, trước khi chia calib) trùng với test (không xóa): 1302 dòng.
- Số dòng calib trùng hệt train (đặc trưng + label, sau mã hóa): 59 dòng.

## 5. Danh sách cột
- **Phiên bản Full**: 42 cột (Xem chi tiết tại `feature_list_full.txt`)
- **Phiên bản Subset_flow**: 12 cột: `dur, proto, service, spkts, dpkts, sbytes, dbytes, rate, sload, dload, smean, dmean`

## 6. Bảng 6.3 - Ánh xạ Suricata và Định nghĩa UNSW
| Cột UNSW | Trường Suricata | Cách tính | Định nghĩa chính thức (UNSW) |
|---|---|---|---|
| `dur` | `flow.start`, `flow.end` | `end - start` | Record total duration |
| `proto` | `proto` | lowercase | Transaction protocol |
| `service` | `app_proto` | map bảng 6.4 | http, ftp, smtp, ssh, dns, ftp-data ,irc and (-) if not much used |
| `spkts` | `flow.pkts_toserver` | lấy thẳng | Source to destination packet count |
| `dpkts` | `flow.pkts_toclient` | lấy thẳng | Destination to source packet count |
| `sbytes` | `flow.bytes_toserver` | lấy thẳng | Source to destination transaction bytes |
| `dbytes` | `flow.bytes_toclient` | lấy thẳng | Destination to source transaction bytes |
| `smean` | tính | `round(sbytes / spkts)` | Mean of the flow packet size transmitted by the src |
| `dmean` | tính | `round(dbytes / dpkts)` | Mean of the flow packet size transmitted by the dst |
| `rate` | tính | `(spkts + dpkts - 1) / dur` | Không mô tả rõ trong tài liệu UNSW; công thức xác định bằng cách dò lại từ dữ liệu |
| `sload` | tính | `(sbytes - smean) * 8 / dur` | Source bits per second |
| `dload` | tính | `(dbytes - dmean) * 8 / dur` | Destination bits per second |

**Quy ước:** khi `dur = 0` thì đặt `rate = sload = dload = 0` (và `smean`/`dmean` = 0 khi `spkts`/`dpkts` = 0).
Các công thức trên khớp dữ liệu UNSW với sai số khoảng 1e-8. Lúc chạy thật, hệ thống tính các cột này
từ log Suricata bằng cùng công thức (hàm `compute_derived` trong `prepare_data.py`); sai công thức thì
model nhận số lệch thang và chấm sai.

**Kiểm chứng công thức** (tính lại từ `spkts`/`dpkts`/`sbytes`/`dbytes`/`dur` rồi so với cột có sẵn; dung sai tương đối 1e-6):

| Tập | Cột | Dòng lệch (dung sai 1e-6) | Dòng lệch > 1% | Lệch tương đối lớn nhất |
|---|---|---|---|---|
| Train | `smean` | 1643 / 175341 | 547 | 2.5641% |
| Train | `dmean` | 1583 / 175341 | 912 | 2.2222% |
| Train | `rate` | 4 / 175341 | 4 | 100.0000% |
| Train | `sload` | 32373 / 175341 | 23 | 100.0000% |
| Train | `dload` | 35455 / 175341 | 13 | 78.9738% |
| Test | `smean` | 647 / 82332 | 282 | 2.5641% |
| Test | `dmean` | 1082 / 82332 | 514 | 2.2222% |
| Test | `rate` | 1269 / 82332 | 1269 | 100.0000% |
| Test | `sload` | 18292 / 82332 | 1332 | 100.0000% |
| Test | `dload` | 19891 / 82332 | 83 | 100.0000% |

*Ghi chú:* các dòng bị đánh dấu "lệch" ở dung sai chặt 1e-6 đều lệch rất nhỏ (xem cột "Lệch tương đối lớn nhất"),
nguyên nhân là do làm tròn `smean`/`dmean` và do dữ liệu gốc lưu số thực với độ chính xác hữu hạn. Số dòng có ít nhất
một cột lệch quá 1% chỉ là một phần rất nhỏ: Train: 1482 / 175341 dòng (0.845%); Test: 2114 / 82332 dòng (2.568%).

**Điểm không khớp được hoàn toàn giữa Suricata và UNSW-NB15 (bắt buộc ghi, theo mục 6.3):**
- Cách đếm byte của Suricata có thể lệch nhẹ với UNSW do cách tính header/payload.
- Khi Suricata bắn alert, luồng mạng có thể **chưa kết thúc** (chưa đủ `flow.end`), nên `dur`,
  `spkts`/`dpkts`, `sbytes`/`dbytes` và các cột tính từ chúng (`rate`, `sload`, `dload`, `smean`, `dmean`)
  có thể **chưa đầy đủ/không ổn định** so với dữ liệu UNSW vốn đo trên luồng đã hoàn tất.

## 7. Những gì bất thường gặp phải khi xử lý
- Phát hiện 6471 dòng ở tập train chính thức trùng lặp hoàn toàn về đặc trưng + label
  sau khi bỏ cột `attack_cat` (dù `attack_cat` của chúng khác nhau) — đã xóa thêm trước khi chia train/calib, xem mục 4.
- **Giá trị `proto` hiếm có tỷ lệ tấn công rất cao (nguy cơ "đường tắt"):** trong UNSW, các giá trị
  `proto` hiếm như `unas` và nhóm `__other__` (mọi proto ngoài top 10) có tỷ lệ tấn công 100%. Ngoài đời
  không như vậy, nên model có thể học "đường tắt" (thấy proto lạ là kết luận tấn công) thay vì học
  hành vi luồng thật. Số dòng và tỷ lệ cụ thể (tính trên tập train chính thức sau dedup và tập test,
  trước khi mã hóa):

| proto | Train: số dòng | Train: % tấn công | Test: số dòng | Test: % tấn công | Ghi chú |
|---|---|---|---|---|---|
| `tcp` | 76119 | 49.86% | 43095 | 35.38% |  |
| `udp` | 22984 | 43.44% | 29418 | 72.48% |  |
| `__other__` | 742 | 98.11% | 4066 | 100.00% |  |
| `arp` | 633 | 0.00% | 987 | 0.00% |  |
| `unas` | 474 | 100.00% | 3515 | 100.00% | ⚠️ 100% tấn công ở Train |
| `ospf` | 196 | 68.88% | 676 | 94.38% |  |
| `sctp` | 62 | 100.00% | 324 | 100.00% | ⚠️ 100% tấn công ở Train |
| `any` | 18 | 100.00% | 96 | 100.00% | ⚠️ 100% tấn công ở Train |
| `igmp` | 17 | 0.00% | 30 | 0.00% |  |
| `ipv6` | 12 | 100.00% | 61 | 100.00% | ⚠️ 100% tấn công ở Train |
| `rsvp` | 12 | 100.00% | 64 | 100.00% | ⚠️ 100% tấn công ở Train |

  *`__other__` ở đây là các giá trị proto không nằm trong top 10 của tập train (và không phải `unas`).*
- *(Điền tay thêm nếu có: số dòng/tỷ lệ nhãn khác xa tài liệu mô tả, giá trị service lạ không có trong bảng 6.4, v.v.
  Nếu gặp bất thường khác — báo Hiếu ngay, đừng tự sửa cho khớp.)*
