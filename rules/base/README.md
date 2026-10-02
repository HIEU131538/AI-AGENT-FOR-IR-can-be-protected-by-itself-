# Bộ luật nền AegisSOC (`rules/base/`)

Bộ luật do nhóm AegisSOC chốt. **Ba phần dùng chung đúng bộ này**:

1. **Splunk**: luật phát hiện chạy thật trong lab.
2. **Kho RAG của Agent**: Agent tra đúng luật đã bắn alert để đọc mô tả và mục `falsepositives`.
3. **Bộ kịch bản vàng v2**: `rule_name` và `rule_level` trong mỗi alert lấy đúng từ bảng này.

| Nội dung | Số lượng |
|---|---|
| Luật lấy nguyên văn từ SigmaHQ (commit `07ec293`, ngày 25/09/2026) | 25 luật, thư mục `sigmahq/` |
| Luật nhóm tự viết cho Suricata (SigmaHQ không có luật cho Suricata) | 3 luật, thư mục `custom/` |
| Chỉ mục: mã, tên, mức, ATT&CK, nguồn log, falsepositives, dùng cho gì trong lab | `base_rules.csv` |

## Việc của bạn làm Splunk

**1. Chuyển luật sang SPL bằng `sigma-cli`:**

```bash
pip install sigma-cli
sigma plugin install splunk
sigma plugin install sysmon
sigma list pipelines            # chọn pipeline khớp cách bạn nạp Sysmon vào Splunk
sigma convert -t splunk -p sysmon rules/base/sigmahq/proc_creation_win_certutil_download.yml
```

Tên trường mỗi nguồn log cần ánh xạ riêng:
- **Luật `process_creation`** (B05–B22) đọc Sysmon Event ID 1.
- **Luật `webserver`** (B01–B04) dùng tên trường `c-uri`, `c-uri-query`, `c-useragent`. Nếu nạp log IIS W3C thì phải ánh xạ về các trường tương ứng (`cs-uri-stem`, `cs-uri-query`, `cs(User-Agent)`).
- **Luật `dns`** (B23–B25) chạy trên sự kiện DNS của Suricata hoặc log DNS Windows.
- **3 luật `custom/`** dùng thẳng tên trường của Suricata `eve.json`.

**2. Đặt tên saved search đúng bằng `title` của luật.** Alert gửi sang Agent (`POST /ingest/alerts`, theo hợp đồng alert B2) phải mang:
- `rule_name` = `title`, giữ nguyên chữ hoa, chữ thường
- `rule_level` = `level`
- `attack_ids` = cột `attack_ids` trong `base_rules.csv`
- `surface`:
  - nhóm `web` → `web`
  - các nhóm `webshell`, `powershell`, `lolbas`, `discovery`, `persistence`, `lateral` → `endpoint`
  - nhóm `dns` và `network` → `network`

**3. KHÔNG tinh chỉnh luật nền để giấu báo nhầm.** Ví dụ: không thêm ngoại lệ bỏ qua máy quét của IT, không lọc script quản trị. Việc phân biệt báo nhầm là phần Agent phải làm và là thứ đề tài cần đo. Nếu Splunk tự lọc hết thì bộ đo không còn gì để đo.

**4. Muốn thêm luật thì cứ thêm**, nhưng:
- Để vào `rules/extra/`, kèm một file CSV cùng cột với `base_rules.csv`.
- Không sửa `title` hoặc `level` của 28 luật nền khi chưa báo nhóm. Bộ vàng v2 và kho RAG phụ thuộc vào hai trường này.

**5. Ghi nguồn (bắt buộc theo giấy phép).** Luật SigmaHQ phát hành theo **Detection Rule License (DRL) 1.1**. Giữ nguyên trường `author` trong file YAML. Trong mô tả của mỗi saved search chuyển từ luật SigmaHQ, ghi: `Based on SigmaHQ rule <id> by <author>, DRL 1.1`.

## Cập nhật bộ luật

Danh sách luật chọn nằm trong `sync_sigmahq.py` (thư mục gốc repo) (biến `BASE_RULES`). Chạy lại script sẽ tải đúng commit SigmaHQ đã ghi, chép lại luật nền, sinh lại `base_rules.csv`, rồi nạp thư viện luật cho RAG.
