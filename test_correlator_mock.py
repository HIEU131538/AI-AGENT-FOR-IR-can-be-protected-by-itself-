import json
from agent.nodes.correlator import node_correlator

def run_mock_test():
    print("="*60)
    print("🚀 BẮT ĐẦU CHẠY THỬ NGHIỆM: CORRELATION ENGINE (TUẦN 3)")
    print("="*60)

    # State ban đầu với trí nhớ trống rỗng
    mock_state = {
        "attack_timeline": []
    }

    # KỊCH BẢN: 4 Log đến từ cùng 1 IP (10.0.0.5)
    test_logs = [
        {
            "desc": "LOG 1: Quét mạng (Bắt đầu chuỗi)",
            "raw_log": {"event": "port_scan", "timestamp": "2026-06-12T10:00:00Z"},
            "extracted_ioc": {"source_ip": "10.0.0.5"}
        },
        {
            "desc": "LOG 2: Đăng nhập sai (Nâng cấp Severity)",
            "raw_log": {"event": "ssh_bruteforce", "timestamp": "2026-06-12T10:05:00Z"},
            "extracted_ioc": {"source_ip": "10.0.0.5"}
        },
        {
            "desc": "LOG 3: Log đến muộn (Test lỗi Time Diff Âm)",
            "raw_log": {"event": "ping_sweep", "timestamp": "2026-06-12T10:02:00Z"},
            "extracted_ioc": {"source_ip": "10.0.0.5"}
        },
        {
            "desc": "LOG 4: Tấn công tiếp nhưng đã quá 15 phút (Test Timeout)",
            "raw_log": {"event": "sql_dump", "timestamp": "2026-06-12T10:30:00Z"},
            "extracted_ioc": {"source_ip": "10.0.0.5"}
        }
    ]

    for i, test_case in enumerate(test_logs, 1):
        print(f"\n>>> ĐANG XỬ LÝ {test_case['desc']} <<<")
        
        # Nạp dữ liệu vào State
        mock_state["raw_log"] = test_case["raw_log"]
        mock_state["extracted_ioc"] = test_case["extracted_ioc"]
        
        # Gọi Trạm Correlator
        result = node_correlator(mock_state)
        
        # In ra màn hình dòng tư duy của AI
        for note in result.get("investigation_notes", []):
            print(f"   {note}")
            
        # Giả lập hành vi operator.add của LangGraph (Cộng dồn trí nhớ)
        mock_state["attack_timeline"].extend(result["attack_timeline"])

if __name__ == "__main__":
    run_mock_test()