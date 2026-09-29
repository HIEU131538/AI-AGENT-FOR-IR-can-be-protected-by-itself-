import os
import shutil
import subprocess

def sync_sigma_rules():
    repo_url = "https://github.com/SigmaHQ/sigma.git"
    temp_dir = "data/sigma_temp"
    target_dir = "data/sigma_rules"

    # 1. Clone kho dữ liệu khổng lồ từ GitHub
    print("[*] Đang tải kho SigmaHQ từ GitHub (sẽ mất khoảng vài chục giây)...")
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    
    # Dùng git clone tải về thư mục tạm
    subprocess.run(["git", "clone", "--depth", "1", repo_url, temp_dir])

    # 2. Lọc và copy các luật thực chiến quan trọng nhất
    # (Tớ bỏ qua Windows để tránh làm nặng máy, tập trung vào Web, Linux và Network cho đồ án của cậu)
    categories = ["web", "linux", "network"] 
    print(f"\n[*] Đang trích xuất các luật từ các danh mục: {categories}...")
    
    count = 0
    for category in categories:
        source_path = os.path.join(temp_dir, "rules", category)
        if os.path.exists(source_path):
            for root, _, files in os.walk(source_path):
                for file in files:
                    if file.endswith((".yml", ".yaml")):
                        src_file = os.path.join(root, file)
                        dst_file = os.path.join(target_dir, file)
                        # Đảm bảo không ghi đè 3 cái luật "chim mồi" cực xịn cậu tự viết
                        if not os.path.exists(dst_file):
                            shutil.copy2(src_file, dst_file)
                            count += 1
    
    # 3. Dọn dẹp chiến trường
    shutil.rmtree(temp_dir)
    print(f"\n[+] BÙM! Đã thu hoạch thành công {count} Sigma Rules chuẩn quốc tế vào thư mục '{target_dir}'!")

if __name__ == "__main__":
    sync_sigma_rules()