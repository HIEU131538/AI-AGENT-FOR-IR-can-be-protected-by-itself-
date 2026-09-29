import threading
# Lock toàn cục bảo vệ MỌI thao tác ChromaDB trong process
# Đảm bảo tại mọi thời điểm chỉ có 1 thread truy cập PersistentClient
chroma_lock = threading.Lock()
