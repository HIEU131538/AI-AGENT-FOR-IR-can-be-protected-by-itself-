import re
import ipaddress
import logging

# Dùng module-level logger theo chuẩn chuyên nghiệp
logger = logging.getLogger(__name__)

class OutputSanitizer:
    """
    Lớp khiên bảo vệ (Output Sanitizer) chống lại lỗ hổng AI-Assisted RCE (LLM02).
    Đã nâng cấp trả về Audit Event (Dict) để Dashboard thống kê thay vì chỉ True/False.
    """

    # Danh sách đen các ký tự dùng trong Command Injection trên Linux
    DANGEROUS_CHARS = re.compile(r'[;&|`$<>\{\}\[\]\n\r\\]')

    # Danh sách trắng các hành động được phép thực thi
    ALLOWED_ACTIONS = {
        "ignore", "monitor", "alert", "alert_operator", 
        "throttle", "block_ip", "isolate_container"
    }

    @classmethod
    def contains_command_injection(cls, payload: str) -> bool:
        """Kiểm tra ký tự nguy hiểm (; & | ` $ ...)."""
        if cls.DANGEROUS_CHARS.search(payload):
            logger.critical(f"[SKEPTICISM - SANITIZER] Phát hiện payload chứa ký tự thực thi mã độc: {payload}")
            return True
        return False

    @classmethod
    def validate_action(cls, action: str) -> dict:
        """Whitelist 0: Kiểm tra Action hợp lệ."""
        clean_action = action.strip().lower()
        if clean_action not in cls.ALLOWED_ACTIONS:
            logger.critical(f"[SANITIZER] CẢNH BÁO: Hành động ảo giác/Không hợp lệ: '{action}'")
            return {"valid": False, "reason": "invalid_action", "value": clean_action}
        return {"valid": True, "reason": "ok", "value": clean_action}

    @classmethod
    def validate_ip(cls, ip_str: str) -> dict:
        """
        Whitelist 1: Xác thực nghiêm ngặt IP (Ép cứng IPv4 theo góp ý).
        """
        clean_ip = ip_str.strip()
        
        if cls.contains_command_injection(clean_ip):
            return {"valid": False, "reason": "command_injection", "value": clean_ip}
            
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            # Nâng cấp: Ép IPv4-only để tương thích iptables
            if not isinstance(ip_obj, ipaddress.IPv4Address):
                logger.warning(f"[SANITIZER] Hỗ trợ IPv4 only. IP bị từ chối: {clean_ip}")
                return {"valid": False, "reason": "not_ipv4", "value": clean_ip}
            
            return {"valid": True, "reason": "ok", "value": clean_ip}
        except ValueError:
            logger.warning(f"[SANITIZER] Định dạng IP không hợp lệ: {clean_ip}")
            return {"valid": False, "reason": "invalid_format", "value": clean_ip}

    @classmethod
    def validate_container_id(cls, container_id: str) -> dict:
        """Whitelist 2: Xác thực nghiêm ngặt Container ID."""
        clean_id = container_id.strip()
        
        if cls.contains_command_injection(clean_id):
            return {"valid": False, "reason": "command_injection", "value": clean_id}
            
        if not re.match(r'^[a-fA-F0-9]{12,64}$', clean_id):
            logger.warning(f"[SANITIZER] Định dạng Container ID không hợp lệ: {clean_id}")
            return {"valid": False, "reason": "invalid_format", "value": clean_id}
            
        return {"valid": True, "reason": "ok", "value": clean_id}

    @classmethod
    def validate_hostname(cls, hostname: str) -> dict:
        """
        Whitelist 3: Dọn đường sẵn cho tương lai (Ví dụ: block_domain).
        """
        clean_host = hostname.strip()
        if cls.contains_command_injection(clean_host):
            return {"valid": False, "reason": "command_injection", "value": clean_host}
            
        if len(clean_host) > 255 or not re.match(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$', clean_host):
             return {"valid": False, "reason": "invalid_hostname", "value": clean_host}
             
        return {"valid": True, "reason": "ok", "value": clean_host}

# Kiểm thử nhanh
if __name__ == "__main__":
    print(OutputSanitizer.validate_ip("192.168.1.50"))
    print(OutputSanitizer.validate_ip("192.168.1.50; rm -rf /"))
    print(OutputSanitizer.validate_ip("2001:db8::1"))