import logging
import uuid
from datetime import datetime, timezone
from tools.sanitizer import OutputSanitizer

logger = logging.getLogger(__name__)

class ActionTools:
    """
    Kho vũ khí (Action Tool Layer) của AI Agent.
    Mô phỏng thực thi (Simulated Execution) để phục vụ mục đích nghiên cứu học thuật.
    """

    @staticmethod
    def _generate_metadata() -> dict:
        """Sinh ID, Thời gian và Nguồn gốc cho mỗi sự kiện (Audit Trail)."""
        return {
            "action_id": f"ACT-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "soc_agent" # Nâng cấp 2: Phân biệt AI với Con người
        }

    @staticmethod
    def block_ip(ip_address: str) -> dict:
        logger.info(f"Trạm Responder yêu cầu CHẶN IP: {ip_address}")
        
        # Khởi tạo siêu dữ liệu ngay từ đầu để dùng cho cả Success và Failed
        result = ActionTools._generate_metadata()
        result["action"] = "block_ip"
        
        audit_event = OutputSanitizer.validate_ip(ip_address)
        if not audit_event["valid"]:
            logger.error(f"[BLOCK HỦY BỎ] Lý do: {audit_event['reason']} | Payload: {audit_event.get('value', ip_address)}")
            # Nâng cấp 1: Failed vẫn có ID
            result.update({"status": "failed", "reason": audit_event["reason"], "target": audit_event.get('value', ip_address)})
            return result

        clean_ip = audit_event["value"]
        logger.warning(f"[ACTION SUCCESS] Đã chặn IP {clean_ip} trên Firewall.")
        
        result.update({"status": "success", "target": clean_ip})
        return result

    @staticmethod
    def isolate_container(container_id: str) -> dict:
        logger.info(f"Trạm Responder yêu cầu CÔ LẬP CONTAINER: {container_id}")
        
        result = ActionTools._generate_metadata()
        result["action"] = "isolate_container"
        
        audit_event = OutputSanitizer.validate_container_id(container_id)
        if not audit_event["valid"]:
            logger.error(f"[ISOLATE HỦY BỎ] Lý do: {audit_event['reason']} | Payload: {audit_event.get('value', container_id)}")
            result.update({"status": "failed", "reason": audit_event["reason"], "target": audit_event.get('value', container_id)})
            return result

        clean_id = audit_event["value"]
        logger.warning(f"[ACTION SUCCESS] Đã ngắt kết nối mạng của Container {clean_id}.")
        
        result.update({"status": "success", "target": clean_id})
        return result

    @staticmethod
    def alert_operator(reason: str) -> dict:
        logger.critical(f"[ESCALATION] BÁO ĐỘNG ĐỎ TỚI SOC ANALYST: {reason}")
        
        result = ActionTools._generate_metadata()
        result.update({
            "status": "success", 
            "action": "alert_operator", 
            "message": reason
        })
        return result

    @staticmethod
    def throttle(ip_address: str) -> dict:
        logger.info(f"Trạm Responder yêu cầu THROTTLE IP: {ip_address}")
        
        result = ActionTools._generate_metadata()
        result["action"] = "throttle"
        
        audit_event = OutputSanitizer.validate_ip(ip_address)
        if not audit_event["valid"]:
            logger.error(f"[THROTTLE HỦY BỎ] Lý do: {audit_event['reason']} | Payload: {audit_event.get('value', ip_address)}")
            result.update({"status": "failed", "reason": audit_event["reason"], "target": audit_event.get('value', ip_address)})
            return result

        clean_ip = audit_event["value"]
        logger.warning(f"[ACTION SUCCESS] Đã bóp băng thông đối với IP {clean_ip}.")
        
        result.update({"status": "success", "target": clean_ip})
        return result