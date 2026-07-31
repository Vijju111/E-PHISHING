from src.engines.base_engine import BaseEngine
from src.utils.security import calculate_hashes

class AttachmentIntelligenceEngine(BaseEngine):
    """
    Engine 6: Attachment Intelligence
    """
    def analyze(self, email_context: dict) -> dict:
        attachments = email_context.get("attachments", [])
        analyzed = []
        att_risk = 0
        dangerous = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.vbs', '.js', '.hta', '.iso', '.img', '.lnk', '.one']
        
        for att in attachments:
            filename = att["filename"].lower()
            payload = att["payload"]
            hashes = calculate_hashes(payload)
            ext = "." + filename.split('.')[-1] if '.' in filename else ""
            
            risk = 0
            findings = []
            if ext in dangerous:
                findings.append(f"Dangerous attachment extension: {ext}")
                risk += 60
                
            parts = filename.split('.')
            if len(parts) > 2 and parts[-2] in ['pdf', 'txt', 'jpg', 'png', 'doc']:
                findings.append(f"Double extension evasion technique: {filename}")
                risk += 50
                
            att_risk = max(att_risk, risk)
            analyzed.append({
                "filename": att["filename"],
                "extension": ext,
                "file_size": att["file_size"],
                "sha256": hashes["sha256"],
                "risk_score": risk,
                "findings": findings
            })
            
        return {
            "engine_name": "Attachment Intelligence",
            "risk_score": min(100, att_risk),
            "findings": [f for a in analyzed for f in a["findings"]],
            "metadata": {"analyzed_attachments": analyzed}
        }
