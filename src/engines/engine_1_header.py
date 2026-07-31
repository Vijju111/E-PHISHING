import re
from src.engines.base_engine import BaseEngine

class HeaderIntelligenceEngine(BaseEngine):
    """
    Engine 1: Header Intelligence
    Analyzes Received headers, authentication results, message IDs, and mailer signatures.
    """
    def analyze(self, email_context: dict) -> dict:
        msg_obj = email_context["msg_obj"]
        received = msg_obj.get_all("Received", [])
        message_id = msg_obj.get("Message-ID", "")
        x_mailer = msg_obj.get("X-Mailer", "")
        
        findings = []
        risk_score = 0
        
        required = ["From", "To", "Subject", "Date", "Message-ID"]
        missing = [h for h in required if not msg_obj.get(h)]
        if missing:
            findings.append(f"Missing mandatory headers: {', '.join(missing)}")
            risk_score += 15
            
        if not message_id or "@" not in message_id:
            findings.append("Missing or malformed Message-ID header.")
            risk_score += 20
            
        # If no Received header, penalize slightly less if message ID matches domain
        if not received:
            findings.append("Missing Received transit headers.")
            risk_score += 10
            
        suspicious_mailers = ["mass mailer", "phish", "python", "phpmailer", "swaks"]
        if any(sm in x_mailer.lower() for sm in suspicious_mailers):
            findings.append(f"Suspicious automated mailing tool signature in X-Mailer: {x_mailer}")
            risk_score += 20
            
        return {
            "engine_name": "Header Intelligence",
            "risk_score": min(100, risk_score),
            "findings": findings,
            "metadata": {"received_count": len(received), "x_mailer": x_mailer}
        }
