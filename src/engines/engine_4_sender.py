import re
from src.engines.base_engine import BaseEngine

class SenderTrustEngine(BaseEngine):
    """
    Engine 4: Sender Trust
    """
    def analyze(self, email_context: dict) -> dict:
        metadata = email_context["metadata"]
        from_header = metadata["from"]
        reply_to = metadata["reply_to"]
        
        findings = []
        sender_risk = 0
        
        email_match = re.search(r'<([^>]+)>', from_header)
        from_email = email_match.group(1).lower() if email_match else from_header.strip().lower()
        
        if reply_to:
            reply_match = re.search(r'<([^>]+)>', reply_to)
            reply_email = (reply_match.group(1) if reply_match else reply_to).strip().lower()
            if reply_email and from_email and reply_email != from_email:
                findings.append(f"Reply-To address ({reply_email}) differs from From address ({from_email}).")
                sender_risk += 35
                
        executives = ["ceo", "cfo", "director", "president", "hr", "support", "admin", "security"]
        display_name_match = re.match(r'^([^<]+)', from_header)
        display_name = display_name_match.group(1).strip('"\' ') if display_name_match else ""
        
        if display_name and any(ex in display_name.lower() for ex in executives):
            free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
            domain = from_email.split('@')[-1] if '@' in from_email else ""
            if domain in free_providers:
                findings.append(f"Display Name Impersonation: Executive title '{display_name}' sent from free email provider '{domain}'.")
                sender_risk += 50
                
        return {
            "engine_name": "Sender Trust",
            "risk_score": min(100, sender_risk),
            "findings": findings,
            "metadata": {"from_email": from_email, "display_name": display_name}
        }
