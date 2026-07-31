from src.engines.base_engine import BaseEngine

class BrandImpersonationEngine(BaseEngine):
    """
    Engine 11: Brand Impersonation
    """
    def analyze(self, email_context: dict) -> dict:
        brands = {
            "Microsoft": ["microsoft", "office365", "outlook", "onedrive"],
            "Google": ["google", "gmail", "gsuite"],
            "Apple": ["apple", "icloud"],
            "Amazon": ["amazon", "aws"],
            "PayPal": ["paypal", "venmo"]
        }
        
        blob = (email_context["metadata"]["subject"] + " " + email_context["plain_text_body"] + " " + email_context["metadata"]["from"]).lower()
        sender_domain = email_context["metadata"]["from"].lower()
        
        findings = []
        risk = 0
        detected = None
        for brand, kws in brands.items():
            if any(kw in blob for kw in kws):
                if not any(kw in sender_domain for kw in kws):
                    detected = brand
                    findings.append(f"Brand Impersonation: Email references '{brand}' while sending domain ({sender_domain}) does not belong to {brand}.")
                    risk += 50
                    break
                    
        return {
            "engine_name": "Brand Impersonation",
            "risk_score": min(100, risk),
            "findings": findings,
            "metadata": {"detected_brand": detected}
        }
