from src.engines.base_engine import BaseEngine

class RecommendationEngine(BaseEngine):
    """
    Engine 16: Recommendation Engine
    """
    def analyze(self, risk_score: int, severity: str, verdict: str) -> dict:
        mitre = ["T1566.002 - Phishing: Phishing Link", "T1598 - Information Gathering"]
        actions = []
        if risk_score > 60:
            actions = [
                "Quarantine email immediately across all mailboxes.",
                "Block sender domain on email gateway.",
                "Revoke active user sessions if credentials were submitted.",
                "Initiate threat hunting for clicked URLs or attachments."
            ]
        elif risk_score > 30:
            actions = ["Review email manually via SOC analyst queue.", "Warn user before interacting with embedded links."]
        else:
            actions = ["No action required. Email appears safe."]
            
        return {
            "engine_name": "Recommendation",
            "risk_score": risk_score,
            "findings": [],
            "metadata": {
                "mitre_mapping": mitre,
                "recommended_actions": actions,
                "evidence_summary": f"Evaluated threat indicators with verdict '{verdict}'."
            }
        }
