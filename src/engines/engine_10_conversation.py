from src.engines.base_engine import BaseEngine

class ConversationAnalysisEngine(BaseEngine):
    """
    Engine 10: Conversation & Relationship
    """
    def analyze(self, email_context: dict) -> dict:
        metadata = email_context["metadata"]
        in_reply_to = metadata.get("in_reply_to", "")
        references = metadata.get("references", "")
        subject = metadata.get("subject", "")
        
        findings = []
        risk = 0
        if subject.lower().startswith("re:") and not in_reply_to and not references:
            findings.append("Thread Hijacking Indicator: Subject indicates reply ('Re:') without reply headers.")
            risk += 40
            
        return {
            "engine_name": "Conversation Analysis",
            "risk_score": min(100, risk),
            "findings": findings,
            "metadata": {}
        }
