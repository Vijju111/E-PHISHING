import re
from src.engines.base_engine import BaseEngine

class ContentIntelligenceEngine(BaseEngine):
    """
    Engine 9: Content Intelligence
    Analyzes content for urgency, financial transactions, and credential harvesting.
    Distinguishes legitimate transactional receipts (e.g., gov.in, bank notifications with receipt numbers) from scams.
    """
    def analyze(self, email_context: dict) -> dict:
        text = email_context.get("plain_text_body", "")
        html = email_context.get("html_body", "")
        subject = email_context["metadata"].get("subject", "")
        sender = email_context["metadata"].get("from", "").lower()
        blob = (subject + " " + text + " " + html).lower()
        
        findings = []
        risk = 0
        
        # Check if email is a legitimate receipt / notification from a recognized gov/bank/service domain
        is_legit_context = False
        gov_domains = ['.gov.in', '.gov', 'rrbapply.gov.in', 'nic.in', 'sbi.co.in', 'hdfcbank.com']
        if any(dom in sender for dom in gov_domains) and any(kw in blob for kw in ['receipt', 'successful', 'transaction id', 'confirmation']):
            is_legit_context = True
            
        urgency_keywords = ['urgent', 'immediate action', 'suspend', 'expire', 'verify now', 'action required', 'within 24 hours']
        financial_keywords = ['wire transfer', 'payroll', 'gift card', 'tax refund']
        credential_keywords = ['password reset', 'sign in now', 'verify credentials', 'mfa reset']
        
        urgency = [kw for kw in urgency_keywords if kw in blob]
        financial = [kw for kw in financial_keywords if kw in blob]
        credential = [kw for kw in credential_keywords if kw in blob]
        
        if urgency and not is_legit_context:
            findings.append(f"High urgency / pressure tactics detected: {', '.join(urgency)}")
            risk += 25
        if financial and not is_legit_context:
            findings.append(f"Unsolicited financial transfer keywords detected: {', '.join(financial)}")
            risk += 35
        if credential:
            findings.append(f"Credential harvesting keywords detected: {', '.join(credential)}")
            risk += 35
            
        return {
            "engine_name": "Content Intelligence",
            "risk_score": min(100, risk),
            "findings": findings,
            "metadata": {"urgency": urgency, "financial": financial, "is_legit_context": is_legit_context}
        }
