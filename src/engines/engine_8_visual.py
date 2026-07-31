from src.engines.base_engine import BaseEngine

class OCRVisualAnalysisEngine(BaseEngine):
    """
    Engine 8: OCR & Visual Analysis
    """
    def analyze(self, email_context: dict) -> dict:
        text = email_context.get("plain_text_body", "").strip()
        html = email_context.get("html_body", "").strip()
        attachments = email_context.get("attachments", [])
        
        findings = []
        risk = 0
        if len(text) < 30 and (len(attachments) > 0 or '<img' in html.lower()):
            findings.append("Image-only or low-text email structure detected.")
            risk += 35
            
        content = (text + " " + html).lower()
        if any(kw in content for kw in ['qr code', 'scan me', 'authenticator qr']):
            findings.append("QR Phishing (Quishing) reference detected.")
            risk += 45
            
        return {
            "engine_name": "OCR & Visual Analysis",
            "risk_score": min(100, risk),
            "findings": findings,
            "metadata": {}
        }
