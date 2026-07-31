from bs4 import BeautifulSoup
from src.engines.base_engine import BaseEngine

class HTMLRenderingEngine(BaseEngine):
    """
    Engine 7: HTML & Rendering
    """
    def analyze(self, email_context: dict) -> dict:
        html = email_context.get("html_body", "")
        if not html:
            return {"engine_name": "HTML Rendering", "risk_score": 0, "findings": [], "metadata": {}}
            
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        iframes = soup.find_all('iframe')
        hidden = soup.find_all(style=lambda v: v and 'display:none' in v.lower())
        
        findings = []
        risk = 0
        if forms:
            findings.append(f"HTML Form elements detected ({len(forms)} form(s)).")
            risk += 35
        if iframes:
            findings.append(f"IFrame elements detected ({len(iframes)} iframe(s)).")
            risk += 25
        if hidden:
            findings.append("Hidden HTML elements detected.")
            risk += 20
            
        return {
            "engine_name": "HTML Rendering",
            "risk_score": min(100, risk),
            "findings": findings,
            "metadata": {"forms": len(forms), "iframes": len(iframes)}
        }
