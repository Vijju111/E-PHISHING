import re
from urllib.parse import urlparse
from src.engines.base_engine import BaseEngine

class URLIntelligenceEngine(BaseEngine):
    """
    Engine 5: URL Intelligence
    """
    def analyze(self, email_context: dict) -> dict:
        text = email_context.get("plain_text_body", "")
        html = email_context.get("html_body", "")
        
        urls = set()
        pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        for m in pattern.findall(text + " " + html):
            urls.add(m.rstrip('"\'<>.,;'))
            
        analyzed = []
        url_risk = 0
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        
        for u in urls:
            parsed = urlparse(u)
            is_https = parsed.scheme.lower() == 'https'
            is_ip = bool(ip_pattern.match(u))
            has_punycode = 'xn--' in parsed.netloc.lower()
            
            u_risk = 0
            u_findings = []
            if not is_https:
                u_findings.append("URL uses insecure HTTP.")
                u_risk += 15
            if is_ip:
                u_findings.append("URL uses raw IP address.")
                u_risk += 40
            if has_punycode:
                u_findings.append("Punycode / IDN homograph encoding detected.")
                u_risk += 30
                
            auth_keywords = ['login', 'signin', 'auth', 'verify', 'account', 'secure', 'password']
            if any(kw in u.lower() for kw in auth_keywords):
                u_findings.append("URL contains credential/login keywords.")
                u_risk += 25
                
            url_risk = max(url_risk, u_risk)
            analyzed.append({"url": u, "domain": parsed.netloc, "risk_score": u_risk, "findings": u_findings})
            
        return {
            "engine_name": "URL Intelligence",
            "risk_score": min(100, url_risk if url_risk > 0 else 5),
            "findings": [f for a in analyzed for f in a["findings"]],
            "metadata": {"extracted_urls": analyzed}
        }
