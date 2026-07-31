import re
import math
from urllib.parse import urlparse, unquote
from src.engines.base_engine import BaseEngine
from src.integrations.threat_intel_client import ThreatIntelClient

class URLIntelligenceEngine(BaseEngine):
    """
    Advanced True URL Intelligence Engine.
    Performs deep extraction from HTML hrefs and body text, computes URL entropy,
    detects punycode/homographs, IP URLs, credential harvesting paths, and live feed matches.
    """
    def analyze(self, email_context: dict) -> dict:
        text = email_context.get("plain_text_body", "")
        html = email_context.get("html_body", "")
        
        urls = set()
        
        # 1. Deep extraction from HTML href attributes
        if html:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                if href and not href.startswith('#') and not href.startswith('mailto:'):
                    urls.add(unquote(href))
                    
        # 2. General regex extraction from body text and raw HTML
        pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        for m in pattern.findall(text + " " + html):
            cleaned = m.rstrip('"\'<>.,;')
            if cleaned:
                urls.add(unquote(cleaned))
                
        analyzed_urls = []
        max_url_risk = 0
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        
        for u in urls:
            parsed = urlparse(u if '://' in u else f'http://{u}')
            netloc = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            
            is_https = parsed.scheme.lower() == 'https'
            is_ip = bool(ip_pattern.match(u))
            has_punycode = 'xn--' in netloc
            
            # Shannon Entropy calculation for domain randomness (DGA / Phishing detection)
            prob = [netloc.count(c) / len(netloc) for c in set(netloc)]
            entropy = -sum(p * math.log2(p) for p in prob) if len(netloc) > 0 else 0
            
            u_risk = 0
            u_findings = []
            
            if not is_https:
                u_findings.append(f"URL uses insecure HTTP protocol: {u}")
                u_risk += 15
                
            if is_ip:
                u_findings.append(f"URL uses raw IP address instead of domain: {u}")
                u_risk += 45
                
            if has_punycode:
                u_findings.append(f"Punycode / IDN homograph encoding detected in domain: {netloc}")
                u_risk += 35
                
            if entropy > 4.2:
                u_findings.append(f"High entropy (randomness) in domain name (potential DGA/phishing): {netloc}")
                u_risk += 25
                
            auth_keywords = ['login', 'signin', 'auth', 'verify', 'account', 'update', 'banking', 'secure', 'password', 'wallet', 'portal']
            if any(kw in path or kw in query for kw in auth_keywords):
                u_findings.append(f"Credential / login harvesting keywords in URL path: {u}")
                u_risk += 30
                
            # Live OpenPhish feed verification
            feed_res = ThreatIntelClient.query_openphish_feed(u)
            if feed_res.get("status") == "success" and feed_res.get("matched") is True:
                u_findings.append(f"CRITICAL: URL confirmed active malicious phishing site in OpenPhish live feed: {u}")
                u_risk += 95
                
            max_url_risk = max(max_url_risk, u_risk)
            analyzed_urls.append({
                "url": u,
                "domain": netloc,
                "is_https": is_https,
                "is_ip": is_ip,
                "entropy": round(entropy, 2),
                "risk_score": min(100, u_risk),
                "findings": u_findings
            })
            
        all_findings = [f for a in analyzed_urls for f in a["findings"]]
        
        return {
            "engine_name": "URL Intelligence",
            "risk_score": min(100, max_url_risk if max_url_risk > 0 else (5 if analyzed_urls else 0)),
            "findings": all_findings,
            "metadata": {
                "extracted_urls": analyzed_urls,
                "total_urls_analyzed": len(analyzed_urls)
            }
        }
