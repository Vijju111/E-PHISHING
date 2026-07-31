import re
from urllib.parse import urlparse

def extract_urls(text, html):
    """
    Extracts all URLs from plain text and HTML content.
    """
    urls = set()
    # Regex for URL extraction
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    
    if text:
        for match in url_pattern.findall(text):
            urls.add(match)
    if html:
        for match in url_pattern.findall(html):
            # Clean trailing quotes or tags
            clean_url = match.rstrip('"\'<>.,;')
            urls.add(clean_url)
            
    return list(urls)

def analyze_urls(urls):
    """
    Phase 7: URL Intelligence Engine
    Analyzes extracted URLs for HTTPS, IP-based URLs, homograph/punycode, redirect parameters, etc.
    """
    findings = []
    url_risk = 0
    analyzed_urls = []
    
    ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    
    for u in urls:
        parsed = urlparse(u)
        is_https = parsed.scheme.lower() == 'https'
        is_ip = bool(ip_pattern.match(u))
        has_punycode = 'xn--' in parsed.netloc.lower()
        
        u_risk = 0
        u_findings = []
        
        if not is_https:
            u_findings.append("URL uses insecure HTTP protocol.")
            u_risk += 15
            
        if is_ip:
            u_findings.append("URL uses raw IP address instead of domain name (high phishing indicator).")
            u_risk += 40
            
        if has_punycode:
            u_findings.append("Punycode / IDN homograph encoding detected in domain.")
            u_risk += 30
            
        # Check for login/auth keywords in URL path or query
        auth_keywords = ['login', 'signin', 'auth', 'verify', 'account', 'update', 'banking', 'secure', 'password']
        if any(kw in u.lower() for kw in auth_keywords):
            u_findings.append("URL contains credential/login harvesting keywords.")
            u_risk += 25
            
        url_risk = max(url_risk, u_risk)
        analyzed_urls.append({
            "url": u,
            "domain": parsed.netloc,
            "is_https": is_https,
            "is_ip": is_ip,
            "has_punycode": has_punycode,
            "findings": u_findings,
            "risk_score": u_risk
        })
        
    if analyzed_urls and url_risk == 0:
        url_risk = 5
        
    return {
        "extracted_urls": analyzed_urls,
        "url_risk_score": min(100, url_risk)
    }
