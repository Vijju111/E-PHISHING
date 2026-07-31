import re
from urllib.parse import urlparse

def analyze_domains(parsed_data, urls):
    """
    Phase 5: Domain Intelligence Engine
    Analyzes sending domains and extracted URL domains for age, suspicious TLDs, disposable status, etc.
    """
    sender = parsed_data["metadata"]["from"]
    # Extract domain from sender email
    domain_match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', sender)
    sender_domain = domain_match.group(1).lower() if domain_match else ""
    
    findings = []
    domain_risk = 0
    
    suspicious_tlds = ['.xyz', '.top', '.club', '.gq', '.ml', '.cf', '.tk', '.cn', '.ru', '.work', '.click', '.loan', '.buzz', '.su']
    disposable_domains = ['mailinator.com', 'tempmail.com', '10minutemail.com', 'guerrillamail.com', 'trashmail.com', 'yopmail.com']
    
    if sender_domain:
        if any(sender_domain.endswith(tld) for tld in suspicious_tlds):
            findings.append(f"Sender domain uses high-risk suspicious TLD: {sender_domain}")
            domain_risk += 35
            
        if sender_domain in disposable_domains:
            findings.append(f"Sender domain is a known disposable/temporary email provider: {sender_domain}")
            domain_risk += 50
            
    # Check URL domains
    for u in urls:
        parsed_url = urlparse(u)
        netloc = parsed_url.netloc.lower()
        if any(netloc.endswith(tld) for tld in suspicious_tlds):
            findings.append(f"Embedded URL uses suspicious TLD: {netloc}")
            domain_risk += 25
            
    domain_risk = min(100, domain_risk)
    trust_score = max(0, 100 - domain_risk)
    
    return {
        "sender_domain": sender_domain,
        "findings": findings,
        "domain_risk_score": domain_risk,
        "domain_trust_score": trust_score
    }
