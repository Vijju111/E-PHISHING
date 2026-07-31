def analyze_threat_intel(parsed_data, urls, attachments):
    """
    Phase 14: Threat Intelligence Engine
    Queries internal IOC database and threat intel feeds.
    """
    findings = []
    ti_risk = 0
    ioc_matches = []
    
    # Built-in sample malicious known IOCs for demonstration
    known_malicious_domains = ["phishing-secure-login.com", "update-bank-account.net", "verify-mfa-portal.xyz", "office365-login-alert.com"]
    known_malicious_hashes = ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    
    for u in urls:
        for md in known_malicious_domains:
            if md in u.lower():
                findings.append(f"IOC Match: URL matches known malicious threat intel domain ({md}).")
                ti_risk += 80
                ioc_matches.append({"type": "url", "indicator": u, "source": "Threat Intel Feed"})
                
    for att in attachments:
        sha = att.get("sha256", "")
        if sha in known_malicious_hashes:
            findings.append(f"IOC Match: Attachment SHA-256 matches known malware hash.")
            ti_risk += 90
            ioc_matches.append({"type": "hash", "indicator": sha, "source": "Malware DB"})
            
    ti_risk = min(100, ti_risk)
    
    return {
        "ioc_matches": ioc_matches,
        "findings": findings,
        "threat_intel_risk_score": ti_risk
    }
