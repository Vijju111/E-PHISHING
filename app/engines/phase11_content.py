def analyze_content(parsed_data):
    """
    Phase 11: Content Intelligence Engine
    Detects urgency, financial fraud, invoice scam, credential harvesting, password reset, MFA requests, etc.
    """
    plain_text = parsed_data.get("plain_text_body", "")
    html_body = parsed_data.get("html_body", "")
    subject = parsed_data["metadata"].get("subject", "")
    
    content_blob = (subject + " " + plain_text + " " + html_body).lower()
    
    findings = []
    content_risk = 0
    
    urgency_keywords = ['urgent', 'immediate action', 'expire', 'suspended', 'account closure', 'verify now', 'action required', 'asap']
    financial_keywords = ['invoice', 'payment', 'wire transfer', 'payroll', 'bank details', 'overdue', 'tax refund', 'gift card']
    credential_keywords = ['password reset', 'sign in', 'login', 'credentials', 'mfa', 'multifactor', 'security alert']
    
    urgency_matches = [kw for kw in urgency_keywords if kw in content_blob]
    financial_matches = [kw for kw in financial_keywords if kw in content_blob]
    credential_matches = [kw for kw in credential_keywords if kw in content_blob]
    
    if urgency_matches:
        findings.append(f"High urgency / pressure tactics detected: {', '.join(urgency_matches)}")
        content_risk += 25
        
    if financial_matches:
        findings.append(f"Financial fraud / BEC / Invoice keywords detected: {', '.join(financial_matches)}")
        content_risk += 35
        
    if credential_matches:
        findings.append(f"Credential harvesting / account security keywords detected: {', '.join(credential_matches)}")
        content_risk += 35
        
    content_risk = min(100, content_risk)
    
    return {
        "urgency_matches": urgency_matches,
        "financial_matches": financial_matches,
        "credential_matches": credential_matches,
        "findings": findings,
        "content_risk_score": content_risk
    }
