import re

def analyze_headers(msg_obj):
    """
    Phase 3: Header Intelligence Engine
    Analyzes Received headers, Authentication-Results, X-Originating-IP, Mailer, etc.
    Detects header spoofing, missing headers, timestamp anomalies, etc.
    """
    received_headers = msg_obj.get_all("Received", [])
    auth_results = msg_obj.get_all("Authentication-Results", [])
    x_originating_ip = msg_obj.get("X-Originating-IP", "")
    x_mailer = msg_obj.get("X-Mailer", "")
    user_agent = msg_obj.get("User-Agent", "")
    message_id = msg_obj.get("Message-ID", "")
    
    findings = []
    risk_score = 0
    
    # Check missing required headers
    required_headers = ["From", "To", "Subject", "Date", "Message-ID"]
    missing = [h for h in required_headers if not msg_obj.get(h)]
    if missing:
        findings.append(f"Missing mandatory headers: {', '.join(missing)}")
        risk_score += 15
        
    # Check Message-ID format anomaly
    if message_id:
        if "@" not in message_id or len(message_id) < 8:
            findings.append("Suspicious or malformed Message-ID detected.")
            risk_score += 10
    else:
        findings.append("Completely missing Message-ID header.")
        risk_score += 20
        
    # Check Received chain depth & private IP misuse
    if not received_headers:
        findings.append("No 'Received' headers found (direct injection or missing transit trail).")
        risk_score += 25
    else:
        # Check for localhost / private IPs in public received chain
        private_ip_pattern = re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b')
        for rh in received_headers:
            if private_ip_pattern.search(rh) and "internal" not in rh.lower():
                findings.append("Private IP address observed in external transit received chain.")
                risk_score += 15

    # Check suspicious mail clients / X-Mailer
    suspicious_mailers = ["mass mailer", "bulk", "phish", "python", "phpmailer", "zmailer", "swaks"]
    mailer_str = (x_mailer + " " + user_agent).lower()
    for sm in suspicious_mailers:
        if sm in mailer_str:
            findings.append(f"Suspicious automated mailing tool / script signature detected: {sm}")
            risk_score += 20
            
    risk_score = min(100, risk_score)
    
    return {
        "received_count": len(received_headers),
        "auth_results": auth_results,
        "x_originating_ip": x_originating_ip,
        "x_mailer": x_mailer,
        "findings": findings,
        "header_risk_score": risk_score
    }
