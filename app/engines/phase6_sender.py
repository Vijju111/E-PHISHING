import re

def analyze_sender_trust(parsed_data):
    """
    Phase 6: Sender Trust Engine
    Compares Display Name, From Address, Reply-To, Return-Path to detect spoofing & impersonation.
    """
    metadata = parsed_data["metadata"]
    from_header = metadata["from"]
    reply_to = metadata["reply_to"]
    return_path = metadata["return_path"]
    
    findings = []
    sender_risk = 0
    
    # Extract email from From header (e.g. "John Doe <john@example.com>")
    email_match = re.search(r'<([^>]+)>', from_header)
    from_email = email_match.group(1).lower() if email_match else from_header.strip().lower()
    
    display_name_match = re.match(r'^([^<]+)', from_header)
    display_name = display_name_match.group(1).strip('"\' ') if display_name_match else ""
    
    # Check Reply-To mismatch
    if reply_to:
        reply_email_match = re.search(r'<([^>]+)>', reply_to)
        reply_email = (reply_email_match.group(1) if reply_email_match else reply_to).strip().lower()
        if reply_email and from_email and reply_email != from_email:
            findings.append(f"Reply-To address ({reply_email}) differs from From address ({from_email}). Common BEC indicator.")
            sender_risk += 35
            
    # Check Return-Path mismatch
    if return_path:
        rp_clean = return_path.strip('<>').lower()
        if from_email and rp_clean and rp_clean != "mailer-daemon" and rp_clean != "postmaster":
            # Extract domain
            from_domain = from_email.split('@')[-1] if '@' in from_email else ""
            rp_domain = rp_clean.split('@')[-1] if '@' in rp_clean else ""
            if from_domain and rp_domain and from_domain != rp_domain:
                findings.append(f"Return-Path domain ({rp_domain}) does not align with From domain ({from_domain}).")
                sender_risk += 20
                
    # Check Display Name impersonation heuristics (e.g. CEO / Executive name in display name with external domain)
    executives = ["ceo", "cfo", "director", "president", "hr", "human resources", "support", "admin", "security", "billing"]
    if display_name and any(exec_title in display_name.lower() for exec_title in executives):
        # Check if sending domain is free email or suspicious
        free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com']
        from_domain = from_email.split('@')[-1] if '@' in from_email else ""
        if from_domain in free_providers:
            findings.append(f"High-risk Display Name Impersonation: Display name contains executive/department title '{display_name}' while sending from public free provider '{from_domain}'.")
            sender_risk += 50
            
    sender_risk = min(100, sender_risk)
    trust_score = max(0, 100 - sender_risk)
    
    return {
        "from_email": from_email,
        "display_name": display_name,
        "reply_to": reply_to,
        "return_path": return_path,
        "findings": findings,
        "sender_risk_score": sender_risk,
        "sender_trust_score": trust_score
    }
