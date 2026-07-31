def analyze_authentication(msg_obj):
    """
    Phase 4: Email Authentication Engine
    Evaluates SPF, DKIM, DMARC, and ARC authentication results from headers.
    """
    auth_results_list = msg_obj.get_all("Authentication-Results", [])
    auth_text = " ".join(auth_results_list).lower()
    
    spf_status = "none"
    dkim_status = "none"
    dmarc_status = "none"
    arc_status = "none"
    
    findings = []
    
    if "spf=pass" in auth_text:
        spf_status = "pass"
    elif "spf=fail" in auth_text:
        spf_status = "fail"
        findings.append("SPF verification FAILED.")
    elif "spf=softfail" in auth_text:
        spf_status = "softfail"
        findings.append("SPF verification SOFTFAIL.")
        
    if "dkim=pass" in auth_text:
        dkim_status = "pass"
    elif "dkim=fail" in auth_text:
        dkim_status = "fail"
        findings.append("DKIM verification FAILED.")
        
    if "dmarc=pass" in auth_text:
        dmarc_status = "pass"
    elif "dmarc=fail" in auth_text:
        dmarc_status = "fail"
        findings.append("DMARC verification FAILED (Policy violation / alignment failure).")
        
    if "arc=pass" in auth_text:
        arc_status = "pass"
        
    # Calculate confidence score based on auth results
    # If DMARC or SPF/DKIM fail, risk increases
    auth_risk = 0
    if spf_status == "fail":
        auth_risk += 35
    elif spf_status == "softfail":
        auth_risk += 15
    if dkim_status == "fail":
        auth_risk += 35
    if dmarc_status == "fail":
        auth_risk += 40
        
    if not auth_results_list:
        findings.append("No Authentication-Results headers present.")
        auth_risk += 20
        confidence_score = 50
    else:
        confidence_score = 90
        
    auth_risk = min(100, auth_risk)
    
    return {
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "arc_status": arc_status,
        "findings": findings,
        "auth_risk_score": auth_risk,
        "confidence_score": confidence_score
    }
