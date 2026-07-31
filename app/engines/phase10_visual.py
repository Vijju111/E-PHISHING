def analyze_visual(parsed_data, attachments):
    """
    Phase 10: OCR & Visual Analysis Engine
    Analyzes embedded images, logos, QR codes, and image-only phishing indicators.
    """
    findings = []
    visual_risk = 0
    
    # Check for image-only email (e.g. body has images/attachments but no text)
    plain_text = parsed_data.get("plain_text_body", "").strip()
    html_body = parsed_data.get("html_body", "").strip()
    
    if len(plain_text) < 30 and (len(attachments) > 0 or '<img' in html_body.lower()):
        findings.append("Image-only or low-text email structure detected (common evasion technique against keyword filters).")
        visual_risk += 35
        
    # Check for QR codes in text/html or attachments
    qr_keywords = ['qr code', 'scan me', 'scan the qr', 'authenticator qr']
    content_blob = (plain_text + " " + html_body).lower()
    if any(kw in content_blob for kw in qr_keywords):
        findings.append("QR Phishing (Quishing) reference detected in email content.")
        visual_risk += 45
        
    visual_risk = min(100, visual_risk)
    
    return {
        "findings": findings,
        "visual_risk_score": visual_risk
    }
