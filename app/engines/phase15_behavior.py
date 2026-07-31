def analyze_behavior(engine_results):
    """
    Phase 15: Behavioral Analysis Engine
    Classifies attack objectives (Credential Phishing, BEC, CEO Fraud, Invoice Fraud, Malware Delivery, etc.).
    """
    behavior_class = "Benign / Normal Email"
    confidence = 85
    
    brand_risk = engine_results.get("brand_risk_score", 0)
    content_risk = engine_results.get("content_risk_score", 0)
    att_risk = engine_results.get("attachment_risk_score", 0)
    url_risk = engine_results.get("url_risk_score", 0)
    sender_risk = engine_results.get("sender_risk_score", 0)
    
    if att_risk >= 60:
        behavior_class = "Malware Delivery / Ransomware"
        confidence = 90
    elif brand_risk >= 50 or url_risk >= 40:
        behavior_class = "Credential Phishing / Account Takeover"
        confidence = 90
    elif sender_risk >= 50 and content_risk >= 30:
        behavior_class = "Business Email Compromise (BEC) / Executive Impersonation"
        confidence = 85
    elif content_risk >= 35:
        behavior_class = "Suspicious Financial / Invoice Scam"
        confidence = 80
    elif url_risk > 15 or content_risk > 15:
        behavior_class = "Suspicious Phishing Attempt"
        confidence = 75
        
    return {
        "behavior_classification": behavior_class,
        "behavior_confidence": confidence
    }
