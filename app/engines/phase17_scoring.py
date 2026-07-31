def calculate_dynamic_risk(all_scores):
    """
    Phase 17: Dynamic Risk Scoring Engine
    Calculates overall phishing risk (0-100), confidence score (0-100), and severity level with adaptive weighting.
    """
    weights = {
        "header": 0.05,
        "auth": 0.10,
        "domain": 0.10,
        "sender": 0.15,
        "url": 0.20,
        "attachment": 0.20,
        "html": 0.05,
        "visual": 0.05,
        "content": 0.05,
        "relationship": 0.02,
        "brand": 0.10,
        "threat_intel": 0.20
    }
    
    total_weight = 0
    weighted_sum = 0
    
    for key, weight in weights.items():
        score = all_scores.get(key, 0)
        weighted_sum += score * weight
        total_weight += weight
        
    base_risk = weighted_sum / total_weight if total_weight > 0 else 0
    
    # Adaptive boosting: if threat intel, URL, or attachment risk is extremely high, boost overall risk score
    max_engine_score = max(all_scores.values()) if all_scores else 0
    
    risk_score = int(round(max(base_risk, max_engine_score * 0.85)))
    risk_score = max(0, min(100, risk_score))
    
    # Determine severity
    if risk_score <= 20:
        severity = "Safe"
        verdict = "LEGITIMATE"
    elif risk_score <= 40:
        severity = "Low Risk"
        verdict = "SUSPICIOUS - LOW CONFIDENCE"
    elif risk_score <= 60:
        severity = "Suspicious"
        verdict = "SUSPICIOUS - MODERATE RISK"
    elif risk_score <= 80:
        severity = "High Risk"
        verdict = "MALICIOUS / PHISHING"
    else:
        severity = "Critical Phishing"
        verdict = "HIGH-CONFIDENCE CRITICAL THREAT"
        
    confidence_score = 92 if risk_score > 50 or risk_score < 15 else 70
    
    return {
        "risk_score": risk_score,
        "confidence_score": confidence_score,
        "severity": severity,
        "verdict": verdict
    }
