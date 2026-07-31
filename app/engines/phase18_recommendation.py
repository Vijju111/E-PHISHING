def generate_recommendations(scoring_res, behavior_res, correlation_res):
    """
    Phase 18: Recommendation Engine
    Generates analyst recommendations, mitigation steps, MITRE ATT&CK mapping, and suggested response.
    """
    risk_score = scoring_res["risk_score"]
    severity = scoring_res["severity"]
    verdict = scoring_res["verdict"]
    behavior = behavior_res["behavior_classification"]
    
    mitre_mapping = []
    if "Credential" in behavior:
        mitre_mapping.append("T1566.002 - Phishing: Phishing Link")
        mitre_mapping.append("T1598 - Information Gathering for Phishing")
    elif "Malware" in behavior:
        mitre_mapping.append("T1566.001 - Phishing: Attachment")
        mitre_mapping.append("T1204 - User Execution")
    elif "BEC" in behavior or "Impersonation" in behavior:
        mitre_mapping.append("T1566.002 - Phishing")
        mitre_mapping.append("T1036 - Masquerading")
    else:
        mitre_mapping.append("T1566 - Phishing")
        
    recommended_actions = []
    if risk_score > 60:
        recommended_actions.append("Quarantine email immediately across mailboxes.")
        recommended_actions.append("Block sender domain / email address on email gateway.")
        recommended_actions.append("Revoke active user sessions if credentials were submitted.")
        recommended_actions.append("Initiate targeted threat hunting for clicked URLs or downloaded attachments.")
    elif risk_score > 30:
        recommended_actions.append("Review email manually via SOC analyst queue.")
        recommended_actions.append("Warn user before interacting with embedded links.")
    else:
        recommended_actions.append("No action required. Email appears safe.")
        
    return {
        "verdict": verdict,
        "severity": severity,
        "mitre_mapping": mitre_mapping,
        "recommended_actions": recommended_actions,
        "evidence_summary": f"Analyzed {correlation_res['total_indicators_count']} indicators with classification '{behavior}'."
    }
