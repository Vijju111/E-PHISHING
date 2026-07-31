def analyze_conversation(parsed_data):
    """
    Phase 12: Conversation & Relationship Engine
    Analyzes Thread-ID, In-Reply-To, References to detect thread hijacking.
    """
    metadata = parsed_data["metadata"]
    in_reply_to = metadata.get("in_reply_to", "")
    references = metadata.get("references", "")
    subject = metadata.get("subject", "")
    
    findings = []
    relationship_risk = 0
    
    # Check thread hijacking indicator: Subject starts with "Re: " but no In-Reply-To or References header
    if subject.lower().startswith("re:") and not in_reply_to and not references:
        findings.append("Thread Hijacking Indicator: Subject indicates reply ('Re:'), but In-Reply-To and References headers are missing.")
        relationship_risk += 40
        
    relationship_risk = min(100, relationship_risk)
    
    return {
        "in_reply_to": in_reply_to,
        "references": references,
        "findings": findings,
        "relationship_risk_score": relationship_risk
    }
