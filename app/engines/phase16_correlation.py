def correlate_evidence(all_engine_results):
    """
    Phase 16: Evidence Correlation Engine
    Collects evidence from all engines and generates unified evidence graph, supporting vs contradictory evidence.
    """
    supporting_evidence = []
    contradictory_evidence = []
    
    for engine_name, res in all_engine_results.items():
        if isinstance(res, dict) and "findings" in res:
            for f in res["findings"]:
                supporting_evidence.append(f"[{engine_name.upper()}] {f}")
                
    # Check for contradictions (e.g. SPF pass but domain risk high)
    if all_engine_results.get("auth", {}).get("spf_status") == "pass" and all_engine_results.get("domain", {}).get("domain_risk_score", 0) > 50:
        contradictory_evidence.append("Authentication (SPF Pass) contradicts high domain risk/suspicious TLD indicators.")
        
    return {
        "supporting_evidence": supporting_evidence,
        "contradictory_evidence": contradictory_evidence,
        "total_indicators_count": len(supporting_evidence)
    }
