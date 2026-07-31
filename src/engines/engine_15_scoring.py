from src.engines.base_engine import BaseEngine

class DynamicRiskScoringEngine(BaseEngine):
    """
    Engine 15: Dynamic Risk Scoring
    """
    def analyze(self, all_scores: dict) -> dict:
        max_score = max(all_scores.values()) if all_scores else 0
        risk_score = min(100, max_score)
        
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
            
        return {
            "engine_name": "Dynamic Risk Scoring",
            "risk_score": risk_score,
            "findings": [],
            "metadata": {"severity": severity, "verdict": verdict, "confidence_score": 90}
        }
