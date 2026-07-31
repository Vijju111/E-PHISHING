from src.engines.base_engine import BaseEngine

class EvidenceCorrelationEngine(BaseEngine):
    """
    Engine 14: Evidence Correlation
    """
    def analyze(self, all_engine_results: dict) -> dict:
        supporting = []
        for name, res in all_engine_results.items():
            if isinstance(res, dict) and "findings" in res:
                for f in res["findings"]:
                    supporting.append(f"[{name}] {f}")
                    
        return {
            "engine_name": "Evidence Correlation",
            "risk_score": 0,
            "findings": supporting,
            "metadata": {"total_indicators": len(supporting)}
        }
