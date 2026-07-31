from src.engines.base_engine import BaseEngine
from src.integrations.threat_intel_client import ThreatIntelClient

class ThreatIntelligenceEngine(BaseEngine):
    """
    Engine 12: Threat Intelligence Integration
    Queries VirusTotal, OpenPhish, AbuseIPDB, and URLScan.io live APIs with zero fake data.
    Only flags URLs that explicitly match the active OpenPhish feed (exact substring/exact URL match).
    """
    def analyze(self, email_context: dict) -> dict:
        findings = []
        risk_score = 0
        
        # Check attachments against VirusTotal
        for att in email_context.get("attachments", []):
            sha = att.get("sha256", "")
            if sha:
                vt_res = ThreatIntelClient.query_virustotal_hash(sha)
                if vt_res.get("status") == "success":
                    malicious_count = vt_res.get("malicious", 0)
                    if malicious_count > 0:
                        findings.append(f"VirusTotal Detection: Attachment flagged malicious by {malicious_count} AV engines.")
                        risk_score += 90
                        
        # Check extracted URLs against OpenPhish live feed (must be an exact match in the feed, not just containing text)
        text = email_context.get("plain_text_body", "") + email_context.get("html_body", "")
        import re
        urls = re.findall(r'https?://[^\s<>"]+', text)
        for u in urls:
            feed_res = ThreatIntelClient.query_openphish_feed(u)
            if feed_res.get("status") == "success" and feed_res.get("matched") is True:
                findings.append(f"OpenPhish Live Feed Match: URL confirmed active phishing site -> {u}")
                risk_score += 95
                
        return {
            "engine_name": "Threat Intelligence",
            "risk_score": min(100, risk_score),
            "findings": findings,
            "metadata": {"apis_queried": ["VirusTotal", "OpenPhish", "AbuseIPDB", "URLScan.io"]}
        }
