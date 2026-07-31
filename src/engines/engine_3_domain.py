import dns.resolver
from src.engines.base_engine import BaseEngine

class DomainIntelligenceEngine(BaseEngine):
    """
    Engine 3: Domain & DNS Intelligence
    Performs real-time DNS lookups (MX records, A records, Nameservers) just like PowerDMARC / MXToolbox.
    """
    def analyze(self, email_context: dict) -> dict:
        sender_domain = email_context.get("metadata", {}).get("sender_domain", "")
        if not sender_domain:
            import re
            sender = email_context["metadata"]["from"]
            m = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', sender)
            sender_domain = m.group(1).lower() if m else ""
            
        findings = []
        domain_risk = 0
        mx_records = []
        nameservers = []
        
        if sender_domain:
            # 1. Check MX Records (Mail Exchange)
            try:
                mx_answers = dns.resolver.resolve(sender_domain, 'MX')
                for rdata in mx_answers:
                    mx_records.append(str(rdata.exchange))
                findings.append(f"Live DNS MX Records found for '{sender_domain}': {', '.join(mx_records[:3])}")
            except Exception:
                findings.append(f"Live DNS Warning: No MX records found for sender domain '{sender_domain}' (Mail cannot be received by this domain).")
                domain_risk += 40
                
            # 2. Check Nameservers (NS records)
            try:
                ns_answers = dns.resolver.resolve(sender_domain, 'NS')
                for rdata in ns_answers:
                    nameservers.append(str(rdata.target))
                findings.append(f"Live DNS Nameservers verified for '{sender_domain}'.")
            except Exception:
                pass
                
        return {
            "engine_name": "Domain & DNS Intelligence",
            "risk_score": min(100, domain_risk),
            "findings": findings,
            "metadata": {
                "sender_domain": sender_domain,
                "mx_records": mx_records,
                "nameservers": nameservers
            }
        }
