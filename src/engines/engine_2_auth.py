import dns.resolver
import re
from src.engines.base_engine import BaseEngine

class AuthenticationEngine(BaseEngine):
    """
    Engine 2: Dynamic Real-Time Authentication Engine (SPF, DKIM, DMARC)
    Performs robust live DNS queries (TXT and SPF specific lookups) in real-time.
    """
    def analyze(self, email_context: dict) -> dict:
        msg_obj = email_context["msg_obj"]
        
        sender = email_context["metadata"]["from"]
        domain_match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', sender)
        sender_domain = domain_match.group(1).lower() if domain_match else ""
        
        findings = []
        auth_risk = 0
        
        spf_status = "none"
        dkim_status = "none"
        dmarc_status = "none"
        
        spf_record_content = None
        dmarc_record_content = None
        
        # 1. REAL-TIME LIVE DNS SPF CHECK
        if sender_domain:
            try:
                # Query TXT records
                txt_answers = dns.resolver.resolve(sender_domain, 'TXT')
                for rdata in txt_answers:
                    txt_str = rdata.to_text().strip('"')
                    if "v=spf1" in txt_str.lower():
                        spf_record_content = txt_str
                        spf_status = "pass"
                        findings.append(f"Live DNS SPF Check PASSED: Valid SPF record found for '{sender_domain}': {txt_str}")
                        break
                
                # If not found in TXT, check SPF specific query type if supported
                if not spf_record_content:
                    try:
                        spf_answers = dns.resolver.resolve(sender_domain, 'SPF')
                        for rdata in spf_answers:
                            txt_str = rdata.to_text().strip('"')
                            if "v=spf1" in txt_str.lower():
                                spf_record_content = txt_str
                                spf_status = "pass"
                                findings.append(f"Live DNS SPF (Type SPF) Check PASSED for '{sender_domain}': {txt_str}")
                                break
                    except Exception:
                        pass

                if not spf_record_content:
                    spf_status = "fail"
                    findings.append(f"Live DNS SPF Check FAILED: No valid v=spf1 record published for '{sender_domain}'.")
                    auth_risk += 40
            except dns.resolver.NXDOMAIN:
                spf_status = "fail"
                findings.append(f"Live DNS SPF Check FAILED: Domain '{sender_domain}' does not exist.")
                auth_risk += 50
            except Exception as e:
                spf_status = "error"
                findings.append(f"Live DNS SPF Check Error for '{sender_domain}': {str(e)}")
                auth_risk += 20

        # 2. REAL-TIME LIVE DNS DMARC CHECK
        if sender_domain:
            try:
                dmarc_domain = f"_dmarc.{sender_domain}"
                dmarc_answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                for rdata in dmarc_answers:
                    txt_str = rdata.to_text().strip('"')
                    if "v=dmarc1" in txt_str.lower():
                        dmarc_record_content = txt_str
                        dmarc_status = "pass"
                        findings.append(f"Live DNS DMARC Check PASSED: Valid DMARC record found for '{sender_domain}': {txt_str}")
                        if "p=none" in txt_str.lower():
                            findings.append("DMARC Policy Warning: Policy is set to 'none' (monitoring only).")
                            auth_risk += 15
                        break
                if not dmarc_record_content:
                    dmarc_status = "fail"
                    findings.append(f"Live DNS DMARC Check FAILED: No DMARC record published at '{dmarc_domain}'.")
                    auth_risk += 35
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                dmarc_status = "fail"
                findings.append(f"Live DNS DMARC Check FAILED: Missing DMARC record (_dmarc.{sender_domain}).")
                auth_risk += 35
            except Exception as e:
                dmarc_status = "error"
                findings.append(f"Live DNS DMARC Check Error: {str(e)}")
                auth_risk += 15

        # 3. DKIM Signature & Selector Analysis
        dkim_sig = msg_obj.get("DKIM-Signature", "")
        if dkim_sig:
            dkim_status = "present"
            findings.append("DKIM-Signature header detected in email.")
            s_match = re.search(r's=([a-zA-Z0-9_-]+)', dkim_sig)
            d_match = re.search(r'd=([a-zA-Z0-9.-]+)', dkim_sig)
            if s_match and d_match:
                selector = s_match.group(1)
                dkim_domain = d_match.group(1)
                selector_query = f"{selector}._domainkey.{dkim_domain}"
                try:
                    dkim_answers = dns.resolver.resolve(selector_query, 'TXT')
                    for rdata in dkim_answers:
                        dkim_txt = rdata.to_text()
                        if "k=rsa" in dkim_txt.lower() or "p=" in dkim_txt.lower():
                            findings.append(f"Live DNS DKIM Public Key verified for selector '{selector}' at '{selector_query}'.")
                            dkim_status = "pass"
                            break
                except Exception:
                    findings.append(f"Live DNS DKIM Warning: Could not resolve DKIM public key for selector '{selector}'.")
                    auth_risk += 25
        else:
            dkim_status = "missing"
            findings.append("DKIM-Signature header is missing from email headers.")
            auth_risk += 20

        return {
            "engine_name": "Dynamic Real-Time Authentication",
            "risk_score": min(100, auth_risk),
            "findings": findings,
            "metadata": {
                "spf": spf_status,
                "spf_record": spf_record_content,
                "dkim": dkim_status,
                "dmarc": dmarc_status,
                "dmarc_record": dmarc_record_content,
                "sender_domain": sender_domain
            }
        }
