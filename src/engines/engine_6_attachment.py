import math
from src.engines.base_engine import BaseEngine
from src.utils.security import calculate_hashes
from src.integrations.threat_intel_client import ThreatIntelClient

class AttachmentIntelligenceEngine(BaseEngine):
    """
    Advanced True File & Attachment Intelligence Engine.
    Inspects file magic bytes, computes Shannon entropy, detects double extensions,
    dangerous executables, macros, scripts, and queries VirusTotal live API.
    """
    def analyze(self, email_context: dict) -> dict:
        attachments = email_context.get("attachments", [])
        analyzed = []
        max_att_risk = 0
        
        dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.vbs', '.js', '.wsf', '.hta', '.iso', '.img', '.lnk', '.chm', '.dll', '.msi', '.one', '.jar', '.ps1']
        archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz']
        office_macro_extensions = ['.docm', '.xlsm', '.pptm', '.dotm']
        
        for att in attachments:
            filename = att["filename"].lower()
            payload = att["payload"]
            file_size = att["file_size"]
            
            hashes = calculate_hashes(payload)
            sha256 = hashes["sha256"]
            
            ext = ""
            if "." in filename:
                ext = "." + filename.split('.')[-1]
                
            # 1. Magic Byte Verification (True File Type Inspection)
            magic_bytes = payload[:16]
            detected_type = "Unknown / Binary"
            if magic_bytes.startswith(b'%PDF'):
                detected_type = "PDF Document"
            elif magic_bytes.startswith(b'PK\x03\x04'):
                detected_type = "ZIP / OpenXML Archive"
            elif magic_bytes.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
                detected_type = "OLE Compound File (MS Office / MSI)"
            elif magic_bytes.startswith(b'MZ'):
                detected_type = "Windows Executable (PE / EXE / DLL)"
            elif magic_bytes.startswith(b'\x7fELF'):
                detected_type = "Linux Executable (ELF)"
            elif magic_bytes.startswith(b'\x89PNG'):
                detected_type = "PNG Image"
            elif magic_bytes.startswith(b'\xff\xd8\xff'):
                detected_type = "JPEG Image"
                
            # 2. Shannon Entropy Calculation for Packed / Encrypted Malware Detection
            entropy = 0
            if file_size > 0:
                prob = [payload.count(b) / file_size for b in set(payload)]
                entropy = -sum(p * math.log2(p) for p in prob)
                
            risk = 0
            findings = []
            
            if ext in dangerous_extensions:
                findings.append(f"Dangerous executable/script attachment extension detected: {filename} (Type: {detected_type})")
                risk += 75
            elif ext in office_macro_extensions:
                findings.append(f"Macro-enabled Office document attachment detected: {filename}")
                risk += 50
            elif ext in archive_extensions:
                findings.append(f"Compressed archive container attached: {filename} (Requires unpacking inspection)")
                risk += 20
                
            # Check for binary mismatch (e.g., file named .pdf but magic bytes are MZ executable)
            if ext == '.pdf' and magic_bytes.startswith(b'MZ'):
                findings.append(f"CRITICAL: Extension masquerading detected! File claims to be PDF but magic bytes indicate Windows Executable (EXE): {filename}")
                risk += 95
            elif ext in ['.jpg', '.png'] and magic_bytes.startswith(b'MZ'):
                findings.append(f"CRITICAL: Extension masquerading detected! Executable binary disguised as image: {filename}")
                risk += 95
                
            # Check for double extension evasion (e.g., invoice.pdf.exe)
            parts = filename.split('.')
            if len(parts) > 2 and parts[-2] in ['pdf', 'txt', 'jpg', 'png', 'doc', 'xls', 'docx', 'xlsx']:
                findings.append(f"Double extension evasion technique detected: {filename}")
                risk += 60
                
            # High entropy check (Packed or encrypted payload)
            if entropy > 7.2 and file_size > 1024:
                findings.append(f"High file entropy ({round(entropy, 2)}): Indicates packed, compressed, or encrypted binary payload in {filename}")
                risk += 40
                
            # 3. Live VirusTotal Hash Query
            vt_res = ThreatIntelClient.query_virustotal_hash(sha256)
            if vt_res.get("status") == "success":
                malicious_count = vt_res.get("malicious", 0)
                if malicious_count > 0:
                    findings.append(f"VirusTotal Threat Intel: Attachment confirmed malicious by {malicious_count} security vendors (Hash: {sha256[:16]}...)")
                    risk += 95
            elif vt_res.get("status") == "unconfigured":
                findings.append(f"VirusTotal API Note: Hash {sha256[:12]}... ready for live scanning (Add VT_API_KEY in .env to activate).")
                
            max_att_risk = max(max_att_risk, risk)
            analyzed.append({
                "filename": filename,
                "extension": ext,
                "detected_type": detected_type,
                "file_size": file_size,
                "sha256": sha256,
                "entropy": round(entropy, 2),
                "risk_score": min(100, risk),
                "findings": findings
            })
            
        all_att_findings = [f for a in analyzed for f in a["findings"]]
        
        return {
            "engine_name": "Attachment Intelligence",
            "risk_score": min(100, max_att_risk),
            "findings": all_att_findings,
            "metadata": {
                "analyzed_attachments": analyzed,
                "total_attachments": len(analyzed)
            }
        }
