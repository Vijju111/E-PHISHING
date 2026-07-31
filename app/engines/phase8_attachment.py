import hashlib

def analyze_attachments(attachments):
    """
    Phase 8: Attachment Intelligence Engine
    Analyzes file extension, MIME type, hashes, and detects malicious or suspicious file types (executables, macros, ISO, LNK, HTA, OneNote, etc.).
    """
    findings = []
    attachment_risk = 0
    analyzed = []
    
    dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.vbs', '.js', '.wsf', '.hta', '.iso', '.img', '.lnk', '.chm', '.dll', '.msi', '.one', '.jar']
    archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz']
    office_extensions = ['.docm', '.xlsm', '.pptm']
    
    for att in attachments:
        filename = att["filename"].lower()
        file_size = att["file_size"]
        mime_type = att["mime_type"]
        payload = att["payload"]
        
        sha256 = hashlib.sha256(payload).hexdigest()
        md5 = hashlib.md5(payload).hexdigest()
        
        ext = ""
        if "." in filename:
            ext = "." + filename.split('.')[-1]
            
        att_risk = 0
        att_findings = []
        
        if ext in dangerous_extensions:
            att_findings.append(f"Dangerous attachment extension detected: {ext}")
            att_risk += 60
        elif ext in office_extensions:
            att_findings.append(f"Macro-enabled Office document attachment detected: {ext}")
            att_risk += 45
        elif ext in archive_extensions:
            att_findings.append(f"Compressed archive attachment detected: {ext} (potential container for malware).")
            att_risk += 20
            
        # Check for double extensions (e.g. invoice.pdf.exe)
        parts = filename.split('.')
        if len(parts) > 2 and parts[-2] in ['pdf', 'txt', 'jpg', 'png', 'doc', 'xls']:
            att_findings.append(f"Double extension evasion technique detected: {filename}")
            att_risk += 50
            
        attachment_risk = max(attachment_risk, att_risk)
        analyzed.append({
            "filename": att["filename"],
            "extension": ext,
            "file_size": file_size,
            "mime_type": mime_type,
            "sha256": sha256,
            "md5": md5,
            "findings": att_findings,
            "risk_score": att_risk
        })
        
    return {
        "analyzed_attachments": analyzed,
        "attachment_risk_score": min(100, attachment_risk)
    }
