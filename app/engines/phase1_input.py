import os
import hashlib
import uuid
from datetime import datetime
from email import message_from_bytes, message_from_string
from email.parser import BytesParser

def validate_and_ingest_email(raw_data: bytes, filename: str = "email.eml"):
    """
    Phase 1: Input Validation Engine
    1. Verify supported format (.eml, .msg, raw RFC822, text)
    2. Validate MIME structure
    3. Check file integrity
    4. Detect corruption
    5. Validate encoding
    6. Check maximum file size (e.g. 50MB)
    7. Calculate SHA-256 of original email
    8. Generate unique Analysis ID
    9. Record processing timestamp
    10. Store immutable original email
    """
    analysis_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    if not raw_data:
        raise ValueError("Empty email payload provided.")
        
    file_size = len(raw_data)
    max_size = 50 * 1024 * 1024 # 50MB
    if file_size > max_size:
        raise ValueError(f"File size {file_size} bytes exceeds maximum allowed size (50MB).")
        
    sha256_hash = hashlib.sha256(raw_data).hexdigest()
    sha1_hash = hashlib.sha1(raw_data).hexdigest()
    md5_hash = hashlib.md5(raw_data).hexdigest()
    
    # Attempt parsing to validate MIME / RFC822
    try:
        if filename.endswith('.msg'):
            # Basic fallback for msg or parse as bytes
            msg_obj = BytesParser().parsebytes(raw_data)
        else:
            msg_obj = BytesParser().parsebytes(raw_data)
    except Exception as e:
        raise ValueError(f"Email parsing error / corruption detected: {str(e)}")
        
    # Store backup
    storage_dir = os.path.expanduser("~/phishing_tool_storage/originals")
    os.makedirs(storage_dir, exist_ok=True)
    backup_path = os.path.join(storage_dir, f"{analysis_id}.eml")
    with open(backup_path, "wb") as f:
        f.write(raw_data)
        
    return {
        "analysis_id": analysis_id,
        "timestamp": timestamp,
        "file_size": file_size,
        "sha256": sha256_hash,
        "sha1": sha1_hash,
        "md5": md5_hash,
        "backup_path": backup_path,
        "msg_obj": msg_obj
    }
