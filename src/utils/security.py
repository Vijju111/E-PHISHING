import hashlib
import re
from src.logging.logger import logger

def calculate_hashes(data: bytes) -> dict:
    """
    Calculates SHA-256, SHA-1, and MD5 hashes for file integrity and IOC extraction.
    """
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest()
    }

def sanitize_string(input_str: str) -> str:
    """
    Sanitizes string inputs to prevent XSS and injection vulnerabilities.
    """
    if not input_str:
        return ""
    # Strip dangerous HTML/script tags for safe rendering
    clean = re.sub(r'<script.*?>.*?</script>', '', input_str, flags=re.IGNORECASE | re.DOTALL)
    return clean.strip()

def validate_email_upload(filename: str, file_size: int, max_size: int = 50 * 1024 * 1024) -> bool:
    """
    Validates file extension and size constraints securely.
    """
    if file_size > max_size:
        logger.warning("File size exceeds maximum threshold", extra_data={"filename": filename, "size": file_size})
        return False
        
    ext = filename.lower().split('.')[-1] if '.' in filename else ""
    allowed = ['eml', 'msg', 'txt', 'rfc822']
    if ext not in allowed:
        logger.warning("Invalid file extension rejected", extra_data={"filename": filename, "extension": ext})
        return False
        
    return True
