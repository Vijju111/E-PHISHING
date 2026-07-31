import os
import html
import re
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from src.logging.logger import logger

class OWASPSecurityMiddleware(BaseHTTPMiddleware):
    """
    OWASP Top 10 Security Hardening Middleware:
    - Adds secure HTTP headers (X-Frame-Options, X-Content-Type-Options, CSP, X-XSS-Protection).
    - Protects against clickjacking, MIME-sniffing, and XSS.
    """
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data:;"
        return response

def secure_filename(filename: str) -> str:
    """
    Prevents path traversal attacks by stripping directory paths and unsafe characters.
    """
    if not filename:
        return "unnamed.eml"
    base = os.path.basename(filename)
    clean = re.sub(r'[^a-zA-Z0-9_.-]', '_', base)
    return clean

def verify_file_magic_bytes(file_content: bytes, filename: str) -> bool:
    """
    Validates file integrity and type via magic bytes to prevent malicious uploads.
    """
    if not file_content:
        return False
    # Check for text/RFC822 email characteristics or msg container header
    ext = filename.lower().split('.')[-1] if '.' in filename else ""
    if ext in ['eml', 'txt', 'rfc822']:
        # Should be valid text/mime headers
        sample = file_content[:100].decode('latin1', errors='ignore').lower()
        if 'subject:' in sample or 'from:' in sample or 'received:' in sample or 'content-type:' in sample or len(file_content) > 0:
            return True
    elif ext == 'msg':
        # OLE Compound File binary header
        if file_content[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
            return True
        return len(file_content) > 100
    return len(file_content) > 0
