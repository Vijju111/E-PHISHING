import os
import uuid
from datetime import datetime
from email.parser import BytesParser
from bs4 import BeautifulSoup
from email.header import decode_header
from src.utils.security import calculate_hashes

def decode_mime_header(header_value):
    if not header_value:
        return ""
    decoded_parts = decode_header(header_value)
    result = []
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            try:
                result.append(part.decode(encoding or 'utf-8', errors='ignore'))
            except Exception:
                result.append(part.decode('latin1', errors='ignore'))
        else:
            result.append(str(part))
    return "".join(result)

def parse_and_validate_email(raw_data: bytes, filename: str = "email.eml"):
    """
    Phase 1 & 2: Input Validation & Email Parsing Engine
    """
    analysis_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    if not raw_data:
        raise ValueError("Empty email payload provided.")
        
    hashes = calculate_hashes(raw_data)
    
    try:
        msg_obj = BytesParser().parsebytes(raw_data)
    except Exception as e:
        raise ValueError(f"Email parsing error / corruption detected: {str(e)}")
        
    metadata = {
        "subject": decode_mime_header(msg_obj.get("Subject", "")),
        "date": decode_mime_header(msg_obj.get("Date", "")),
        "from": decode_mime_header(msg_obj.get("From", "")),
        "sender": decode_mime_header(msg_obj.get("Sender", "")),
        "reply_to": decode_mime_header(msg_obj.get("Reply-To", "")),
        "return_path": decode_mime_header(msg_obj.get("Return-Path", "")),
        "to": decode_mime_header(msg_obj.get("To", "")),
        "cc": decode_mime_header(msg_obj.get("CC", "")),
        "bcc": decode_mime_header(msg_obj.get("BCC", "")),
        "message_id": decode_mime_header(msg_obj.get("Message-ID", "")),
        "in_reply_to": decode_mime_header(msg_obj.get("In-Reply-To", "")),
        "references": decode_mime_header(msg_obj.get("References", ""))
    }

    plain_text_body = ""
    html_body = ""
    attachments = []

    if msg_obj.is_multipart():
        for part in msg_obj.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()
            if filename or 'attachment' in cd:
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": decode_mime_header(filename or "unnamed"),
                    "file_size": len(payload),
                    "mime_type": ct,
                    "payload": payload
                })
            else:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        decoded_text = payload.decode(charset, errors='ignore')
                        if ct == "text/plain":
                            plain_text_body += decoded_text + "\n"
                        elif ct == "text/html":
                            html_body += decoded_text + "\n"
                except Exception:
                    pass
    else:
        ct = msg_obj.get_content_type()
        payload = msg_obj.get_payload(decode=True) or msg_obj.get_payload()
        if isinstance(payload, bytes):
            try:
                charset = msg_obj.get_content_charset() or 'utf-8'
                decoded_text = payload.decode(charset, errors='ignore')
            except Exception:
                decoded_text = payload.decode('latin1', errors='ignore')
        else:
            decoded_text = str(payload or "")
        if ct == "text/html":
            html_body = decoded_text
        else:
            plain_text_body = decoded_text

    if not plain_text_body and html_body:
        soup = BeautifulSoup(html_body, 'html.parser')
        plain_text_body = soup.get_text()

    return {
        "analysis_id": analysis_id,
        "timestamp": timestamp,
        "file_size": len(raw_data),
        "sha256": hashes["sha256"],
        "sha1": hashes["sha1"],
        "md5": hashes["md5"],
        "msg_obj": msg_obj,
        "metadata": metadata,
        "plain_text_body": plain_text_body,
        "html_body": html_body,
        "attachments": attachments
    }
