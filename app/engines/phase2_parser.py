import re
from email.header import decode_header
from bs4 import BeautifulSoup

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

def parse_email_artifacts(msg_obj):
    """
    Phase 2: Email Parsing Engine
    Extracts General Metadata, MIME Structure, Bodies, and Attachments.
    """
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

    mime_structure = {
        "content_type": msg_obj.get_content_type(),
        "is_multipart": msg_obj.is_multipart(),
        "parts": []
    }

    plain_text_body = ""
    html_body = ""
    amp_body = ""
    attachments = []

    if msg_obj.is_multipart():
        for part in msg_obj.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()
            
            mime_structure["parts"].append({
                "content_type": ct,
                "content_disposition": cd,
                "filename": filename,
                "size": len(part.get_payload(decode=True) or b"")
            })

            if filename or 'attachment' in cd:
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": decode_mime_header(filename or "unnamed_attachment"),
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
                        elif "amp" in ct:
                            amp_body += decoded_text + "\n"
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

    # If only HTML exists, extract text representation
    if not plain_text_body and html_body:
        soup = BeautifulSoup(html_body, 'html.parser')
        plain_text_body = soup.get_text()

    return {
        "metadata": metadata,
        "mime_structure": mime_structure,
        "plain_text_body": plain_text_body,
        "html_body": html_body,
        "amp_body": amp_body,
        "attachments": attachments
    }
