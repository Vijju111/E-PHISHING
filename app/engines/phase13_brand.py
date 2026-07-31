import re

def analyze_brand_impersonation(parsed_data, urls):
    """
    Phase 13: Brand Impersonation Engine
    Compares sender, subject, body, and domains against known brands (Microsoft, Google, Apple, Amazon, PayPal, Banks).
    """
    brands = {
        "Microsoft": ["microsoft", "office365", "outlook", "onedrive", "azure"],
        "Google": ["google", "gmail", "gsuite", "drive.google"],
        "Apple": ["apple", "icloud", "itunes", "appleid"],
        "Amazon": ["amazon", "aws", "prime"],
        "PayPal": ["paypal", "venmo"],
        "Banking / Financial": ["chase", "wells fargo", "bank of america", "citibank", "paypal", "hsbc"]
    }
    
    content_blob = (parsed_data["metadata"]["subject"] + " " + parsed_data["plain_text_body"] + " " + parsed_data["metadata"]["from"]).lower()
    sender_domain = parsed_data["metadata"]["from"].lower()
    
    findings = []
    brand_risk = 0
    detected_brand = None
    
    for brand_name, keywords in brands.items():
        if any(kw in content_blob for kw in keywords):
            # Check if sending domain matches brand or is legitimate
            # If sending domain does not contain brand keywords, potential brand spoofing
            if not any(kw in sender_domain for kw in keywords):
                detected_brand = brand_name
                findings.append(f"Brand Impersonation Detected: Email references '{brand_name}' but sending domain ({sender_domain}) does not belong to {brand_name}.")
                brand_risk += 50
                break
                
    brand_risk = min(100, brand_risk)
    
    return {
        "detected_brand": detected_brand,
        "findings": findings,
        "brand_risk_score": brand_risk
    }
