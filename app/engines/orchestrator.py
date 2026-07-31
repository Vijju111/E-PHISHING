from app.engines.phase1_input import validate_and_ingest_email
from app.engines.phase2_parser import parse_email_artifacts
from app.engines.phase3_headers import analyze_headers
from app.engines.phase4_auth import analyze_authentication
from app.engines.phase5_domain import analyze_domains
from app.engines.phase6_sender import analyze_sender_trust
from app.engines.phase7_url import extract_urls, analyze_urls
from app.engines.phase8_attachment import analyze_attachments
from app.engines.phase9_html import analyze_html
from app.engines.phase10_visual import analyze_visual
from app.engines.phase11_content import analyze_content
from app.engines.phase12_conversation import analyze_conversation
from app.engines.phase13_brand import analyze_brand_impersonation
from app.engines.phase14_threatintel import analyze_threat_intel
from app.engines.phase15_behavior import analyze_behavior
from app.engines.phase16_correlation import correlate_evidence
from app.engines.phase17_scoring import calculate_dynamic_risk
from app.engines.phase18_recommendation import generate_recommendations
from app.engines.phase19_reporting import generate_report_export
from app.engines.phase20_storage import save_to_storage

def run_phishing_analysis_pipeline(raw_data: bytes, filename: str = "email.eml"):
    """
    Executes all 20 phases of the Enterprise Phishing Analysis Algorithm (Version 2.0).
    """
    # Phase 1: Input Validation
    ingest = validate_and_ingest_email(raw_data, filename)
    analysis_id = ingest["analysis_id"]
    timestamp = ingest["timestamp"]
    msg_obj = ingest["msg_obj"]
    
    # Phase 2: Parsing
    parsed = parse_email_artifacts(msg_obj)
    
    # Phase 3: Headers
    headers_res = analyze_headers(msg_obj)
    
    # Phase 4: Authentication
    auth_res = analyze_authentication(msg_obj)
    
    # Phase 7: URL Extraction & Analysis (needed for domain & brand & threat intel)
    extracted_raw_urls = extract_urls(parsed["plain_text_body"], parsed["html_body"])
    url_res = analyze_urls(extracted_raw_urls)
    
    # Phase 5: Domain Intelligence
    domain_res = analyze_domains(parsed, extracted_raw_urls)
    
    # Phase 6: Sender Trust
    sender_res = analyze_sender_trust(parsed)
    
    # Phase 8: Attachments
    att_res = analyze_attachments(parsed["attachments"])
    
    # Phase 9: HTML & Rendering
    html_res = analyze_html(parsed["html_body"])
    
    # Phase 10: OCR & Visual Analysis
    visual_res = analyze_visual(parsed, parsed["attachments"])
    
    # Phase 11: Content Intelligence
    content_res = analyze_content(parsed)
    
    # Phase 12: Conversation
    conv_res = analyze_conversation(parsed)
    
    # Phase 13: Brand Impersonation
    brand_res = analyze_brand_impersonation(parsed, extracted_raw_urls)
    
    # Phase 14: Threat Intelligence
    ti_res = analyze_threat_intel(parsed, extracted_raw_urls, parsed["attachments"])
    
    # Collect all scores for scoring engine
    all_scores = {
        "header": headers_res["header_risk_score"],
        "auth": auth_res["auth_risk_score"],
        "domain": domain_res["domain_risk_score"],
        "sender": sender_res["sender_risk_score"],
        "url": url_res["url_risk_score"],
        "attachment": att_res["attachment_risk_score"],
        "html": html_res["html_risk_score"],
        "visual": visual_res["visual_risk_score"],
        "content": content_res["content_risk_score"],
        "relationship": conv_res["relationship_risk_score"],
        "brand": brand_res["brand_risk_score"],
        "threat_intel": ti_res["threat_intel_risk_score"]
    }
    
    # Phase 15: Behavioral Analysis
    behavior_res = analyze_behavior(all_scores)
    
    # Phase 16: Evidence Correlation
    all_engine_results = {
        "header": headers_res,
        "auth": auth_res,
        "domain": domain_res,
        "sender": sender_res,
        "url": url_res,
        "attachment": att_res,
        "html": html_res,
        "visual": visual_res,
        "content": content_res,
        "relationship": conv_res,
        "brand": brand_res,
        "threat_intel": ti_res
    }
    correlation_res = correlate_evidence(all_engine_results)
    
    # Phase 17: Dynamic Risk Scoring
    scoring_res = calculate_dynamic_risk(all_scores)
    
    # Phase 18: Recommendation Engine
    recommendation_res = generate_recommendations(scoring_res, behavior_res, correlation_res)
    
    # Construct full analysis payload
    analysis_result = {
        "analysis_id": analysis_id,
        "timestamp": timestamp,
        "file_size": ingest["file_size"],
        "sha256": ingest["sha256"],
        "parsed": parsed,
        "engines": all_engine_results,
        "behavior": behavior_res,
        "correlation": correlation_res,
        "scoring": scoring_res,
        "recommendation": recommendation_res
    }
    
    # Phase 20: Storage
    save_to_storage(analysis_result)
    
    return analysis_result
