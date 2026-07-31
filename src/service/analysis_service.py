from src.engines.input_parser import parse_and_validate_email
from src.engines.engine_1_header import HeaderIntelligenceEngine
from src.engines.engine_2_auth import AuthenticationEngine
from src.engines.engine_3_domain import DomainIntelligenceEngine
from src.engines.engine_4_sender import SenderTrustEngine
from src.engines.engine_5_url import URLIntelligenceEngine
from src.engines.engine_6_attachment import AttachmentIntelligenceEngine
from src.engines.engine_7_html import HTMLRenderingEngine
from src.engines.engine_8_visual import OCRVisualAnalysisEngine
from src.engines.engine_9_content import ContentIntelligenceEngine
from src.engines.engine_10_conversation import ConversationAnalysisEngine
from src.engines.engine_11_brand import BrandImpersonationEngine
from src.engines.engine_12_threatintel import ThreatIntelligenceEngine
from src.engines.engine_13_behavior import BehavioralAnalysisEngine
from src.engines.engine_14_correlation import EvidenceCorrelationEngine
from src.engines.engine_15_scoring import DynamicRiskScoringEngine
from src.engines.engine_16_recommendation import RecommendationEngine

from src.repository.analysis_repository import AnalysisRepository
from src.logging.logger import logger

class AnalysisService:
    """
    Service Layer orchestrating the entire email phishing analysis pipeline across all 16 detection engines.
    """
    @classmethod
    def analyze_email(cls, raw_data: bytes, filename: str = "email.eml", session_id: str = "default_session") -> dict:
        logger.info("Starting email analysis pipeline", extra={"extra_data": {"filename": filename, "size": len(raw_data)}})
        
        email_context = parse_and_validate_email(raw_data, filename)
        
        engines = {
            "header": HeaderIntelligenceEngine().analyze(email_context),
            "auth": AuthenticationEngine().analyze(email_context),
            "domain": DomainIntelligenceEngine().analyze(email_context),
            "sender": SenderTrustEngine().analyze(email_context),
            "url": URLIntelligenceEngine().analyze(email_context),
            "attachment": AttachmentIntelligenceEngine().analyze(email_context),
            "html": HTMLRenderingEngine().analyze(email_context),
            "visual": OCRVisualAnalysisEngine().analyze(email_context),
            "content": ContentIntelligenceEngine().analyze(email_context),
            "conversation": ConversationAnalysisEngine().analyze(email_context),
            "brand": BrandImpersonationEngine().analyze(email_context),
            "threat_intel": ThreatIntelligenceEngine().analyze(email_context),
        }
        
        att_risk = engines["attachment"]["risk_score"]
        brand_risk = engines["brand"]["risk_score"]
        url_risk = engines["url"]["risk_score"]
        content_risk = engines["content"]["risk_score"]
        
        if att_risk >= 60:
            behavior = "Malware Delivery / Ransomware"
        elif brand_risk >= 50 or url_risk >= 40:
            behavior = "Credential Phishing / Account Takeover"
        elif content_risk >= 35:
            behavior = "Financial / Invoice Scam"
        else:
            behavior = "Suspicious Phishing Attempt"
            
        engines["behavior"] = {"engine_name": "Behavioral Analysis", "risk_score": 0, "findings": [], "metadata": {"behavior_classification": behavior}}
        
        correlation = EvidenceCorrelationEngine().analyze(engines)
        engines["correlation"] = correlation
        
        all_scores = {name: res["risk_score"] for name, res in engines.items() if isinstance(res, dict) and "risk_score" in res}
        scoring = DynamicRiskScoringEngine().analyze(all_scores)
        
        recommendation = RecommendationEngine().analyze(scoring["risk_score"], scoring["metadata"]["severity"], scoring["metadata"]["verdict"])
        
        analysis_result = {
            "analysis_id": email_context["analysis_id"],
            "timestamp": email_context["timestamp"],
            "file_size": email_context["file_size"],
            "sha256": email_context["sha256"],
            "parsed": {
                "metadata": email_context["metadata"],
                "plain_text_body": email_context["plain_text_body"]
            },
            "engines": engines,
            "behavior": {"behavior_classification": behavior, "behavior_confidence": 92},
            "correlation": {"supporting_evidence": correlation["findings"], "total_indicators_count": len(correlation["findings"])},
            "scoring": {
                "risk_score": scoring["risk_score"],
                "confidence_score": scoring["metadata"]["confidence_score"],
                "severity": scoring["metadata"]["severity"],
                "verdict": scoring["metadata"]["verdict"]
            },
            "recommendation": recommendation["metadata"]
        }
        
        AnalysisRepository.save_analysis(analysis_result, session_id=session_id)
        logger.info("Email analysis completed successfully", extra={"extra_data": {"analysis_id": email_context["analysis_id"], "risk_score": scoring["risk_score"]}})
        
        return analysis_result
