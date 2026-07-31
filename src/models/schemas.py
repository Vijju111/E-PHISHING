from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class EmailSubmissionRequest(BaseModel):
    subject: str = Field(..., description="Email subject line")
    sender: str = Field(..., description="Sender email address")
    recipient: str = Field(default="user@enterprise.com", description="Recipient email address")
    body: str = Field(..., description="Email body content")

class EngineResult(BaseModel):
    engine_name: str
    risk_score: int = Field(..., ge=0, le=100)
    findings: List[str]
    metadata: Dict[str, Any] = {}

class AnalysisResponse(BaseModel):
    analysis_id: str
    timestamp: str
    file_size: int
    sha256: str
    risk_score: int
    confidence_score: int
    severity: str
    verdict: str
    behavior_classification: str
    engines: Dict[str, Any]
    recommendations: Dict[str, Any]
