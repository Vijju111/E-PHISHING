import os
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException, Cookie, Response
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, PlainTextResponse, Response as FastAPIResponse
from fastapi.templating import Jinja2Templates

from src.config.config import settings
from src.logging.logger import logger
from src.service.analysis_service import AnalysisService
from src.repository.analysis_repository import AnalysisRepository
from src.reports.report_generator import generate_pdf_report
from src.utils.owasp_security import OWASPSecurityMiddleware, secure_filename, verify_file_magic_bytes
from src.utils.session_manager import create_secure_session_token, verify_secure_session_token

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise-Grade Email Phishing Analysis Platform",
    version=settings.VERSION
)

app.add_middleware(OWASPSecurityMiddleware)

templates = Jinja2Templates(directory="src/presentation/templates")

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FastAPIResponse(status_code=204)

def get_or_create_session(request: Request, response: Response) -> str:
    token = request.cookies.get("phishguard_session")
    if token:
        try:
            data = verify_secure_session_token(token, max_age=3600)
            session_id = data.get("session_id")
            if session_id:
                new_token = create_secure_session_token({"session_id": session_id})
                response.set_cookie(key="phishguard_session", value=new_token, httponly=True, secure=False, samesite="lax", max_age=3600)
                return session_id
        except HTTPException:
            pass
            
    new_session_id = os.urandom(16).hex()
    new_token = create_secure_session_token({"session_id": new_session_id})
    response.set_cookie(key="phishguard_session", value=new_token, httponly=True, secure=False, samesite="lax", max_age=3600)
    return new_session_id

@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request, response: Response, verified: str = Cookie(default=None)):
    session_id = get_or_create_session(request, response)
    
    history = AnalysisRepository.get_all_history_for_session(session_id)
    total = len(history)
    critical = sum(1 for h in history if h.get("risk_score", 0) > 80)
    high = sum(1 for h in history if 60 < h.get("risk_score", 0) <= 80)
    suspicious = sum(1 for h in history if 40 < h.get("risk_score", 0) <= 60)
    safe = sum(1 for h in history if h.get("risk_score", 0) <= 40)
    
    stats = {
        "total_scans": total,
        "critical_count": critical,
        "high_count": high,
        "suspicious_count": suspicious,
        "safe_count": safe
    }
    
    is_verified = verified == "true"
    
    return templates.TemplateResponse(request, "index.html", {
        "history": history, 
        "stats": stats,
        "is_verified": is_verified
    })

@app.post("/api/v1/verify-math")
async def verify_math_captcha(response: Response, answer: int = Form(...), expected: int = Form(...)):
    if answer == expected:
        response.set_cookie(key="verified", value="true", httponly=True, secure=False, samesite="lax", max_age=86400)
        return {"status": "success"}
    raise HTTPException(status_code=400, detail="Incorrect mathematical answer. Access denied.")

@app.post(f"{settings.API_V1_PREFIX}/analyze/eml")
async def analyze_eml(request: Request, response: Response, file: UploadFile = File(...)):
    try:
        session_id = get_or_create_session(request, response)
        filename = secure_filename(file.filename or "email.eml")
        content = await file.read()
        
        if not verify_file_magic_bytes(content, filename):
            raise HTTPException(status_code=400, detail="Invalid file integrity or unsupported email format.")
            
        result = AnalysisService.analyze_email(content, filename, session_id=session_id)
        return JSONResponse(content={"status": "success", "analysis_id": result["analysis_id"], "result": result})
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error("EML analysis failed", extra={"extra_data": {"error": str(e)}})
        raise HTTPException(status_code=400, detail=str(e))

@app.post(f"{settings.API_V1_PREFIX}/analyze/text")
async def analyze_text(
    request: Request,
    response: Response,
    subject: str = Form(...),
    sender: str = Form(...),
    recipient: str = Form(default="user@enterprise.com"),
    body: str = Form(...)
):
    try:
        session_id = get_or_create_session(request, response)
        import html
        clean_subject = html.escape(subject) if subject else ""
        clean_sender = html.escape(sender) if sender else ""
        clean_body = html.escape(body) if body else ""
        
        rfc822 = f"""Subject: {clean_subject}
From: {clean_sender}
To: {recipient}
Date: Tue, 29 Jul 2026 10:00:00 +0000
Message-ID: <enterprise-{os.urandom(4).hex()}@phishguard.local>
Content-Type: text/plain; charset="utf-8"

{clean_body}
""".encode("utf-8")
        result = AnalysisService.analyze_email(rfc822, "manual_submission.eml", session_id=session_id)
        return JSONResponse(content={"status": "success", "analysis_id": result["analysis_id"], "result": result})
    except Exception as e:
        logger.error("Text analysis failed", extra={"extra_data": {"error": str(e)}})
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/report/{analysis_id}", response_class=HTMLResponse)
async def view_report(request: Request, response: Response, analysis_id: str):
    session_id = get_or_create_session(request, response)
    detail = AnalysisRepository.get_analysis_detail(analysis_id, session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Report not found.")
    return templates.TemplateResponse(request, "report.html", {"report": detail})

@app.get(f"{settings.API_V1_PREFIX}/export/pdf/{{analysis_id}}")
async def export_pdf(request: Request, response: Response, analysis_id: str):
    session_id = get_or_create_session(request, response)
    detail = AnalysisRepository.get_analysis_detail(analysis_id, session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Report not found.")
    pdf_path = os.path.expanduser(f"~/phishing_tool_storage/report_{analysis_id}.pdf")
    generate_pdf_report(detail, pdf_path)
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"phishguard_report_{analysis_id[:8]}.pdf")

@app.get(f"{settings.API_V1_PREFIX}/export/json/{{analysis_id}}")
async def export_json(request: Request, response: Response, analysis_id: str):
    session_id = get_or_create_session(request, response)
    detail = AnalysisRepository.get_analysis_detail(analysis_id, session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Report not found.")
    return JSONResponse(content=detail)

@app.get(f"{settings.API_V1_PREFIX}/export/csv/{{analysis_id}}")
async def export_csv(request: Request, response: Response, analysis_id: str):
    session_id = get_or_create_session(request, response)
    detail = AnalysisRepository.get_analysis_detail(analysis_id, session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Report not found.")
    csv_text = f"Metric,Value\nSubject,\"{detail['parsed']['metadata']['subject']}\"\nRisk Score,{detail['scoring']['risk_score']}\nSeverity,{detail['scoring']['severity']}\nVerdict,\"{detail['scoring']['verdict']}\""
    return PlainTextResponse(csv_text, media_type="text/csv")