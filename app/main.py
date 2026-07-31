import os
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.engines.orchestrator import run_phishing_analysis_pipeline
from app.engines.phase20_storage import load_history, get_detail
from app.engines.phase19_reporting import generate_report_export

app = FastAPI(
    title="Next-Gen Email Phishing Analysis Engine (v2.0)",
    description="Enterprise Multi-Engine Detection Framework & Phishing Analysis Web Tool",
    version="2.0.0"
)

templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    history = load_history()
    
    # Calculate statistics
    total_scans = len(history)
    critical_count = sum(1 for h in history if h.get("risk_score", 0) > 80)
    high_count = sum(1 for h in history if 60 < h.get("risk_score", 0) <= 80)
    suspicious_count = sum(1 for h in history if 40 < h.get("risk_score", 0) <= 60)
    safe_count = sum(1 for h in history if h.get("risk_score", 0) <= 40)
    
    stats = {
        "total_scans": total_scans,
        "critical_count": critical_count,
        "high_count": high_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count
    }
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "history": history,
        "stats": stats
    })

@app.post("/api/analyze/eml")
async def analyze_eml_file(file: UploadFile = File(...)):
    try:
        content = await file.read()
        filename = file.filename or "uploaded.eml"
        result = run_phishing_analysis_pipeline(content, filename)
        return JSONResponse(content={"status": "success", "analysis_id": result["analysis_id"], "result": result})
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/analyze/text")
async def analyze_raw_text(
    subject: str = Form(...),
    sender: str = Form(...),
    recipient: str = Form(default="user@enterprise.com"),
    body: str = Form(...)
):
    try:
        rfc822_raw = f"""Subject: {subject}
From: {sender}
To: {recipient}
Date: Tue, 29 Jul 2026 10:00:00 +0000
Message-ID: <sample-{os.urandom(4).hex()}@phish.local>
Content-Type: text/plain; charset="utf-8"

{body}
""".encode("utf-8")
        result = run_phishing_analysis_pipeline(rfc822_raw, "manual_submission.eml")
        return JSONResponse(content={"status": "success", "analysis_id": result["analysis_id"], "result": result})
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/report/{analysis_id}", response_class=HTMLResponse)
async def view_report(request: Request, analysis_id: str):
    detail = get_detail(analysis_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Analysis report not found.")
    return templates.TemplateResponse("report.html", {
        "request": request,
        "report": detail
    })

@app.get("/api/export/{analysis_id}")
async def export_report(analysis_id: str, format: str = "json"):
    detail = get_detail(analysis_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Analysis report not found.")
    
    exported = generate_report_export(detail, export_format=format)
    if format == "json":
        return JSONResponse(content=detail)
    elif format == "csv":
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(exported, media_type="text/csv")
    else:
        return JSONResponse(content=detail)
