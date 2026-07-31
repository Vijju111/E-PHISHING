import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(analysis_report: dict, output_path: str) -> str:
    """
    Generates a professional, comprehensive, enterprise-grade PDF report using ReportLab.
    Includes Email Date, Complete Header Details, risk score breakdown, true verdict, and recommendations.
    """
    doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=16, textColor=colors.HexColor("#0f172a"), spaceAfter=4)
    subtitle_style = ParagraphStyle('SubTitleStyle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor("#64748b"), spaceAfter=10)
    section_style = ParagraphStyle('SectionStyle', parent=styles['Heading2'], fontSize=11, textColor=colors.HexColor("#1e293b"), spaceBefore=8, spaceAfter=4)
    normal_style = ParagraphStyle('NormalStyle', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor("#334155"), leading=11)
    bold_style = ParagraphStyle('BoldStyle', parent=normal_style, fontName="Helvetica-Bold")
    
    # Header Banner
    story.append(Paragraph("PhishGuard Enterprise &bull; Forensic Security Report", title_style))
    story.append(Paragraph(f"<b>Analysis ID:</b> {analysis_report['analysis_id']} &nbsp;|&nbsp; <b>Evaluated At:</b> {analysis_report['timestamp']} &nbsp;|&nbsp; <b>SHA-256:</b> {analysis_report['sha256'][:20]}...", subtitle_style))
    
    # Executive Summary Box
    scoring = analysis_report["scoring"]
    behavior = analysis_report["behavior"]
    
    summary_data = [
        [Paragraph(f"<b>Risk Score:</b> {scoring['risk_score']}/100", bold_style), Paragraph(f"<b>Severity:</b> {scoring['severity']}", bold_style)],
        [Paragraph(f"<b>True Verdict:</b> {scoring['verdict']}", bold_style), Paragraph(f"<b>Behavior:</b> {behavior['behavior_classification']}", bold_style)]
    ]
    t = Table(summary_data, colWidths=[250, 290])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 8))
    
    # Email Metadata & Complete Header Details Section
    story.append(Paragraph("1. Email Date & Complete Header Details", section_style))
    meta = analysis_report['parsed']['metadata']
    meta_data = [
        [Paragraph("<b>Email Date:</b>", bold_style), Paragraph(meta.get('date', 'N/A'), normal_style)],
        [Paragraph("<b>Subject:</b>", bold_style), Paragraph(meta.get('subject', 'N/A'), normal_style)],
        [Paragraph("<b>From (Sender):</b>", bold_style), Paragraph(meta.get('from', 'N/A'), normal_style)],
        [Paragraph("<b>To (Recipient):</b>", bold_style), Paragraph(meta.get('to', 'N/A'), normal_style)],
        [Paragraph("<b>Reply-To:</b>", bold_style), Paragraph(meta.get('reply_to', 'N/A'), normal_style)],
        [Paragraph("<b>Return-Path:</b>", bold_style), Paragraph(meta.get('return_path', 'N/A'), normal_style)],
        [Paragraph("<b>Message-ID:</b>", bold_style), Paragraph(meta.get('message_id', 'N/A'), normal_style)]
    ]
    meta_table = Table(meta_data, colWidths=[110, 430])
    meta_table.setStyle(TableStyle([
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8))
    
    # Detection Engines Breakdown
    story.append(Paragraph("2. Multi-Engine Forensic Analysis Results", section_style))
    engines = analysis_report.get("engines", {})
    engine_rows = [[Paragraph("<b>Engine Name</b>", bold_style), Paragraph("<b>Risk Score</b>", bold_style), Paragraph("<b>Key Findings / Description</b>", bold_style)]]
    
    for name, res in engines.items():
        if isinstance(res, dict) and "risk_score" in res:
            findings_text = "<br/>".join(res.get("findings", ["No threats detected"])) if res.get("findings") else "Clean / Verified"
            engine_rows.append([
                Paragraph(res.get("engine_name", name).title(), bold_style),
                Paragraph(f"{res.get('risk_score', 0)}/100", normal_style),
                Paragraph(findings_text, normal_style)
            ])
            
    engine_table = Table(engine_rows, colWidths=[120, 50, 370])
    engine_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(engine_table)
    story.append(Spacer(1, 8))
    
    # Recommendations & MITRE
    story.append(Paragraph("3. Incident Response Recommendations & MITRE ATT&CK", section_style))
    rec = analysis_report.get("recommendation", {})
    mitre_str = ", ".join(rec.get("mitre_mapping", ["N/A"]))
    actions = rec.get("recommended_actions", ["No action required."])
    
    rec_data = [
        [Paragraph("<b>MITRE ATT&CK:</b>", bold_style), Paragraph(mitre_str, normal_style)],
        [Paragraph("<b>Recommended Actions:</b>", bold_style), Paragraph("<br/>".join([f"&bull; {act}" for act in actions]), normal_style)]
    ]
    rec_table = Table(rec_data, colWidths=[120, 420])
    rec_table.setStyle(TableStyle([
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(rec_table)
    
    doc.build(story)
    return output_path
