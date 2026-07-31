import json

def generate_report_export(analysis_data, export_format="json"):
    """
    Phase 19: Reporting Engine
    Exports analysis results in JSON, CSV, or structured report dictionaries.
    """
    if export_format == "json":
        return json.dumps(analysis_data, indent=2, default=str)
    elif export_format == "csv":
        # CSV summary representation
        csv_lines = ["Category,Metric,Value"]
        meta = analysis_data.get("parsed", {}).get("metadata", {})
        csv_lines.append(f"Metadata,Subject,\"{meta.get('subject', '')}\"")
        csv_lines.append(f"Metadata,From,\"{meta.get('from', '')}\"")
        scoring = analysis_data.get("scoring", {})
        csv_lines.append(f"Scoring,Risk Score,{scoring.get('risk_score', 0)}")
        csv_lines.append(f"Scoring,Severity,\"{scoring.get('severity', '')}\"")
        csv_lines.append(f"Scoring,Verdict,\"{scoring.get('verdict', '')}\"")
        return "\n".join(csv_lines)
    else:
        return analysis_data
