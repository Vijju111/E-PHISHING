import os
import json

STORAGE_DB_PATH = os.path.expanduser("~/phishing_tool_storage/history.json")

def save_to_storage(analysis_result):
    """
    Phase 20: Storage & Dashboard Engine
    Stores analysis results in local JSON database for historical tracking, search, and trends.
    """
    os.makedirs(os.path.dirname(STORAGE_DB_PATH), exist_ok=True)
    history = load_history()
    
    # Store summary entry
    summary = {
        "analysis_id": analysis_result["analysis_id"],
        "timestamp": analysis_result["timestamp"],
        "subject": analysis_result["parsed"]["metadata"]["subject"],
        "from": analysis_result["parsed"]["metadata"]["from"],
        "risk_score": analysis_result["scoring"]["risk_score"],
        "severity": analysis_result["scoring"]["severity"],
        "verdict": analysis_result["scoring"]["verdict"],
        "behavior": analysis_result["behavior"]["behavior_classification"]
    }
    
    history.insert(0, summary)
    # Keep last 200 records
    history = history[:200]
    
    with open(STORAGE_DB_PATH, "w") as f:
        json.dump(history, f, indent=2, default=str)
        
    # Also save full detailed JSON record
    detail_path = os.path.expanduser(f"~/phishing_tool_storage/details_{summary['analysis_id']}.json")
    with open(detail_path, "w") as f:
        json.dump(analysis_result, f, indent=2, default=str)

def load_history():
    if not os.path.exists(STORAGE_DB_PATH):
        return []
    try:
        with open(STORAGE_DB_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return []

def get_detail(analysis_id):
    detail_path = os.path.expanduser(f"~/phishing_tool_storage/details_{analysis_id}.json")
    if os.path.exists(detail_path):
        try:
            with open(detail_path, "r") as f:
                return json.load(f)
        except Exception:
            return None
    return None
