import json
import os
from typing import Optional
from src.config.config import settings
from src.database.supabase_client import supabase_client
from src.logging.logger import logger

class AnalysisRepository:
    """
    Repository Pattern for Analysis Results persistence and retrieval.
    Enforces strict session isolation (Confidentiality) across all users and devices,
    using session-specific local storage files when Supabase is not configured.
    """
    STORAGE_DIR = os.path.expanduser("~/phishing_tool_storage")

    @classmethod
    def _get_session_file_path(cls, session_id: str) -> str:
        os.makedirs(cls.STORAGE_DIR, exist_ok=True)
        # Sanitize session_id to prevent path traversal
        clean_sid = "".join(c for c in session_id if c.isalnum() or c in "_-")
        if not clean_sid:
            clean_sid = "default_session"
        return os.path.join(cls.STORAGE_DIR, f"history_{clean_sid}.json")

    @classmethod
    def save_analysis(cls, analysis_result: dict, session_id: str) -> None:
        analysis_result["session_id"] = session_id
        
        # 1. Attempt Supabase persistence if configured
        try:
            if "placeholder" not in settings.SUPABASE_URL:
                supabase_client.table("analyses").insert({
                    "analysis_id": analysis_result["analysis_id"],
                    "session_id": session_id,
                    "timestamp": analysis_result["timestamp"],
                    "sha256": analysis_result["sha256"],
                    "risk_score": analysis_result["scoring"]["risk_score"],
                    "severity": analysis_result["scoring"]["severity"],
                    "verdict": analysis_result["scoring"]["verdict"],
                    "full_report": analysis_result
                }).execute()
        except Exception as e:
            logger.warning("Supabase persistence failed or schema missing, using isolated local session storage", extra={"extra_data": {"error": str(e)}})

        # 2. Strict Session-Isolated Local Storage (Prevents multi-user history leakage)
        session_file = cls._get_session_file_path(session_id)
        history = cls.get_all_history_for_session(session_id)
        
        # Remove duplicate if exists
        history = [h for h in history if h.get("analysis_id") != analysis_result["analysis_id"]]
        history.insert(0, {
            "analysis_id": analysis_result["analysis_id"],
            "session_id": session_id,
            "timestamp": analysis_result["timestamp"],
            "subject": analysis_result["parsed"]["metadata"]["subject"],
            "from": analysis_result["parsed"]["metadata"]["from"],
            "risk_score": analysis_result["scoring"]["risk_score"],
            "severity": analysis_result["scoring"]["severity"],
            "verdict": analysis_result["scoring"]["verdict"]
        })
        history = history[:200]
        
        with open(session_file, "w") as f:
            json.dump(history, f, indent=2, default=str)

        # Save individual detail file
        detail_path = os.path.join(cls.STORAGE_DIR, f"details_{analysis_result['analysis_id']}.json")
        with open(detail_path, "w") as f:
            json.dump(analysis_result, f, indent=2, default=str)

    @classmethod
    def get_all_history_for_session(cls, session_id: str) -> list:
        session_file = cls._get_session_file_path(session_id)
        if not os.path.exists(session_file):
            return []
        try:
            with open(session_file, "r") as f:
                return json.load(f)
        except Exception:
            return []

    @classmethod
    def get_analysis_detail(cls, analysis_id: str, session_id: str) -> Optional[dict]:
        detail_path = os.path.join(cls.STORAGE_DIR, f"details_{analysis_id}.json")
        if os.path.exists(detail_path):
            try:
                with open(detail_path, "r") as f:
                    detail = json.load(f)
                    # Enforce strict confidentiality: verify session ownership if session_id is present
                    if detail.get("session_id") and detail.get("session_id") != session_id:
                        return None
                    return detail
            except Exception:
                return None
        return None
