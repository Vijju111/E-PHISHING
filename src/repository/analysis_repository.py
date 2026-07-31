import json
import os
from typing import Optional
from src.config.config import settings
from src.database.supabase_client import supabase_client
from src.logging.logger import logger

class AnalysisRepository:
    """
    Repository Pattern for Analysis Results persistence and retrieval.
    Guarantees that analysis history updates instantly for the user's active session
    while enforcing strict session isolation so no user can view another user's history or reports.
    """
    STORAGE_DIR = os.path.expanduser("~/phishing_tool_storage")
    _IN_MEMORY_CACHE = {}

    @classmethod
    def _get_session_file_path(cls, session_id: str) -> str:
        os.makedirs(cls.STORAGE_DIR, exist_ok=True)
        clean_sid = "".join(c for c in session_id if c.isalnum() or c in "_-")
        if not clean_sid:
            clean_sid = "default_session"
        return os.path.join(cls.STORAGE_DIR, f"history_{clean_sid}.json")

    @classmethod
    def save_analysis(cls, analysis_result: dict, session_id: str) -> None:
        analysis_result["session_id"] = session_id
        
        # 1. Save to in-memory runtime cache
        cls._IN_MEMORY_CACHE[analysis_result["analysis_id"]] = analysis_result

        # 2. Attempt Supabase persistence if configured
        try:
            if "placeholder" not in settings.SUPABASE_URL:
                supabase_client.table("analyses").upsert({
                    "analysis_id": analysis_result["analysis_id"],
                    "session_id": session_id,
                    "timestamp": analysis_result["timestamp"],
                    "sha256": analysis_result["sha256"],
                    "risk_score": analysis_result["scoring"]["risk_score"],
                    "severity": analysis_result["scoring"]["severity"],
                    "verdict": analysis_result["scoring"]["verdict"],
                    "full_report": analysis_result
                }, on_conflict="analysis_id").execute()
        except Exception as e:
            logger.warning("Supabase persistence failed", extra={"extra_data": {"error": str(e)}})

        # 3. Save to session-isolated local history file (Ensures history & total scans update instantly)
        try:
            session_file = cls._get_session_file_path(session_id)
            history = []
            if os.path.exists(session_file):
                with open(session_file, "r") as f:
                    history = json.load(f)
            
            # Remove duplicate entry if re-analyzing same payload
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
            with open(session_file, "w") as f:
                json.dump(history[:200], f, indent=2, default=str)

            # Save individual detail file globally so direct report links resolve instantly
            detail_path = os.path.join(cls.STORAGE_DIR, f"details_{analysis_result['analysis_id']}.json")
            with open(detail_path, "w") as f:
                json.dump(analysis_result, f, indent=2, default=str)
        except Exception as e:
            logger.warning("Local storage persistence failed", extra={"extra_data": {"error": str(e)}})

    @classmethod
    def get_all_history_for_session(cls, session_id: str) -> list:
        # Strict session isolation: only return history file belonging to this specific session_id
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
        # 1. Check in-memory runtime cache first
        if analysis_id in cls._IN_MEMORY_CACHE:
            return cls._IN_MEMORY_CACHE[analysis_id]

        # 2. Check local JSON file
        detail_path = os.path.join(cls.STORAGE_DIR, f"details_{analysis_id}.json")
        if os.path.exists(detail_path):
            try:
                with open(detail_path, "r") as f:
                    detail = json.load(f)
                    cls._IN_MEMORY_CACHE[analysis_id] = detail
                    return detail
            except Exception:
                pass

        # 3. Query Supabase Cloud PostgreSQL
        try:
            if "placeholder" not in settings.SUPABASE_URL:
                res = supabase_client.table("analyses").select("full_report").eq("analysis_id", analysis_id).execute()
                if res.data and len(res.data) > 0:
                    report = res.data[0].get("full_report")
                    if report:
                        cls._IN_MEMORY_CACHE[analysis_id] = report
                        return report
        except Exception as e:
            logger.warning("Supabase detail fetch failed", extra={"extra_data": {"error": str(e)}})

        return None
