import os
import requests
from src.config.config import settings
from src.logging.logger import logger

class ThreatIntelClient:
    """
    Real-time, dynamic Threat Intelligence integration client for:
    - VirusTotal (File hashes & URLs)
    - AbuseIPDB (IP reputation)
    - OpenPhish (Live phishing URL feed)
    - URLScan.io (URL scanning & DOM analysis)
    
    100% Dynamic from Internet APIs with zero hardcoded / fake outputs.
    Provides live status and diagnostic feedback.
    """
    
    @staticmethod
    def query_virustotal_hash(sha256_hash: str) -> dict:
        api_key = os.getenv("VT_API_KEY", "")
        if not api_key or api_key == "placeholder_vt_key":
            return {
                "status": "unconfigured", 
                "source": "VirusTotal", 
                "live_api_working": False,
                "message": "VT_API_KEY not configured in .env. To enable live VirusTotal hash lookups, add your free API key to .env."
            }
            
        url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        headers = {"x-apikey": api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "status": "success", 
                    "source": "VirusTotal", 
                    "live_api_working": True,
                    "malicious": stats.get("malicious", 0), 
                    "suspicious": stats.get("suspicious", 0), 
                    "stats": stats
                }
            elif resp.status_code == 404:
                return {
                    "status": "not_found", 
                    "source": "VirusTotal", 
                    "live_api_working": True,
                    "message": "Hash not found in VirusTotal database (Clean or Unseen file)."
                }
            else:
                return {
                    "status": "error", 
                    "source": "VirusTotal", 
                    "live_api_working": False,
                    "code": resp.status_code,
                    "message": f"HTTP Error {resp.status_code} from VirusTotal API."
                }
        except Exception as e:
            return {
                "status": "error", 
                "source": "VirusTotal", 
                "live_api_working": False,
                "message": str(e)
            }

    @staticmethod
    def query_openphish_feed(url_to_check: str) -> dict:
        """
        Dynamically fetches and queries the official OpenPhish community feed in real-time from the internet.
        """
        try:
            feed_url = os.getenv("OPENPHISH_FEED_URL", "https://openphish.com/feed.txt")
            resp = requests.get(feed_url, timeout=8)
            if resp.status_code == 200:
                phish_urls = set(resp.text.splitlines())
                is_match = url_to_check in phish_urls
                return {
                    "status": "success", 
                    "source": "OpenPhish Live Feed", 
                    "live_api_working": True,
                    "matched": is_match, 
                    "total_feed_entries": len(phish_urls)
                }
        except Exception as e:
            logger.warning("OpenPhish live feed retrieval failed", extra={"extra_data": {"error": str(e)}})
        return {
            "status": "unavailable", 
            "source": "OpenPhish Live Feed", 
            "live_api_working": False,
            "matched": False,
            "message": "Could not download live OpenPhish feed from internet."
        }

    @staticmethod
    def query_abuseipdb(ip_address: str) -> dict:
        api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        if not api_key or api_key == "placeholder_abuse_key":
            return {
                "status": "unconfigured", 
                "source": "AbuseIPDB", 
                "live_api_working": False,
                "message": "ABUSEIPDB_API_KEY not configured in .env. To enable live IP reputation queries, add your free API key to .env."
            }
            
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {"ipAddress": ip_address, "maxAgeInDays": "90"}
        headers = {"Accept": "application/json", "Key": api_key}
        try:
            resp = requests.get(url, headers=headers, params=querystring, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "status": "success",
                    "source": "AbuseIPDB",
                    "live_api_working": True,
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "")
                }
            return {
                "status": "error", 
                "source": "AbuseIPDB", 
                "live_api_working": False,
                "code": resp.status_code,
                "message": f"HTTP Error {resp.status_code} from AbuseIPDB API."
            }
        except Exception as e:
            return {
                "status": "error", 
                "source": "AbuseIPDB", 
                "live_api_working": False,
                "message": str(e)
            }

    @staticmethod
    def submit_urlscan(target_url: str) -> dict:
        api_key = os.getenv("URLSCAN_API_KEY", "")
        if not api_key or api_key == "placeholder_urlscan_key":
            return {
                "status": "unconfigured", 
                "source": "URLScan.io", 
                "live_api_working": False,
                "message": "URLSCAN_API_KEY not configured in .env. To enable live URL scanning, add your free API key to .env."
            }
            
        url = "https://urlscan.io/api/v1/scan/"
        headers = {"API-Key": api_key, "Content-Type": "application/json"}
        payload = {"url": target_url, "visibility": "public"}
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=10)
            if resp.status_code == 200:
                return {
                    "status": "success", 
                    "source": "URLScan.io", 
                    "live_api_working": True,
                    "result": resp.json()
                }
            return {
                "status": "error", 
                "source": "URLScan.io", 
                "live_api_working": False,
                "code": resp.status_code,
                "message": f"HTTP Error {resp.status_code} from URLScan.io API."
            }
        except Exception as e:
            return {
                "status": "error", 
                "source": "URLScan.io", 
                "live_api_working": False,
                "message": str(e)
            }
