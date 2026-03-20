"""
CVE Lookup Module for NeuraTrace
Queries the National Vulnerability Database (NVD) API for CVE information
"""

import requests
import json
import os
import time
import logging
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Route cache to the same custom save directory as the rest of the app
_DEFAULT_SAVE_PATH = r"E:\Backup\Desktop\NT\saved_scans"
_CFG = os.path.join(_DEFAULT_SAVE_PATH, 'neura_trace_config.json')
try:
    if os.path.exists(_CFG):
        import json as _j
        _c = _j.load(open(_CFG))
        _DEFAULT_SAVE_PATH = _c.get('save_path', _DEFAULT_SAVE_PATH)
except Exception:
    pass

DATA_DIR = Path(_DEFAULT_SAVE_PATH)
DATA_DIR.mkdir(parents=True, exist_ok=True)


class CVELookup:
    """Query NVD (National Vulnerability Database) for CVE information"""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_FILE = str(DATA_DIR / "cve_cache.json")
    CACHE_EXPIRY_HOURS = 24

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.cache = self._load_cache()
        self.last_request_time = 0
        self.rate_limit_delay = 6 if not self.api_key else 0.6

    def _load_cache(self) -> Dict:
        try:
            if os.path.exists(self.CACHE_FILE):
                with open(self.CACHE_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load cache: {e}")
        return {"entries": {}, "last_updated": None}

    def _save_cache(self):
        try:
            self.cache["last_updated"] = datetime.now().isoformat()
            with open(self.CACHE_FILE, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save cache: {e}")

    def _is_cache_valid(self, key: str) -> bool:
        if key not in self.cache["entries"]:
            return False
        entry = self.cache["entries"][key]
        cached_time = datetime.fromisoformat(entry.get("timestamp", "2000-01-01"))
        return datetime.now() - cached_time < timedelta(hours=self.CACHE_EXPIRY_HOURS)

    def _rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()

    def search_by_keyword(self, keyword: str, max_results: int = 10) -> List[Dict]:
        cache_key = f"keyword_{keyword}_{max_results}"
        if self._is_cache_valid(cache_key):
            logger.info(f"Using cached results for: {keyword}")
            return self.cache["entries"][cache_key]["data"]

        self._rate_limit()
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            params = {"keywordSearch": keyword, "resultsPerPage": max_results}
            response = requests.get(self.NVD_API_BASE, params=params, headers=headers, timeout=30)
            response.raise_for_status()

            data = response.json()
            cves = self._parse_cve_response(data)

            self.cache["entries"][cache_key] = {
                "data": cves,
                "timestamp": datetime.now().isoformat()
            }
            self._save_cache()
            return cves
        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Error searching CVEs: {e}")
            return []

    def search_by_cpe(self, product: str, version: str = None) -> List[Dict]:
        cache_key = f"cpe_{product}_{version}"
        if self._is_cache_valid(cache_key):
            return self.cache["entries"][cache_key]["data"]

        self._rate_limit()
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            params = {
                "keywordSearch": f"{product} {version}" if version else product,
                "resultsPerPage": 20
            }
            response = requests.get(self.NVD_API_BASE, params=params, headers=headers, timeout=30)
            response.raise_for_status()

            data = response.json()
            cves = self._parse_cve_response(data)

            self.cache["entries"][cache_key] = {
                "data": cves,
                "timestamp": datetime.now().isoformat()
            }
            self._save_cache()
            return cves
        except Exception as e:
            logger.error(f"Error in CPE search: {e}")
            return []

    def _parse_cve_response(self, data: Dict) -> List[Dict]:
        cves = []
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "Unknown")

            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            metrics = cve_data.get("metrics", {})
            cvss_score = 0
            severity = "Unknown"

            for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if cvss_version in metrics and metrics[cvss_version]:
                    cvss_data = metrics[cvss_version][0]
                    if "cvssData" in cvss_data:
                        cvss_score = cvss_data["cvssData"].get("baseScore", 0)
                        severity = cvss_data["cvssData"].get("baseSeverity",
                                   cvss_data.get("baseSeverity", "Unknown"))
                        break

            references = [ref.get("url", "") for ref in cve_data.get("references", [])[:3]]
            published = cve_data.get("published", "")[:10]

            cves.append({
                "cve_id": cve_id,
                "description": description[:500] + "..." if len(description) > 500 else description,
                "cvss_score": cvss_score,
                "severity": severity.upper() if severity else "UNKNOWN",
                "published": published,
                "references": references
            })

        cves.sort(key=lambda x: x["cvss_score"], reverse=True)
        return cves

    def get_cves_for_service(self, service_name: str, banner: str = "") -> Dict:
        version = self._extract_version(banner)
        search_term = f"{service_name} {version}" if version else service_name
        cves = self.search_by_keyword(search_term, max_results=5)

        critical_count = sum(1 for c in cves if c["severity"] == "CRITICAL")
        high_count = sum(1 for c in cves if c["severity"] == "HIGH")
        medium_count = sum(1 for c in cves if c["severity"] == "MEDIUM")

        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 0:
            risk_level = "HIGH"
        elif medium_count > 0:
            risk_level = "MEDIUM"
        elif cves:
            risk_level = "LOW"
        else:
            risk_level = "UNKNOWN"

        return {
            "service": service_name,
            "version": version if version else "Unknown",
            "cves": cves,
            "cve_count": len(cves),
            "risk_level": risk_level,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count
        }

    def _extract_version(self, banner: str) -> Optional[str]:
        if not banner:
            return None
        patterns = [
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)',
            r'/(\d+\.\d+\.\d+)',
            r'/(\d+\.\d+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        return None


def lookup_cves(service_name: str, banner: str = "", api_key: str = None) -> Dict:
    lookup = CVELookup(api_key)
    return lookup.get_cves_for_service(service_name, banner)
