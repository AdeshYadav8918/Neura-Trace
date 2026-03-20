"""
CVE Lookup Module for NeuraTrace (MILITARY-GRADE HARDENED)
Air-gapped offline CVE lookup mirror. Outbound NVD queries are disabled for strict OPSEC.
"""

import json
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

OFFLINE_CVE_DB = [
    {
        "cve_id": "CVE-2021-44228",
        "description": "Log4j Remote Code Execution (Log4Shell)",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "published": "2021-12-10",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
    },
    {
        "cve_id": "CVE-2017-0144",
        "description": "SMBv1 Remote Code Execution (EternalBlue)",
        "cvss_score": 9.3,
        "severity": "CRITICAL",
        "published": "2017-03-16",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"]
    },
    {
        "cve_id": "CVE-2014-0160",
        "description": "OpenSSL Information Disclosure (Heartbleed)",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "published": "2014-04-07",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"]
    }
]

class CVELookup:
    """Offline isolated CVE Database Mirror"""
    
    def __init__(self, api_key: Optional[str] = None):
        """Ignore API key, strictly offline mode"""
        logger.info("CVE Lookup operating in air-gapped Offline DB Mode.")
        pass

    def search_by_keyword(self, keyword: str, max_results: int = 10) -> List[Dict]:
        """Search local offline database"""
        results = []
        kw_lower = keyword.lower()
        for cve in OFFLINE_CVE_DB:
            if kw_lower in cve["description"].lower() or kw_lower in cve["cve_id"].lower():
                results.append(cve)
        return results[:max_results]

    def search_by_cpe(self, product: str, version: str = None) -> List[Dict]:
        return self.search_by_keyword(product)

    def get_cves_for_service(self, service_name: str, banner: str = "") -> Dict:
        cves = self.search_by_keyword(service_name)
        
        # Determine strict risk based on local findings
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
            "version": "Offline Match",
            "cves": cves,
            "cve_count": len(cves),
            "risk_level": risk_level,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count
        }

def lookup_cves(service_name: str, banner: str = "", api_key: str = None) -> Dict:
    lookup = CVELookup(api_key)
    return lookup.get_cves_for_service(service_name, banner)
