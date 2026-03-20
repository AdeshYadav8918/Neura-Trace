"""
AI Analyzer Module for NeuraTrace
Provides AI-powered analysis for traffic, vulnerabilities, and malicious patterns
Supports Google Gemini API
"""

import json
import os
import logging
from typing import Dict, List, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import Google Generative AI
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    logger.warning("google-generativeai not installed. Run: pip install google-generativeai")


class AIAnalyzer:
    """AI-powered security analysis using Google Gemini"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model = None
        self.initialized = False
        
        if GEMINI_AVAILABLE and self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-2.5-flash')
                self.initialized = True
                logger.info("Gemini AI initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini: {e}")
    
    def is_available(self) -> bool:
        return self.initialized and self.model is not None
    
    def analyze_live_traffic(self, packets_summary: Dict) -> Dict:
        if not self.is_available():
            return self._get_unavailable_response("Live Traffic Analysis")
        
        prompt = f"""You are a network security analyst. Analyze this captured network traffic and provide insights.

CAPTURED TRAFFIC SUMMARY:
- Total Packets: {packets_summary.get('total_packets', 0)}
- Protocols Found: {', '.join(packets_summary.get('protocols', []))}
- Source IPs: {', '.join(packets_summary.get('source_ips', [])[:10])}
- Destination IPs: {', '.join(packets_summary.get('dest_ips', [])[:10])}
- Capture Duration: {packets_summary.get('duration', 'Unknown')}

Provide a concise analysis in this exact JSON format:
{{
    "traffic_summary": "Brief 1-2 sentence summary of the traffic",
    "anomalies_detected": ["list of any suspicious patterns or anomalies"],
    "protocol_analysis": "Analysis of protocol distribution",
    "recommendations": ["actionable security recommendations"],
    "risk_level": "LOW/MEDIUM/HIGH/CRITICAL",
    "notable_ips": ["any IPs that warrant attention"]
}}

Respond ONLY with valid JSON, no markdown or explanations."""

        return self._query_ai(prompt, "traffic_analysis")
    
    def analyze_vulnerabilities(self, scan_results: Dict, cve_data: List[Dict] = None) -> Dict:
        if not self.is_available():
            return self._get_unavailable_response("Vulnerability Analysis")
        
        open_ports_info = []
        for port, service in scan_results.get('open_ports', {}).items():
            details = scan_results.get('service_details', {}).get(str(port), {})
            banner = details.get('banner', 'No banner')[:100]
            open_ports_info.append(f"Port {port}: {service} - Banner: {banner}")
        
        cve_info = ""
        if cve_data:
            for cve in cve_data[:5]:
                cve_info += f"\n- {cve.get('cve_id')}: {cve.get('severity')} (CVSS: {cve.get('cvss_score')})"
                cve_info += f"\n  {cve.get('description', '')[:150]}..."
        
        prompt = f"""You are a cybersecurity expert. Analyze these port scan results and CVE data.

TARGET: {scan_results.get('target', 'Unknown')}
SCAN TIME: {scan_results.get('scan_time', 'Unknown')}

OPEN PORTS AND SERVICES:
{chr(10).join(open_ports_info) if open_ports_info else 'No open ports found'}

KNOWN VULNERABILITIES (from CVE Database):
{cve_info if cve_info else 'No CVEs found'}

Provide a security assessment in this exact JSON format:
{{
    "overall_risk": "LOW/MEDIUM/HIGH/CRITICAL",
    "security_score": 0-100,
    "executive_summary": "2-3 sentence executive summary",
    "critical_findings": ["list of critical security issues"],
    "vulnerable_services": [
        {{"port": 80, "service": "Apache", "risk": "HIGH", "issue": "outdated version"}}
    ],
    "attack_vectors": ["potential ways an attacker could exploit these services"],
    "immediate_actions": ["urgent actions to take now"],
    "remediation_steps": ["detailed remediation recommendations"],
    "compliance_notes": "Any regulatory compliance concerns (PCI-DSS, HIPAA, etc.)"
}}

Respond ONLY with valid JSON, no markdown or explanations."""

        return self._query_ai(prompt, "vulnerability_analysis")
    
    def detect_malicious_traffic(self, pcap_analysis: Dict) -> Dict:
        if not self.is_available():
            return self._get_unavailable_response("Malicious Traffic Detection")
        
        prompt = f"""You are a threat intelligence analyst. Analyze this PCAP data for malicious activity.

PCAP ANALYSIS:
- Total Packets: {pcap_analysis.get('summary', {}).get('total_packets', 0)}
- Protocols: {', '.join(pcap_analysis.get('summary', {}).get('protocols', []))}
- Source IPs: {', '.join(pcap_analysis.get('summary', {}).get('source_ips', [])[:15])}
- Destination IPs: {', '.join(pcap_analysis.get('summary', {}).get('dest_ips', [])[:15])}

Look for indicators of:
1. Port scanning activity
2. Data exfiltration patterns
3. Command & Control (C2) communication
4. DDoS attack signatures
5. Malware beaconing
6. SQL injection attempts
7. Brute force attacks

Respond in this exact JSON format:
{{
    "threat_level": "NONE/LOW/MEDIUM/HIGH/CRITICAL",
    "malicious_indicators": [
        {{"type": "C2 Communication", "confidence": "HIGH", "evidence": "Regular beaconing to known bad IP"}}
    ],
    "suspicious_ips": [
        {{"ip": "x.x.x.x", "reason": "Known malicious infrastructure"}}
    ],
    "attack_patterns": ["detected attack patterns"],
    "ioc_extracted": ["Indicators of Compromise found"],
    "timeline": "Timeline of suspicious activity if detectable",
    "recommendations": ["immediate response actions"],
    "false_positive_notes": "Any potential false positives to consider"
}}

Respond ONLY with valid JSON, no markdown or explanations."""

        return self._query_ai(prompt, "malicious_detection")
    
    def analyze_device_security(self, device_info: Dict, cve_data: List[Dict] = None) -> Dict:
        if not self.is_available():
            return self._get_unavailable_response("Device Security Audit")
        
        services_info = []
        for service in device_info.get('services', []):
            port = service.get('port', 'Unknown')
            name = service.get('name', 'Unknown')
            banner = service.get('banner', 'No banner')[:100]
            state = service.get('state', 'open')
            services_info.append(f"Port {port} ({state}): {name} - {banner}")
        
        cve_info_str = "No known CVEs found"
        if cve_data:
            cve_list = []
            for cve in cve_data[:10]:
                cve_list.append(f"- {cve.get('id')}: {cve.get('summary', '')[:100]} (CVSS: {cve.get('cvss', 'N/A')})")
            cve_info_str = chr(10).join(cve_list)
        
        prompt = f"""You are a device security expert conducting a comprehensive security audit.

TARGET DEVICE: {device_info.get('target', 'Unknown')}
DEVICE TYPE: {device_info.get('device_type', 'Unknown - please infer from services')}
SCAN TIME: {device_info.get('scan_time', 'Unknown')}

ACTIVE SERVICES DETECTED:
{chr(10).join(services_info) if services_info else 'No services detected'}

KNOWN VULNERABILITIES (CVEs):
{cve_info_str}

Provide your assessment in this exact JSON format:
{{
    "device_security_score": 0-100,
    "overall_risk": "LOW/MEDIUM/HIGH/CRITICAL",
    "device_type_detected": "Server/Workstation/IoT Device/Router/etc",
    "executive_summary": "2-3 sentence summary",
    "services_analysis": [
        {{
            "port": 22,
            "service": "SSH",
            "necessity": "REQUIRED/OPTIONAL/UNNECESSARY",
            "exposure_risk": "LOW/MEDIUM/HIGH",
            "is_appropriately_exposed": true,
            "vulnerabilities": ["List relevant CVE IDs if any"],
            "hardening_recommendations": ["specific hardening steps"]
        }}
    ],
    "unnecessary_services": ["services that should be disabled"],
    "inappropriately_exposed": ["services that should not be publicly accessible"],
    "critical_security_issues": ["urgent security problems"],
    "attack_surface_summary": "Description of the device attack surface",
    "priority_actions": ["ordered list of priority security actions"],
    "compliance_concerns": ["any regulatory compliance issues"],
    "best_practices": ["general security best practices for this device type"]
}}

Respond ONLY with valid JSON, no markdown or explanations."""

        return self._query_ai(prompt, "device_security_audit")
    
    def _query_ai(self, prompt: str, analysis_type: str) -> Dict:
        try:
            response = self.model.generate_content(prompt)
            response_text = response.text.strip()
            
            if response_text.startswith("```"):
                lines = response_text.split("\n")
                response_text = "\n".join(lines[1:-1])
            
            try:
                result = json.loads(response_text)
                result["_meta"] = {
                    "analysis_type": analysis_type,
                    "timestamp": datetime.now().isoformat(),
                    "ai_model": "gemini-2.5-flash",
                    "status": "success"
                }
                return result
            except json.JSONDecodeError:
                return {
                    "raw_analysis": response_text,
                    "_meta": {
                        "analysis_type": analysis_type,
                        "timestamp": datetime.now().isoformat(),
                        "status": "parse_error"
                    }
                }
        except Exception as e:
            logger.error(f"AI query failed: {e}")
            return {
                "error": str(e),
                "_meta": {
                    "analysis_type": analysis_type,
                    "timestamp": datetime.now().isoformat(),
                    "status": "error"
                }
            }
    
    def chat(self, message: str, context: str = "") -> str:
        if not self.is_available():
            return "AI chat not available. Please configure your Gemini API key in the .env file."
        
        system_prompt = """You are NeuraTrace AI, a cybersecurity teaching assistant integrated into the NeuraTrace dashboard.
You help learners understand network security concepts. When a user asks to perform an action:
- Acknowledge enthusiastically and guide them through the parameters needed
- Explain what each step does in simple terms suitable for learners
- Live Capture: Ask which network interface and how many packets
- Port Scanning: Ask for target IP and port range
- PCAP Analysis: Guide them to the Analyze tab"""

        full_prompt = f"{system_prompt}\n\n"
        if context:
            full_prompt += f"Current context: {context}\n\n"
        full_prompt += f"User: {message}\n\nAssistant:"
        
        try:
            response = self.model.generate_content(full_prompt)
            return response.text.strip()
        except Exception as e:
            logger.error(f"Chat error: {e}")
            return f"Sorry, I encountered an error: {str(e)}"
    
    def _get_unavailable_response(self, analysis_type: str) -> Dict:
        return {
            "error": "AI analysis not available",
            "reason": "API key not configured or google-generativeai not installed",
            "setup_instructions": [
                "1. Install: pip install google-generativeai",
                "2. Get API key from: https://makersuite.google.com/app/apikey",
                "3. Add to .env file: GEMINI_API_KEY=your_key_here"
            ],
            "_meta": {
                "analysis_type": analysis_type,
                "timestamp": datetime.now().isoformat(),
                "status": "unavailable"
            }
        }


def get_ai_analyzer(api_key: str = None) -> AIAnalyzer:
    return AIAnalyzer(api_key)
