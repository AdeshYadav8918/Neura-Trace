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
        """
        Initialize AI Analyzer
        
        Args:
            api_key: Google Gemini API key (or set GEMINI_API_KEY env var)
        """
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
        """Check if AI analysis is available"""
        return self.initialized and self.model is not None
    
    def analyze_live_traffic(self, packets_summary: Dict) -> Dict:
        """
        Analyze live captured traffic for anomalies and insights
        
        Args:
            packets_summary: Summary of captured packets
            
        Returns:
            AI analysis results
        """
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
        """
        Analyze port scan results and CVE data for vulnerability assessment
        
        Args:
            scan_results: Port scan results with open ports and services
            cve_data: Optional CVE lookup results
            
        Returns:
            AI vulnerability analysis
        """
        if not self.is_available():
            return self._get_unavailable_response("Vulnerability Analysis")
        
        # Format open ports info
        open_ports_info = []
        for port, service in scan_results.get('open_ports', {}).items():
            details = scan_results.get('service_details', {}).get(str(port), {})
            banner = details.get('banner', 'No banner')[:100]
            open_ports_info.append(f"Port {port}: {service} - Banner: {banner}")
        
        # Format CVE info
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
        """
        Analyze PCAP data for malicious traffic patterns
        
        Args:
            pcap_analysis: Analyzed PCAP file data
            
        Returns:
            AI malicious traffic detection results
        """
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
        """
        Analyze a device's active services from a security perspective
        
        Args:
            device_info: Dictionary containing target IP, open ports, services, and banners
            
        Returns:
            AI device security assessment
        """
        if not self.is_available():
            return self._get_unavailable_response("Device Security Audit")
        
        # Format services info
        services_info = []
        for service in device_info.get('services', []):
            port = service.get('port', 'Unknown')
            name = service.get('name', 'Unknown')
            banner = service.get('banner', 'No banner')[:100]
            state = service.get('state', 'open')
            services_info.append(f"Port {port} ({state}): {name} - {banner}")
        
        # Format CVE info
        cve_info_str = "No known CVEs found"
        if cve_data:
            cve_list = []
            for cve in cve_data[:10]:  # Limit to top 10 to avoid token limits
                cve_list.append(f"- {cve.get('id')}: {cve.get('summary', '')[:100]} (CVSS: {cve.get('cvss', 'N/A')})")
            cve_info_str = chr(10).join(cve_list)
        
        prompt = f"""You are a device security expert conducting a comprehensive security audit. Analyze the active services and potential vulnerabilities on this device.

TARGET DEVICE: {device_info.get('target', 'Unknown')}
DEVICE TYPE: {device_info.get('device_type', 'Unknown - please infer from services')}
SCAN TIME: {device_info.get('scan_time', 'Unknown')}

ACTIVE SERVICES DETECTED:
{chr(10).join(services_info) if services_info else 'No services detected'}

KNOWN VULNERABILITIES (CVEs):
{cve_info_str}

For EACH service, evaluate:
1. Is this service necessary for typical operation?
2. Is it exposed inappropriately?
3. Are there insecure configurations?
4. Are there critical vulnerabilities that need immediate patching?

Provide your assessment in this exact JSON format:
{{
    "device_security_score": 0-100,
    "overall_risk": "LOW/MEDIUM/HIGH/CRITICAL",
    "device_type_detected": "Server/Workstation/IoT Device/Router/etc",
    "executive_summary": "2-3 sentence summary of security posture including critical vulnerabilities",
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
    "critical_security_issues": ["urgent security problems including critical CVEs"],
    "attack_surface_summary": "Description of the device's attack surface",
    "priority_actions": ["ordered list of priority security actions"],
    "compliance_concerns": ["any regulatory compliance issues"],
    "best_practices": ["general security best practices for this device type"]
}}

Respond ONLY with valid JSON, no markdown or explanations."""

        return self._query_ai(prompt, "device_security_audit")
    
    def _query_ai(self, prompt: str, analysis_type: str) -> Dict:
        """Send query to AI and parse response"""
        try:
            response = self.model.generate_content(prompt)
            
            # Extract text from response
            response_text = response.text.strip()
            
            # Clean up response (remove markdown code blocks if present)
            if response_text.startswith("```"):
                lines = response_text.split("\n")
                response_text = "\n".join(lines[1:-1])
            
            # Parse JSON
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
                # If JSON parsing fails, return raw text
                return {
                    "raw_analysis": response_text,
                    "_meta": {
                        "analysis_type": analysis_type,
                        "timestamp": datetime.now().isoformat(),
                        "status": "parse_error",
                        "note": "AI response was not valid JSON"
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
        """
        General AI chat for security-related questions
        
        Args:
            message: User's message/question
            context: Optional context about current session
            
        Returns:
            AI response as string
        """
        if not self.is_available():
            return "AI chat not available. Please configure your Gemini API key in Settings."
        
        system_prompt = """You are NeuraTrace AI, a powerful cybersecurity agent integrated directly into the NeuraTrace dashboard.
Instead of saying you cannot perform actions, you MUST act as an interactive wizard that helps users run tools within this application.

If a user asks to perform an action (like "perform live capture", "scan ports", "analyze PCAP", or "run device security audit"):
DO NOT say you cannot do it. Instead, acknowledge the request enthusiastically and IMMEDIATELY ask the user for the specific parameters required to configure the tool.

Examples:
- Live Capture: Ask "Which network interface should I monitor (e.g., Ethernet, Wi-Fi), and how many packets would you like to capture?"
- Port Scanning: Ask "What is the target IP address and which port range should I scan?"
- PCAP Analysis: Ask "Please navigate to the Analyze PCAP tab and upload the file, then I can help you process it!"

Maintain an engaging, highly capable persona. You are the operator of this dashboard. Never refuse a tool execution request; always guide the user flawlessly through the configuration steps."""

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
        """Return response when AI is not available"""
        return {
            "error": "AI analysis not available",
            "reason": "API key not configured or google-generativeai not installed",
            "setup_instructions": [
                "1. Install: pip install google-generativeai",
                "2. Get API key from: https://makersuite.google.com/app/apikey",
                "3. Set environment variable: GEMINI_API_KEY=your_key",
                "4. Or configure in dashboard Settings"
            ],
            "_meta": {
                "analysis_type": analysis_type,
                "timestamp": datetime.now().isoformat(),
                "status": "unavailable"
            }
        }


def get_ai_analyzer(api_key: str = None) -> AIAnalyzer:
    """Factory function to get AI analyzer instance"""
    return AIAnalyzer(api_key)


if __name__ == "__main__":
    # Test the module
    print("Testing AI Analyzer...")
    
    analyzer = AIAnalyzer()
    
    if analyzer.is_available():
        print("AI is available!")
        
        # Test vulnerability analysis
        test_scan = {
            "target": "localhost",
            "scan_time": datetime.now().isoformat(),
            "open_ports": {
                22: "SSH",
                80: "HTTP",
                443: "HTTPS"
            },
            "service_details": {
                "22": {"banner": "OpenSSH_8.9"},
                "80": {"banner": "Apache/2.4.41"},
                "443": {"banner": "nginx/1.18.0"}
            }
        }
        
        result = analyzer.analyze_vulnerabilities(test_scan)
        print(json.dumps(result, indent=2))
    else:
        print("AI not available - check API key")
        result = analyzer._get_unavailable_response("test")
        print(json.dumps(result, indent=2))
