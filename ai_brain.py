import os
import google.generativeai as genai

class AIBrain:
    def __init__(self, api_key=None):
        """
        Initializes the AI Brain using Google Gemini 1.5 Flash.
        Expects a valid Gemini API key.
        """
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
        else:
            self.model = None

    def is_available(self):
        return self.model is not None

    def _generate_strict_verdict(self, prompt: str) -> str:
        """Helper to enforce the [SAFE] / [UNSAFE] structure."""
        if not self.is_available():
            return "❌ AI Brain Offline. Please configure your Gemini API Key in Settings."
            
        system_rules = (
            "You are an expert, highly critical network security analyzer embedded inside the NeuraTrace platform. "
            "You will be given raw scan outputs, port maps, or packet capture logs. "
            "Your ONLY job is to respond with a security verdict. "
            "\n\CRITICAL RULES:\n"
            "1. You MUST start your response with EXACTLY ONE of these two tags: [SAFE] or [UNSAFE].\n"
            "2. If [UNSAFE], follow the tag with a bulleted, concise list of detected vulnerabilities, exactly what port/packet triggered it, and a remediation.\n"
            "3. If [SAFE], follow with a concise 1-sentence confirmation of why it appears secure.\n"
            "4. Never output markdown wrapping the tag (e.g. no **[SAFE]**), just raw text [SAFE] or [UNSAFE] at the very start."
        )

        full_prompt = f"{system_rules}\n\nDATA TO ANALYZE:\n{prompt}"
        
        try:
            response = self.model.generate_content(full_prompt)
            # Basic fallback if model hallucinates formatting
            text = response.text.strip()
            if not text.startswith("[SAFE]") and not text.startswith("[UNSAFE]"):
                if "UNSAFE" in text.upper():
                    return f"[UNSAFE]\n\n{text}"
                else:
                     return f"[SAFE]\n\n{text}"
            return text
        except Exception as e:
            return f"❌ AI Brain Error: Could not reach Google Gemini API. {str(e)}"

    def analyze_live_capture(self, stdout_log: str) -> str:
        """Analyzes stdout from a raw packet capture."""
        if not stdout_log.strip():
            return "[SAFE] No packets captured to analyze."
            
        prompt = f"Analyze this live packet capture stdout log for any malicious traffic patterns (e.g., rapid port scanning, unencrypted text, excessive syns):\n\n{stdout_log}"
        return self._generate_strict_verdict(prompt)

    def analyze_port_scan(self, stdout_log: str) -> str:
        """Analyzes Nmap/socket open port scan results."""
        if not stdout_log.strip():
             return "[SAFE] No open ports or scan data to analyze."
             
        prompt = f"Analyze this port scan log. Identify any dangerously exposed ports (like 21, 23, 3389) or suspicious services:\n\n{stdout_log}"
        return self._generate_strict_verdict(prompt)
        
    def analyze_device_security(self, scan_data: str, cve_list: list) -> str:
        """Analyzes device security including discovered CVEs."""
        prompt = f"Analyze this device scan data:\n{scan_data}\n\nKnown CVEs discovered on services:\n{cve_list}\n"
        prompt += "\nDetermine if this device represents an immediate risk."
        return self._generate_strict_verdict(prompt)

    def analyze_pcap_structure(self, pcap_summary: dict) -> str:
        """Analyzes structured pyshark PCAP data dictionary."""
        prompt = f"Analyze this parsed PCAP traffic summary for malware signatures or covert channels:\n{pcap_summary}"
        return self._generate_strict_verdict(prompt)
