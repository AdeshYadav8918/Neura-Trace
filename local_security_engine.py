import json
import re

class LocalSecurityEngine:
    def __init__(self):
        """
        100% Offline Heuristic Security Engine.
        Uses local dictionary-based signatures instead of NVD or external AI.
        """
        self.DANGEROUS_PORTS = {
            21: "FTP (Unencrypted File Transfer - Highly Vulnerable)",
            23: "Telnet (Unencrypted Remote Shell - Critical Risk)",
            80: "HTTP (Unencrypted Web Traffic - Prone to interception)",
            135: "RPC (Windows RPC - Historically vulnerable to worms)",
            139: "NetBIOS (Legacy Windows sharing - Prone to enumeration)",
            445: "SMB (Prone to EternalBlue / Ransomware propagation)",
            3389: "RDP (Remote Desktop - Prime target for brute-force)"
        }
        
        self.SUSPICIOUS_BANNERS = [
            "vsftpd 2.3.4", # Backdoored
            "ProFTPD 1.3.5", # Mod_copy RCE
            "OpenSSH 4.", # Weak cryptography
            "Windows XP", # EOL
            "IIS 6.0" # EOL
        ]

    def _generate_report(self, is_safe: bool, details: list, reason: str = ""):
        if is_safe:
            return f"[SAFE] {reason}"
        else:
            issues = "\n- ".join(details)
            return f"[UNSAFE]\n- {issues}"

    def analyze_live_capture(self, stdout_log: str) -> str:
        """Heuristically analyze raw strict PCAP stdout"""
        if not stdout_log.strip():
            return self._generate_report(True, [], "No traffic anomalies detected in capture.")
            
        anomalies = []
        lines = stdout_log.lower().split('\n')
        
        # Super basic local heuristic checks
        if sum(1 for line in lines if "syn" in line) > (len(lines) // 2) and len(lines) > 20:
            anomalies.append("Possible SYN Flood or rapid port scan detected (High SYN ratio).")
        
        if sum(1 for line in lines if "password" in line or "login" in line) > 0:
            anomalies.append("Plaintext authentication keywords detected in raw packet stream.")
            
        if anomalies:
            return self._generate_report(False, anomalies)
        return self._generate_report(True, [], "Traffic patterns appear standard.")

    def analyze_port_scan(self, port_data_str: str) -> str:
        """Analyze open ports mapping"""
        try:
            open_ports = json.loads(port_data_str)
        except:
            return self._generate_report(True, [], "No actionable port data.")
            
        risks = []
        for port_str in open_ports.keys():
            port_num = int(port_str)
            if port_num in self.DANGEROUS_PORTS:
                risks.append(f"Port {port_num} Open: {self.DANGEROUS_PORTS[port_num]}")
                
        if risks:
            risks.append("Remediation: Close unused ports or wrap in VPN/TLS immediately.")
            return self._generate_report(False, risks)
        return self._generate_report(True, [], "No inherently high-risk ports exposed.")

    def analyze_device_security(self, scan_data_str: str) -> str:
        """Deep device inspection offline"""
        try:
            data = json.loads(scan_data_str)
        except:
            return self._generate_report(True, [], "Invalid scan data.")
            
        services = data.get('services', [])
        anomalies = []
        
        for service in services:
            port = int(service['port'])
            banner = str(service.get('banner', ''))
            
            if port in self.DANGEROUS_PORTS:
                anomalies.append(f"Exposed Critical Protocol on Port {port}: {self.DANGEROUS_PORTS[port]}")
                
            for sus in self.SUSPICIOUS_BANNERS:
                if sus.lower() in banner.lower():
                    anomalies.append(f"Dangerous/Outdated Banner Detected: {sus} on port {port}.")
        
        if anomalies:
            return self._generate_report(False, anomalies)
        return self._generate_report(True, [], "Device baseline appears secure. No immediate legacy threats found.")

    def analyze_pcap_structure(self, pcap_summary_str: str) -> str:
        try:
            summary = json.loads(pcap_summary_str)
        except:
            return "[SAFE] Standard structure."
            
        anomalies = []
        if summary.get('total_packets', 0) > 10000 and len(summary.get('dest_ips', [])) < 3:
             anomalies.append("Abnormally high packet volume to very few destinations (Possible DoS/Flood).")
             
        if anomalies:
            return self._generate_report(False, anomalies)
        return self._generate_report(True, [], "PCAP architecture is consistent with normal traffic distribution.")
