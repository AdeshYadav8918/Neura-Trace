import pyshark
import logging
import psutil
import argparse
import json
import os
import sys
import re
from datetime import datetime
from typing import Optional, Dict, Any, List, Union
from scapy.all import sniff, wrpcap
import socket
import concurrent.futures
import platform
import subprocess
import ipaddress
import getpass
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PortScanner:
    def __init__(self, timeout=1.0, max_workers=100):
        self.timeout = timeout
        self.max_workers = max_workers
        self.scan_count = 0
        self.last_scan_time = None
        
        # Rate limiting
        self.MAX_PORTS_PER_DAY = 65535
        self.MIN_TIME_BETWEEN_SCANS = 1.0
        
        # Vulnerable services database (for security analysis)
        self.vulnerable_services_db = self._load_vulnerable_services_db()
    
    def _load_vulnerable_services_db(self):
        """Load database of potentially vulnerable services"""
        return {
            21: {"name": "FTP", "risk": "High", "recommendation": "Use SFTP/FTPS instead"},
            22: {"name": "SSH", "risk": "Medium", "recommendation": "Update OpenSSH, disable root login"},
            23: {"name": "Telnet", "risk": "Critical", "recommendation": "DISABLE - Use SSH instead"},
            25: {"name": "SMTP", "risk": "Medium", "recommendation": "Enable encryption, use authentication"},
            53: {"name": "DNS", "risk": "Low", "recommendation": "Use DNSSEC, keep updated"},
            80: {"name": "HTTP", "risk": "Medium", "recommendation": "Use HTTPS, keep web server updated"},
            110: {"name": "POP3", "risk": "High", "recommendation": "Use POP3S with encryption"},
            139: {"name": "NetBIOS", "risk": "High", "recommendation": "Disable if not needed"},
            143: {"name": "IMAP", "risk": "Medium", "recommendation": "Use IMAPS with encryption"},
            443: {"name": "HTTPS", "risk": "Low", "recommendation": "Keep certificates updated"},
            445: {"name": "SMB", "risk": "Critical", "recommendation": "Disable SMBv1, enable signing"},
            3389: {"name": "RDP", "risk": "High", "recommendation": "Use VPN, enable Network Level Auth"},
            5900: {"name": "VNC", "risk": "High", "recommendation": "Use SSH tunneling or VPN"},
            8080: {"name": "HTTP-Alt", "risk": "Medium", "recommendation": "Use HTTPS, keep updated"},
            27017: {"name": "MongoDB", "risk": "High", "recommendation": "Enable authentication"},
            3306: {"name": "MySQL", "risk": "High", "recommendation": "Use strong passwords, update regularly"},
            5432: {"name": "PostgreSQL", "risk": "Medium", "recommendation": "Enable SSL, use authentication"},
            6379: {"name": "Redis", "risk": "Critical", "recommendation": "Enable auth, bind to localhost"}
        }
    
    def _check_scan_limit(self, num_ports):
        """Check if scan exceeds limits"""
        # Check daily limit
        if self.scan_count + num_ports > self.MAX_PORTS_PER_DAY:
            logging.warning(f"Daily scan limit reached ({self.MAX_PORTS_PER_DAY} ports)")
            return False
        
        # Check rate limiting
        if self.last_scan_time:
            time_since_last = (datetime.now() - self.last_scan_time).total_seconds()
            if time_since_last < self.MIN_TIME_BETWEEN_SCANS:
                logging.warning(f"Scan too fast. Wait {self.MIN_TIME_BETWEEN_SCANS}s between scans.")
                return False
        
        return True
    
    def _validate_target_ip(self, ip):
        """Validate target IP is allowed"""
        # Always allow localhost
        if ip in ['localhost', '127.0.0.1', '::1']:
            return True
        
        # Check if it's a valid IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Private IPs are always allowed
            if ip_obj.is_private:
                return True
            
            # For public IPs, check if running interactively
            import sys
            if not sys.stdin.isatty():
                # Non-interactive mode (e.g., called from Streamlit)
                # Allow the scan - user accepted terms via dashboard
                logging.info(f"Scanning public IP {ip} in non-interactive mode")
                return True
            else:
                # Interactive mode - require confirmation
                print(f"⚠️ Warning: Scanning public IP: {ip}")
                response = input("Are you authorized to scan this IP? (yes/no): ").strip().lower()
                return response == 'yes'
        except ValueError:
            # Not a valid IP address
            logging.error(f"Invalid IP address: {ip}")
            return False
        except Exception as e:
            logging.error(f"Error validating IP {ip}: {e}")
            return False
    
    # FIXED: Added Union[Dict, str] return type to fix Pylance errors on lines 149 and 151
    def scan_ports_with_services(self, target_ip: str, ports: Optional[List[int]] = None, 
                                analyze_security: bool = False, output_format="human") -> Union[Dict, str]:
        """Scan ports and identify services with optional security analysis"""
        
        # Resolve hostname once to avoid DNS spam and timeouts across threads
        try:
            target_ip_resolved = socket.gethostbyname(target_ip)
        except socket.gaierror:
            logging.error(f"Could not resolve hostname: {target_ip}")
            return {"error": f"Could not resolve hostname: {target_ip}"}
        
        # Check limits
        if ports and not self._check_scan_limit(len(ports)):
            logging.error("Scan limit exceeded. Check authorization.")
            return {"error": "Scan limit exceeded"}
        
        if not self._validate_target_ip(target_ip):
            logging.error(f"Invalid or unauthorized target: {target_ip}")
            return {"error": "Invalid or unauthorized target"}
        
        if ports is None:
            ports = list(range(1, 1025))  # Common ports
        
        open_ports = {}
        service_details = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.check_port_with_details, target_ip_resolved, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    result = future.result(timeout=self.timeout)
                    if result and result['status'] == 'open':
                        open_ports[port] = result['service']
                        service_details[port] = result
                except Exception:
                    pass
        
        # Update scan count
        self.scan_count += len(ports)
        self.last_scan_time = datetime.now()
        
        # Generate results
        result = {
            "target": target_ip,
            "resolved_ip": target_ip_resolved,
            "scan_time": datetime.now().isoformat(),
            "open_ports": open_ports,
            "service_details": service_details,
            "total_ports_scanned": len(ports),
            "open_count": len(open_ports)
        }
        
        # Add security analysis if requested
        if analyze_security:
            security_analysis = self._analyze_services_security(service_details)
            result["security_analysis"] = security_analysis
            result["security_score"] = security_analysis.get("security_score", 0)
            result["risk_level"] = security_analysis.get("risk_level", "Unknown")
        
        if output_format == "json":
            return json.dumps(result, indent=2)
        else:
            return self._format_scan_results(result, analyze_security)
    
    def check_port_with_details(self, ip: str, port: int) -> Dict:
        """Check if a port is open and get detailed service information"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                # Use a more generous timeout for organizational networks
                sock.settimeout(2.0)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    # Port is open, get detailed information using the ALREADY ESTABLISHED connection
                    service_info = self._get_detailed_service_info_with_sock(sock, ip, port)
                    
                    # Get process information if it's the local machine
                    process_info = {}
                    if ip in ['127.0.0.1', '::1', socket.gethostbyname('localhost')]:
                        process_info = self._get_process_info_for_port(port)
                    
                    return {
                        "status": "open",
                        "port": port,
                        "service": service_info.get("name", "Unknown"),
                        "version": service_info.get("version", "Unknown"),
                        "banner": service_info.get("banner", ""),
                        "protocol": service_info.get("protocol", "TCP"),
                        "process_info": process_info,
                        "timestamp": datetime.now().isoformat()
                    }
                else:
                    return {"status": "closed", "port": port}
        except Exception as e:
            return {"status": "error", "port": port, "details": str(e)}
    
    def _get_detailed_service_info_with_sock(self, sock: socket.socket, ip: str, port: int) -> Dict:
        """Get detailed service information including banner using an actively connected socket"""
        service_info = {
            "name": self.identify_service(port),
            "version": "Unknown",
            "banner": "",
            "protocol": "TCP"
        }
        
        # Try to get banner directly using the already connected socket
        try:
            # Set a shorter timeout specifically for banner grabbing
            sock.settimeout(1.5)
            
            # Send appropriate probe based on port to elicit a response
            if port in [80, 8080]:
                sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 443:
                sock.sendall(b'\x16\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00') # ClientHello
            elif port == 21:
                pass # FTP sends banner automatically
            elif port == 22:
                pass # SSH sends banner automatically
            else:
                sock.sendall(b'\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info["banner"] = banner[:200]  # Limit banner length
            
            # Extract version from banner
            if "Apache" in banner:
                service_info["name"] = "Apache HTTP Server"
                version_match = re.search(r'Apache/([\d\.]+)', banner)
                if version_match:
                    service_info["version"] = version_match.group(1)
            elif "nginx" in banner.lower():
                service_info["name"] = "nginx"
                version_match = re.search(r'nginx/([\d\.]+)', banner)
                if version_match:
                    service_info["version"] = version_match.group(1)
            elif "SSH" in banner:
                service_info["name"] = "SSH"
                version_match = re.search(r'SSH-([\d\.]+)', banner)
                if version_match:
                    service_info["version"] = version_match.group(1)
                    
        except Exception:
            pass # Ignore banner grabbing timeouts and connection reset errors
        
        return service_info
    
    def _get_process_info_for_port(self, port: int) -> Dict:
        """Get process information for a local port"""
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.laddr and conn.laddr.port == port and conn.status == 'LISTEN':
                    try:
                        proc = psutil.Process(conn.pid)
                        return {
                            "pid": conn.pid,
                            "name": proc.name(),
                            "cmdline": ' '.join(proc.cmdline()) if proc.cmdline() else "",
                            "username": proc.username(),
                            "status": proc.status()
                        }
                    except:
                        return {"pid": conn.pid, "name": "Unknown"}
        except:
            pass
        return {}
    
    def identify_service(self, port: int) -> str:
        """Identify service by port number"""
        common_services = {
            20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
            27017: "MongoDB", 5900: "VNC", 9200: "Elasticsearch", 11211: "Memcached",
            2049: "NFS", 873: "rsync", 514: "syslog", 161: "SNMP",
            389: "LDAP", 636: "LDAPS", 1433: "MSSQL", 1521: "Oracle DB"
        }
        return common_services.get(port, f"Service on port {port}")
    
    def _analyze_services_security(self, service_details: Dict) -> Dict:
        """Analyze security of discovered services"""
        vulnerabilities = []
        recommendations = []
        total_risk = 0
        max_risk = 0
        
        for port, details in service_details.items():
            service_name = details.get("service", "")
            banner = details.get("banner", "")
            
            # Check against vulnerable services database
            if port in self.vulnerable_services_db:
                vuln_info = self.vulnerable_services_db[port]
                
                risk_score = self._get_risk_score(vuln_info["risk"])
                total_risk += risk_score
                max_risk += 100  # Max risk per service
                
                vulnerability = {
                    "port": port,
                    "service": service_name,
                    "risk": vuln_info["risk"],
                    "risk_score": risk_score,
                    "recommendation": vuln_info["recommendation"],
                    "details": f"Known {vuln_info['name']} service on port {port}"
                }
                vulnerabilities.append(vulnerability)
                recommendations.append(vuln_info["recommendation"])
            
            # Additional security checks based on banner
            if banner:
                # Check for outdated versions
                outdated_indicators = [
                    ("Apache/2.2", "Apache 2.2 is outdated"),
                    ("Apache/2.4.0", "Apache 2.4.0 has known vulnerabilities"),
                    ("OpenSSH_7.", "OpenSSH 7.x has known issues"),
                    ("nginx/1.0", "nginx 1.0 is very old")
                ]
                
                for indicator, message in outdated_indicators:
                    if indicator in banner:
                        vulnerability = {
                            "port": port,
                            "service": service_name,
                            "risk": "High",
                            "risk_score": 70,
                            "recommendation": f"Update {service_name} to latest version",
                            "details": message
                        }
                        vulnerabilities.append(vulnerability)
                        break
        
        # Calculate security score (0-100, higher is better)
        if max_risk > 0:
            security_score = 100 - int((total_risk / max_risk) * 100)
        else:
            security_score = 100
        
        # Determine risk level
        if security_score >= 80:
            risk_level = "Low"
        elif security_score >= 60:
            risk_level = "Medium"
        elif security_score >= 40:
            risk_level = "High"
        else:
            risk_level = "Critical"
        
        return {
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "recommendations": list(set(recommendations)),  # Remove duplicates
            "security_score": security_score,
            "risk_level": risk_level,
            "total_risk": total_risk
        }
    
    def _get_risk_score(self, risk_level: str) -> int:
        """Convert risk level to score"""
        scores = {"Critical": 90, "High": 70, "Medium": 50, "Low": 30}
        return scores.get(risk_level, 0)
    
    def _format_scan_results(self, results: Dict, analyze_security: bool) -> str:
        """Format scan results for human-readable output"""
        output = []
        output.append("=" * 70)
        output.append(f"PORT SCAN WITH SERVICE DETECTION - {results['target']}")
        output.append("=" * 70)
        
        open_ports = results.get("open_ports", {})
        total_scanned = results.get("total_ports_scanned", 0)
        open_count = results.get("open_count", 0)
        
        output.append(f"\n📊 SCAN SUMMARY:")
        output.append("-" * 40)
        output.append(f"Target: {results['target']}")
        output.append(f"Scan Range: 1-{total_scanned}")
        output.append(f"Open Ports: {open_count}/{total_scanned}")
        output.append(f"Scan Time: {results.get('scan_time', 'N/A')}")
        
        if open_ports:
            output.append(f"\n🔓 OPEN PORTS WITH SERVICES:")
            output.append("-" * 40)
            
            # Sort by port number
            sorted_ports = sorted(open_ports.items())
            for port, service in sorted_ports:
                port_details = results.get("service_details", {}).get(port, {})
                banner = port_details.get("banner", "")
                process_info = port_details.get("process_info", {})
                
                output.append(f"\nPort {port}: {service}")
                
                if banner:
                    output.append(f"  Banner: {banner[:50]}...")
                
                if process_info and process_info.get("name") != "Unknown":
                    output.append(f"  Process: {process_info.get('name', 'Unknown')} (PID: {process_info.get('pid', 'N/A')})")
                    if process_info.get("cmdline"):
                        output.append(f"  Command: {process_info.get('cmdline', '')[:60]}...")
        else:
            output.append(f"\n🚫 No open ports found")
        
        # Security analysis section
        if analyze_security and "security_analysis" in results:
            security = results["security_analysis"]
            output.append(f"\n🛡️ SECURITY ANALYSIS:")
            output.append("-" * 40)
            output.append(f"Security Score: {security.get('security_score', 0)}/100")
            output.append(f"Risk Level: {security.get('risk_level', 'Unknown')}")
            output.append(f"Vulnerabilities Found: {security.get('vulnerabilities_found', 0)}")
            
            vulnerabilities = security.get("vulnerabilities", [])
            if vulnerabilities:
                output.append(f"\n⚠️  POTENTIAL SECURITY ISSUES:")
                for i, vuln in enumerate(vulnerabilities, 1):
                    output.append(f"\n{i}. {vuln.get('service', 'Unknown')} on port {vuln.get('port', 'N/A')}")
                    output.append(f"   Risk: {vuln.get('risk', 'Unknown')}")
                    output.append(f"   Recommendation: {vuln.get('recommendation', 'N/A')}")
            
            recommendations = security.get("recommendations", [])
            if recommendations:
                output.append(f"\n🎯 RECOMMENDATIONS:")
                for i, rec in enumerate(recommendations[:5], 1):
                    output.append(f"  {i}. {rec}")
                if len(recommendations) > 5:
                    output.append(f"     ... and {len(recommendations) - 5} more")
        
        output.append("\n" + "=" * 70)
        output.append("💡 TIP: Regular port scanning helps maintain network security.")
        
        return "\n".join(output)


class PacketAnalyzer:
    def __init__(self):
        # Display legal warning
        self._check_authorization()
        self._display_legal_warning()
        
        self.captured_packets = []
        self.capture_stats = {
            'start_time': None,
            'end_time': None,
            'total_packets': 0,
            'protocols': set(),
            'interfaces_used': set()
        }
        self.port_scanner = PortScanner()
    
    def _check_authorization(self):
        """Check if user has authorization to scan"""
        user = getpass.getuser()
        
        # Log usage
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'tool': 'NeuraTrace',
            'action': 'initialized'
        }
        
        # Save local log
        os.makedirs('saved_scans', exist_ok=True)
        with open('saved_scans/neura_trace_usage.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def _display_legal_warning(self):
        """Display legal warning to user"""
        # Check if running in interactive mode first
        import sys
        if not sys.stdin.isatty():
            # Non-interactive mode (e.g., called from Streamlit), skip prompt
            return
        
        warning = """
        ============================================================
                            LEGAL NOTICE                           
        ============================================================
          NEURA TRACE - NETWORK ANALYSIS TOOL                      
                                                                   
          WARNING: Unauthorized use of this tool may violate:      
          - Computer Fraud and Abuse Act (CFAA)                    
          - Local cybersecurity laws                               
          - Terms of Service of monitored networks                 
                                                                   
          BY USING THIS TOOL YOU CONFIRM:                          
          1. Written authorization to test target networks         
          2. Legal right to capture/analyze network traffic        
          3. Compliance with all applicable laws                   
                                                                   
          For authorized security testing only.                    
          Report vulnerabilities responsibly.                      
        ============================================================
        """
        print(warning)
        
        # Ask for confirmation
        try:
            response = input("Do you accept these terms? (yes/no): ").strip().lower()
            if response != 'yes':
                print("Exiting...")
                sys.exit(0)
        except (EOFError, OSError):
            pass  # Continue if running in non-interactive mode
    
    def scan_with_service_detection(self, target_ip="localhost", start_port=1, end_port=1024, 
                                   analyze_security=False, output_format="human"):
        """Scan ports with integrated service detection"""
        try:
            ports = list(range(start_port, end_port + 1))
            result = self.port_scanner.scan_ports_with_services(target_ip, ports, analyze_security, output_format)
            return result
        except Exception as e:
            error_msg = f"Scan failed: {e}"
            logging.error(error_msg)
            if output_format == "json":
                return json.dumps({"error": error_msg}, indent=2)
            else:
                return error_msg
    
    def packet_callback(self, packet):
        """Callback for each captured packet"""
        self.captured_packets.append(packet)
        print(packet.summary())
        
        # Update stats
        self.capture_stats['total_packets'] += 1
        if hasattr(packet, 'payload'):
            self.capture_stats['protocols'].add(packet.payload.name)
    
    def capture_packets(self, interface="eth0", count=100, filter="", output_file="captured_packets.pcap"):
        """Capture packets from specified interface"""
        logging.info(f"Starting packet capture on {interface} with filter {filter}")
        self.capture_stats['start_time'] = datetime.now().isoformat()
        self.capture_stats['interfaces_used'].add(interface)
        
        try:
            packets = sniff(iface=interface, count=count, filter=filter, prn=self.packet_callback)
            wrpcap(output_file, packets)
            
            self.capture_stats['end_time'] = datetime.now().isoformat()
            self.capture_stats['protocols'] = list(self.capture_stats['protocols'])
            self.capture_stats['interfaces_used'] = list(self.capture_stats['interfaces_used'])
            
            logging.info(f"Packet capture complete. {len(packets)} packets captured.")
            
            # Save capture metadata
            self.save_capture_metadata(output_file)
            
            return True, len(packets), self.capture_stats
        except Exception as e:
            logging.error(f"Error capturing packets: {e}")
            return False, 0, {}
    
    def save_capture_metadata(self, output_file):
        """Save capture metadata as JSON"""
        metadata_file = output_file.replace('.pcap', '_metadata.json')
        metadata = {
            'filename': output_file,
            'capture_stats': self.capture_stats,
            'timestamp': datetime.now().isoformat(),
            'packet_count': len(self.captured_packets)
        }
        
        try:
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            logging.info(f"Metadata saved to {metadata_file}")
        except Exception as e:
            logging.error(f"Error saving metadata: {e}")
    
    def analyze_packets(self, pcap_file, output_format="human"):
        """Analyze packets from a PCAP file"""
        try:
            cap = pyshark.FileCapture(pcap_file)
            analysis_results = {
                'packets': [],
                'summary': {
                    'total_packets': 0,
                    'protocols': set(),
                    'source_ips': set(),
                    'dest_ips': set()
                }
            }
            
            for packet in cap:
                analysis_results['summary']['total_packets'] += 1
                
                if hasattr(packet, 'ip'):
                    analysis_results['summary']['source_ips'].add(packet.ip.src)
                    analysis_results['summary']['dest_ips'].add(packet.ip.dst)
                
                if hasattr(packet, 'highest_layer'):
                    analysis_results['summary']['protocols'].add(packet.highest_layer)
            
            # Convert sets to lists for JSON serialization
            analysis_results['summary']['protocols'] = list(analysis_results['summary']['protocols'])
            analysis_results['summary']['source_ips'] = list(analysis_results['summary']['source_ips'])
            analysis_results['summary']['dest_ips'] = list(analysis_results['summary']['dest_ips'])
            
            if output_format == "json":
                return json.dumps(analysis_results, indent=2)
            else:
                return self._format_analysis_human(analysis_results)
                
        except Exception as e:
            error_msg = f"Error analyzing packets: {e}"
            logging.error(error_msg)
            if output_format == "json":
                return json.dumps({"error": error_msg}, indent=2)
            else:
                return error_msg
    
    def _format_analysis_human(self, analysis_data):
        """Format analysis data for human-readable output"""
        output = []
        output.append("=" * 60)
        output.append("PCAP FILE ANALYSIS")
        output.append("=" * 60)
        
        summary = analysis_data.get('summary', {})
        
        output.append(f"\nSUMMARY:")
        output.append("-" * 40)
        output.append(f"Total Packets: {summary.get('total_packets', 0)}")
        
        protocols = summary.get('protocols', [])
        if protocols:
            output.append(f"Protocols Found ({len(protocols)}): {', '.join(protocols)}")
        else:
            output.append("No protocols identified")
        
        source_ips = summary.get('source_ips', [])
        if source_ips:
            output.append(f"\nSource IPs ({len(source_ips)}):")
            for ip in list(source_ips)[:10]:  # Show first 10
                output.append(f"  • {ip}")
            if len(source_ips) > 10:
                output.append(f"  ... and {len(source_ips) - 10} more")
        
        dest_ips = summary.get('dest_ips', [])
        if dest_ips:
            output.append(f"\nDestination IPs ({len(dest_ips)}):")
            for ip in list(dest_ips)[:10]:  # Show first 10
                output.append(f"  • {ip}")
            if len(dest_ips) > 10:
                output.append(f"  ... and {len(dest_ips) - 10} more")
        
        output.append("\n" + "=" * 60)
        
        return "\n".join(output)
    
    def _format_interfaces_human(self, interfaces):
        """Format interfaces data for human-readable output"""
        output = []
        output.append("=" * 60)
        output.append("NETWORK INTERFACES")
        output.append("=" * 60)
        
        if interfaces:
            for interface, addrs in interfaces.items():
                output.append(f"\n{interface}:")
                output.append("-" * 30)
                for addr in addrs:
                    output.append(f"  Family: {addr.get('family', 'N/A')}")
                    output.append(f"  Address: {addr.get('address', 'N/A')}")
                    if addr.get('netmask'):
                        output.append(f"  Netmask: {addr.get('netmask')}")
                    if addr.get('broadcast'):
                        output.append(f"  Broadcast: {addr.get('broadcast')}")
                    output.append("")
        else:
            output.append("No network interfaces found")
        
        output.append("=" * 60)
        
        return "\n".join(output)
    
    def list_network_interfaces(self, output_format="human"):
        """List all available network interfaces"""
        try:
            interfaces = psutil.net_if_addrs()
            interface_details = {}
            
            for interface, addrs in interfaces.items():
                interface_details[interface] = []
                for addr in addrs:
                    interface_details[interface].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask if addr.netmask else None,
                        'broadcast': addr.broadcast if addr.broadcast else None
                    })
            
            if output_format == "json":
                return json.dumps(interface_details, indent=2)
            else:
                return self._format_interfaces_human(interface_details)
                
        except Exception as e:
            error_msg = f"Error listing network interfaces: {e}"
            logging.error(error_msg)
            if output_format == "json":
                return json.dumps({"error": error_msg}, indent=2)
            else:
                return error_msg
    
    def get_dashboard_data(self):
        """Get data formatted for dashboard display"""
        return {
            'capture_stats': self.capture_stats,
            'recent_captures': len(self.captured_packets),
            'protocols_identified': list(self.capture_stats.get('protocols', [])),
            'capture_duration': self._calculate_capture_duration()
        }
    
    def _calculate_capture_duration(self):
        """Calculate duration of capture"""
        if self.capture_stats['start_time'] and self.capture_stats['end_time']:
            try:
                start = datetime.fromisoformat(self.capture_stats['start_time'].replace('Z', '+00:00'))
                end = datetime.fromisoformat(self.capture_stats['end_time'].replace('Z', '+00:00'))
                duration = end - start
                return duration.total_seconds()
            except (ValueError, TypeError, AttributeError):
                return 0
        return 0

def main():
    import sys
    # Force UTF-8 encoding for standard output to handle emojis safely on Windows
    sys.stdout.reconfigure(encoding='utf-8')
    
    parser = argparse.ArgumentParser(
        description="Neura Trace - Network Analysis with Integrated Port & Service Scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        LEGAL NOTICE:
        ------------
        This tool is for authorized security testing only.
        Unauthorized use may violate laws including:
        - Computer Fraud and Abuse Act (CFAA)
        - Local cybersecurity regulations
        - Network Terms of Service
        
        Use responsibly and only on networks you own or have
        explicit written permission to test.
        """
    )
    
    # Capture arguments
    parser.add_argument('-i', '--interface', type=str, help="Network interface to capture packets from")
    parser.add_argument('-p', '--protocol', type=str, help="Protocol to filter (e.g., TCP, UDP, HTTP)")
    parser.add_argument('-c', '--count', type=int, default=100, help="Number of packets to capture")
    parser.add_argument('-o', '--output', type=str, default="saved_scans/captured_packets.pcap", help="Output file")
    
    # Analysis arguments
    parser.add_argument('--list_interfaces', action='store_true', help="List available network interfaces")
    parser.add_argument('--analyze', type=str, help="Analyze existing PCAP file")
    
    # Port scanning with integrated service detection
    parser.add_argument('--scan', type=str, help="Scan target IP for open ports with service detection")
    parser.add_argument('--ports', type=str, default="1-1024", help="Port range (e.g., 1-1000)")
    parser.add_argument('--analyze-security', action='store_true', help="Include security analysis in scan")
    
    # Output format
    parser.add_argument('--json', action='store_true', help="Output in JSON format (for dashboard)")
    
    # Debug
    parser.add_argument('--debug', action='store_true', help="Enable debug mode")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Fix: Correct attribute name from analyze_security to analyze-security
    analyze_security_flag = getattr(args, 'analyze_security', False)
    
    # Security check for public IP scans
    if args.scan and args.scan not in ['localhost', '127.0.0.1', '::1']:
        try:
            target_ip = args.scan
            ip_obj = ipaddress.ip_address(target_ip)
            if not ip_obj.is_private:
                print(f"\n⚠️  WARNING: Scanning public IP address: {target_ip}")
                print("This may be illegal without explicit authorization.")
                confirm = input("Do you have permission to scan this IP? (yes/no): ")
                if confirm.lower() != 'yes':
                    print("Scan aborted.")
                    sys.exit(1)
        except ValueError:
            pass  # Not a valid IP, might be hostname
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    analyzer = PacketAnalyzer()
    
    # Determine output format
    output_format = "json" if args.json else "human"
    
    # Handle port scanning with integrated service detection
    if args.scan:
        logging.info(f"Scanning {args.scan} with service detection...")
        try:
            start_port, end_port = map(int, args.ports.split('-'))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                print("ERROR: Invalid port range. Use 1-65535 and start < end")
                sys.exit(1)
            
            results = analyzer.scan_with_service_detection(
                args.scan, 
                start_port, 
                end_port, 
                analyze_security_flag,
                output_format
            )
            print(results)
            
        except ValueError as e:
            print(f"ERROR: Invalid port format or value error: {e}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            sys.exit(1)
        return
    
    # Handle interface listing
    if args.list_interfaces:
        logging.info("Listing Network Interfaces:")
        results = analyzer.list_network_interfaces(output_format)
        print(results)
        return
    
    # Handle PCAP analysis
    if args.analyze:
        logging.info(f"Analyzing PCAP file: {args.analyze}")
        results = analyzer.analyze_packets(args.analyze, output_format)
        print(results)
        return
    
    # Handle packet capture
    if args.interface and args.count:
        logging.info(f"Capturing {args.count} packets on {args.interface}")
        success, packet_count, stats = analyzer.capture_packets(
            interface=args.interface,
            count=args.count,
            filter=args.protocol if args.protocol else "",
            output_file=args.output
        )
        
        if success:
            if output_format == "json":
                result_json = {
                    "success": True,
                    "output_file": args.output,
                    "statistics": {
                        "total_packets": stats['total_packets'],
                        "protocols": stats['protocols'],
                        "duration": analyzer._calculate_capture_duration()
                    }
                }
                print(json.dumps(result_json, indent=2))
            else:
                print(f"\n[SUCCESS] Capture successful!")
                print(f"File saved to: {args.output}")
                print(f"Statistics: {stats['total_packets']} packets, {len(stats['protocols'])} protocols")
                if stats.get('protocols'):
                    print(f"Protocols: {', '.join(stats['protocols'])}")
        else:
            if output_format == "json":
                print(json.dumps({"success": False, "error": "Capture failed"}, indent=2))
            else:
                print("ERROR: Capture failed!")
        return
    
    # Show help if no valid arguments
    print("Neura Trace - Network Analysis with Integrated Port & Service Scanning")
    print("=" * 60)
    parser.print_help()
    print("\nExamples:")
    print("  python packet_analyzer.py --list_interfaces")
    print("  python packet_analyzer.py -i eth0 -c 50")
    print("  python packet_analyzer.py --scan localhost --ports 1-1024")
    print("  python packet_analyzer.py --scan 192.168.1.1 --ports 20-100 --analyze-security")
    print("  python packet_analyzer.py --analyze capture.pcap")
    print("\nDashboard-friendly output:")
    print("  Add --json flag for JSON output")


if __name__ == "__main__":
    main()