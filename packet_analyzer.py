import pyshark
import logging
import psutil
import argparse
import json
import os
import sys
from datetime import datetime
from typing import Optional, Dict, Any
from scapy.all import sniff, wrpcap

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PacketAnalyzer:
    def __init__(self):
        self.captured_packets = []
        self.capture_stats = {
            'start_time': None,
            'end_time': None,
            'total_packets': 0,
            'protocols': set(),
            'interfaces_used': set()
        }
    
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
    
    def analyze_packets(self, pcap_file):
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
            
            return analysis_results
        except Exception as e:
            print(f"Error analyzing packets: {e}")
            return None
    
    def list_network_interfaces(self):
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
            
            return interface_details
        except Exception as e:
            logging.error(f"Error listing network interfaces: {e}")
            return {}
    
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
            start = datetime.fromisoformat(self.capture_stats['start_time'])
            end = datetime.fromisoformat(self.capture_stats['end_time'])
            return (end - start).total_seconds()
        return 0

def main():
    parser = argparse.ArgumentParser(description="Neura Trace - Advanced Network Traffic Analyzer")
    parser.add_argument('-i', '--interface', type=str, help="Network interface to capture packets from")
    parser.add_argument('-p', '--protocol', type=str, help="Protocol to filter (e.g., TCP, UDP, HTTP)")
    parser.add_argument('-c', '--count', type=int, default=100, help="Number of packets to capture")
    parser.add_argument('-o', '--output', type=str, default="captured_packets.pcap", help="Output file")
    parser.add_argument('--list_interfaces', action='store_true', help="List available network interfaces")
    parser.add_argument('--analyze', type=str, help="Analyze existing PCAP file")
    parser.add_argument('--debug', action='store_true', help="Enable debug mode")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    analyzer = PacketAnalyzer()
    
    if args.list_interfaces:
        logging.info("Listing Network Interfaces:")
        interfaces = analyzer.list_network_interfaces()
        print(json.dumps(interfaces, indent=2))
        return
    
    if args.analyze:
        logging.info(f"Analyzing PCAP file: {args.analyze}")
        results = analyzer.analyze_packets(args.analyze)
        if results:
            print(json.dumps(results, indent=2))
        return
    
    if args.interface and args.count:
        logging.info(f"Capturing {args.count} packets on {args.interface}")
        success, packet_count, stats = analyzer.capture_packets(
            interface=args.interface,
            count=args.count,
            filter=args.protocol if args.protocol else "",
            output_file=args.output
        )
        
        if success:
            logging.info(f"✅ Capture successful! Saved to {args.output}")
            logging.info(f"📊 Statistics: {stats['total_packets']} packets, {len(stats['protocols'])} protocols")
        else:
            logging.error("❌ Capture failed!")
    
    if not any([args.list_interfaces, args.analyze, args.interface]):
        parser.print_help()

if __name__ == "__main__":
    main()