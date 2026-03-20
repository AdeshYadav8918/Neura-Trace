# 🧠 Neura Trace - Network Analysis Tool

![Neura Trace Logo](logo.png)

**Neura Trace** is a comprehensive network analysis tool designed for security professionals, system administrators, and network enthusiasts. It combines port scanning with integrated service detection, packet capture, and security analysis in a single, user-friendly interface.

## ✨ Features

### 🔍 **Integrated Port & Service Scanner**
- **Smart Port Scanning**: Scan ranges from 1-65535 with configurable threading
- **Automatic Service Detection**: Identifies running services on open ports
- **Banner Grabbing**: Captures service banners for version identification
- **Process Information**: Shows local process details for services (localhost scans)
- **Security Analysis**: Flags potentially vulnerable services with recommendations

### 🎯 **Live Packet Capture**
- **Real-time Monitoring**: Capture network traffic from any interface
- **Protocol Filtering**: Filter by TCP, UDP, HTTP, DNS, ICMP, ARP
- **PCAP Export**: Save captures in standard PCAP format
- **Metadata Logging**: Automatic capture statistics and metadata

### 📊 **PCAP Analysis**
- **File Upload**: Analyze existing PCAP files
- **Traffic Summary**: Protocol distribution, source/destination IPs
- **Visualization**: Interactive charts and graphs

### 🖥️ **Modern Web Dashboard**
- **Streamlit Interface**: Beautiful, responsive web interface
- **Custom Logo Support**: Upload your own logo or use default
- **Dark/Light Theme**: Automatic theme switching
- **History Tracking**: All scans and captures logged
- **Export Capabilities**: Download results as CSV/JSON

### 🛡️ **Security Features**
- **Legal Compliance**: Built-in authorization warnings and logging
- **Rate Limiting**: Prevents accidental mass scanning
- **Scope Validation**: Validates target IPs before scanning
- **Usage Logging**: All activities logged for accountability

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Administrative/root privileges (for packet capture)

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/neura-trace.git
cd neura-trace

# Install dependencies
pip install -r requirements.txt