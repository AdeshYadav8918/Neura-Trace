# 🧠 Neura Trace

Advanced Network Traffic Analyzer with CLI and web dashboard interface.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red)](https://streamlit.io/)

## ✨ Features

- **Dual Interface**: Command-line tool AND web dashboard
- **Real-time Capture**: Live packet capture with protocol filtering
- **PCAP Analysis**: Load and analyze existing capture files
- **Visual Dashboard**: Interactive charts and statistics
- **Multi-protocol**: TCP, UDP, HTTP, DNS, ICMP support
- **Cross-platform**: Works on Windows, Linux, and macOS

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Administrative privileges for packet capture
- Wireshark/tshark installed

### Installation

1. **Clone and setup:**

    git clone https://github.com/yourusername/neura-trace.git
    cd neura-trace

2. **Install Dependencies**

    pip install -r requirements.txt

3. **Install system dependencies**

* Ubuntu/Debian:

    sudo apt-get install tshark

* macOS:

    brew install wireshark

* Windows:

    Install Wireshark

## 📖 Usage

### Command Line Interface
    
List available interfaces:

    python packet_analyzer.py --list_interfaces
    
Capture packets:

    # Basic capture
    python packet_analyzer.py -i eth0 -c 100
    # Capture with protocol filter
    python packet_analyzer.py -i eth0 -c 50 -p TCP
    # Custom output file
    python packet_analyzer.py -i eth0 -c 200 -o my_capture.pcap

Web Dashboard
        
Start the dashboard:

    streamlit run dashboard.py

* Then open http://localhost:8501 in your browser.
    
### Dashboard Features:

    📊 Overview: Real-time statistics and charts
    🎯 Live Capture: Interactive capture controls
    📁 PCAP Analysis: Upload and analyze capture files
    📜 History: View capture history and export data
    ⚙️ Settings: Configure preferences and defaults

## 📦 Dependencies

* pyshark: Packet analysis
* scapy: Packet capture
* streamlit: Web dashboard
* plotly: Visualizations
* pandas: Data handling
* psutil: System utilities
* All dependencies are listed in requirements.txt

## 🔧 Troubleshooting

Common Issues
    "Permission denied" on capture:

        # Run with admin privileges
        sudo python packet_analyzer.py -i eth0 -c 100

    "No interface found":

        # List available interfaces
        python packet_analyzer.py --list_interfaces
    
    Dashboard won't start:

        # Check if Streamlit is installed
        pip install streamlit
        # Try different port
        streamlit run dashboard.py --server.port 8502

## 🤝 Contributing
Contributions are welcome! Please see CONTRIBUTING.md for guidelines.

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

* Issues: GitHub Issues
* Questions: Open a discussion in GitHub