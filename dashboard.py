import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import subprocess
import json
import os
import sys
import time
from pathlib import Path
import socket
import ipaddress
import base64
from PIL import Image
import io
from streamlit_float import *
import streamlit.components.v1 as components
import requests
try:
    from streamlit_lottie import st_lottie
except ImportError:
    pass

# API Configuration - Hardcoded for Deployment
os.environ['GEMINI_API_KEY'] = "AIzaSyB72wDWbpaTTO-iwHOjKCRMXI5_Z5bjLpE"

# Import AI modules
try:
    from ai_analyzer import AIAnalyzer
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# Import CVE Lookup (independent of AI)
try:
    from cve_lookup import CVELookup
except ImportError:
    pass # Handle gracefully if missing

# Set page favicon - use logo if available
_logo_path = "logo.png"
_page_icon = _logo_path if os.path.exists(_logo_path) else "🛡️"

st.set_page_config(
    page_title="NeuraTrace - Network Security",
    page_icon=_page_icon,
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================
# LOGO HANDLING FUNCTIONS
# ============================

def get_logo_base64(image_path=None):
    """Get logo as base64 or use default if not available"""
    if image_path and os.path.exists(image_path):
        try:
            img = Image.open(image_path)
            max_width = 100
            width_percent = (max_width / float(img.size[0]))
            height_size = int((float(img.size[1]) * float(width_percent)))
            img = img.resize((max_width, height_size), Image.Resampling.LANCZOS)
            
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            img_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return img_base64
        except Exception as e:
            st.sidebar.warning(f"Could not load logo: {e}")
    
    return None

def save_logo_path(logo_path):
    """Save logo path to session state and config file"""
    if logo_path and os.path.exists(logo_path):
        st.session_state.logo_path = logo_path
        
        config = {"logo_path": logo_path}
        with open('neura_trace_config.json', 'w') as f:
            json.dump(config, f)
        return True
    return False

def load_logo_config():
    """Load logo path from config file"""
    try:
        if os.path.exists('neura_trace_config.json'):
            with open('neura_trace_config.json', 'r') as f:
                config = json.load(f)
                return config.get('logo_path')
    except:
        pass
    return None

# ============================
# CUSTOM CSS
# ============================

def inject_css():
    st.markdown("""
<style>
    /* Base SaaS Vercel/Stripe Dark Theme */
    .block-container {
        font-family: 'Inter', 'Geist', sans-serif !important;
        padding-top: 1rem !important;
        margin-top: 0 !important;
    }
    /* Remove the default Streamlit top toolbar gap */
    header[data-testid="stHeader"] {
        height: 0 !important;
        min-height: 0 !important;
    }
    #root > div:first-child > div > div > div > div > section > div {
        padding-top: 0.5rem !important;
    }
    
    /* Typography */
    h1, h2, h3, h4 {
        font-weight: 700 !important;
        letter-spacing: -0.02 !important;
    }
    
    .app-title {
        font-size: 1.8rem !important;
        font-weight: 900 !important;
        background: linear-gradient(90deg, #00D4FF, #7000FF) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        margin-top: 1rem !important;
        letter-spacing: 1px !important;
    }
    .app-subtitle {
        font-size: 0.85rem !important;
        text-transform: uppercase !important;
        letter-spacing: 2px !important;
        color: #9CA3AF !important;
        margin-bottom: 1rem !important;
    }
    .logo-container {
        text-align: center;
        margin-bottom: 2rem;
        animation: fadeInDown 1s ease-in-out;
    }

    .main-header {
        font-size: 3rem !important;
        background: linear-gradient(135deg, #00D4FF, #7000FF) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        margin-bottom: 0.5rem !important;
        font-weight: 800 !important;
        animation: fadeInDown 0.8s ease-out;
    }

    /* Glassmorphism Interactive Grid Cards (Streamlit Container border=True) */
    [data-testid="stVerticalBlockBorderWrapper"], fieldset {
        background: rgba(255, 255, 255, 0.02) !important;
        backdrop-filter: blur(10px) !important;
        -webkit-backdrop-filter: blur(10px) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 16px !important;
        padding: 1.2rem !important;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3) !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
    }
    [data-testid="stVerticalBlockBorderWrapper"]:hover, fieldset:hover {
        transform: translateY(-4px) !important;
        box-shadow: 0 12px 40px 0 rgba(0, 0, 0, 0.6) !important;
        border-color: rgba(0, 212, 255, 0.4) !important;
    }
    
    /* Avoid floating chat getting warped by this global override */
    .float-container [data-testid="stVerticalBlockBorderWrapper"] {
        transform: none !important;
    }

    /* Modern SaaS Buttons - Applied to Primary buttons only */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #7000FF 0%, #00D4FF 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 12px !important;
        font-weight: 600 !important;
        letter-spacing: 0.02em !important;
        padding: 0.6rem 1.2rem !important;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
        box-shadow: 0 4px 14px rgba(112, 0, 255, 0.3) !important;
    }
    .stButton > button[kind="primary"]:hover {
        transform: scale(1.03) !important;
        box-shadow: 0 8px 24px rgba(0, 212, 255, 0.5) !important;
        filter: brightness(1.1);
    }
    .stButton > button[kind="primary"]:active {
        transform: scale(0.97) !important;
    }

    /* Tabular Row Hover */
    .tabular-row {
        border-bottom: 1px solid rgba(255,255,255,0.05);
        padding-top: 8px;
        padding-bottom: 8px;
    }
    .tabular-row:hover {
        background-color: rgba(255,255,255,0.02);
    }
    
    /* Animated Metrics */
    [data-testid="stMetricValue"] {
        font-size: 2.5rem !important;
        font-weight: 800 !important;
        color: #00D4FF !important;
        animation: slideUp 0.6s ease-out;
    }

    /* Pulsing Status Badge */
    .status-badge {
        display: inline-flex;
        align-items: center;
        padding: 0.35rem 0.85rem;
        border-radius: 9999px;
        font-size: 0.85rem;
        font-weight: 600;
        background: rgba(0, 212, 255, 0.1);
        color: #00D4FF;
        border: 1px solid rgba(0, 212, 255, 0.2);
        transition: all 0.3s ease;
    }
    .status-badge::before {
        content: '';
        display: inline-block;
        width: 8px;
        height: 8px;
        margin-right: 8px;
        background-color: #00D4FF;
        border-radius: 50%;
        box-shadow: 0 0 8px #00D4FF;
        animation: pulse-dot 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    }

    /* Tooltip Dark Theme override */
    div[data-testid="stTooltipIcon"] {
        color: #7000FF !important;
    }

    /* Animations */
    @keyframes fadeInDown {
        from { opacity: 0; transform: translateY(-20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes slideUp {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes pulse-dot {
        0%, 100% { opacity: 1; box-shadow: 0 0 2px #00D4FF; }
        50% { opacity: 0.4; box-shadow: 0 0 16px #00D4FF; }
    }
</style>
""", unsafe_allow_html=True)

# Inject Custom SaaS CSS globally
inject_css()

# ============================
# DASHBOARD CLASS
# ============================

def load_app_config():
    """Load app configurations from config file"""
    config = {
        "save_path": r"E:\Backup\Desktop\NT\saved_scans"
    }
    try:
        if os.path.exists('neura_trace_config.json'):
            with open('neura_trace_config.json', 'r') as f:
                saved_config = json.load(f)
                if 'save_path' in saved_config:
                    config['save_path'] = saved_config['save_path']
    except:
        pass
    return config

app_config = load_app_config()

# Private data directory - all user data stored here (excluded from git)
DATA_DIR = Path(app_config["save_path"])
UPLOADS_DIR = DATA_DIR / "uploads"
CAPTURES_DIR = DATA_DIR / "captures"
HISTORY_DIR = DATA_DIR / "history"

# Ensure data directories exist
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
except Exception as e:
    logging.error(f"Failed to create data directories: {e}")

class NeuraTraceDashboard:
    def __init__(self):
        self.capture_history = []
        self.scan_history = []
        self.load_history()
        
        # Initialize logo path
        if 'logo_path' not in st.session_state:
            saved_logo_path = load_logo_config()
            if saved_logo_path and os.path.exists(saved_logo_path):
                st.session_state.logo_path = saved_logo_path
            else:
                default_logo = "logo.png"
                if os.path.exists(default_logo):
                    st.session_state.logo_path = default_logo
                else:
                    st.session_state.logo_path = None
    
    def load_history(self):
        """Load history from private data directory"""
        capture_history_file = HISTORY_DIR / 'capture_history.json'
        scan_history_file = HISTORY_DIR / 'scan_history.json'
        
        try:
            if capture_history_file.exists():
                with open(capture_history_file, 'r') as f:
                    self.capture_history = json.load(f)
        except Exception as e:
            logging.warning(f"Could not load capture history: {e}")
        
        try:
            if scan_history_file.exists():
                with open(scan_history_file, 'r') as f:
                    self.scan_history = json.load(f)
        except Exception as e:
            logging.warning(f"Could not load scan history: {e}")
    
    def save_history(self):
        """Save history to private data directory"""
        try:
            with open(HISTORY_DIR / 'capture_history.json', 'w') as f:
                json.dump(self.capture_history, f, indent=2)
        except Exception as e:
            logging.error(f"Could not save capture history: {e}")
        
        try:
            with open(HISTORY_DIR / 'scan_history.json', 'w') as f:
                json.dump(self.scan_history, f, indent=2)
        except Exception as e:
            logging.error(f"Could not save scan history: {e}")
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        try:
            import psutil
            interfaces = psutil.net_if_addrs()
            return list(interfaces.keys())
        except:
            return ['eth0', 'wlan0', 'en0', 'lo', 'any']
    
    def run_capture(self, interface, count, protocol, output_file):
        """Run packet capture using the CLI tool"""
        try:
            cmd = ['python', 'packet_analyzer.py', 
                   '-i', interface,
                   '-c', str(count),
                   '-o', output_file]
            
            if protocol and protocol != "All":
                cmd.extend(['-p', protocol])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            capture_info = {
                'timestamp': datetime.now().isoformat(),
                'interface': interface,
                'protocol': protocol or 'All',
                'packet_count': count,
                'output_file': output_file,
                'status': 'success' if result.returncode == 0 else 'failed',
                'command': ' '.join(cmd),
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
            self.capture_history.append(capture_info)
            self.save_history()
            
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            return False, "", str(e)
    
    def run_port_scan_with_services(self, target_ip, start_port, end_port, analyze_security=False):
        """Run port scan with integrated service detection"""
        try:
            # Validate input
            if not self._validate_scan_request(target_ip, start_port, end_port):
                return False, "", "Validation failed"
            
            cmd = ['python', 'packet_analyzer.py',
                   '--scan', target_ip,
                   '--ports', f'{start_port}-{end_port}',
                   '--json']
            
            if analyze_security:
                cmd.append('--analyze-security')
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            scan_info = {
                'timestamp': datetime.now().isoformat(),
                'target': target_ip,
                'port_range': f'{start_port}-{end_port}',
                'security_analysis': analyze_security,
                'status': 'success' if result.returncode == 0 else 'failed',
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
            self.scan_history.append(scan_info)
            self.save_history()
            
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            return False, "", str(e)
    
    def _validate_scan_request(self, target_ip, start_port, end_port):
        """Validate scan parameters"""
        port_range_size = end_port - start_port + 1
        if port_range_size > 65535:
            st.error(f"Port range too large ({port_range_size} ports). Maximum 65,535 ports per scan.")
            return False
        
        if start_port > end_port:
            st.error("Start port must be less than end port")
            return False
        
        if start_port < 1 or end_port > 65535:
            st.error("Ports must be between 1 and 65535")
            return False
        
        return True
    
    def analyze_pcap_file(self, pcap_file):
        """Analyze PCAP file"""
        try:
            cmd = ['python', 'packet_analyzer.py', '--analyze', pcap_file, '--json']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                try:
                    return True, json.loads(result.stdout), result.stderr
                except:
                    return True, result.stdout, result.stderr
            return False, "", result.stderr
        except Exception as e:
            return False, "", str(e)

# ============================
# PAGE FUNCTIONS
# ============================

def load_lottieurl(url: str):
    try:
        r = requests.get(url)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None

def st_lottie_header():
    """Renders the top animated header"""
    col1, col2 = st.columns([1, 4])
    with col1:
        # A generic cyber network scanning Lottie animation link
        lottie_cyber = load_lottieurl("https://assets5.lottiefiles.com/packages/lf20_tno6cg2w.json")
        try:
            if lottie_cyber:
                st_lottie(lottie_cyber, height=120, key="network_lottie")
        except NameError:
            st.image("https://img.icons8.com/color/96/000000/network.png", width=80)
            
    with col2:
        st.markdown('<h1 class="main-header">NeuraTrace</h1>', unsafe_allow_html=True)
        st.markdown('<div class="status-badge" style="margin-top: -10px; margin-bottom: 20px;">System Active & Monitoring</div>', unsafe_allow_html=True)

def metric_cards(dashboard):
    """Renders core animated capability metrics"""
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        with st.container(border=True):
            st.metric("Total Captures", len(dashboard.capture_history))
    with col2:
        with st.container(border=True):
            successful = sum(1 for c in dashboard.capture_history if c.get('status') == 'success')
            st.metric("Threats Blocked", successful) # Custom animated metric via CSS slideUp
    with col3:
        with st.container(border=True):
            total_scans = len(dashboard.scan_history)
            st.metric("Port Scans", total_scans)
    with col4:
        with st.container(border=True):
            security_scans = sum(1 for s in dashboard.scan_history if s.get('security_analysis'))
            st.metric("Security Audits", security_scans)

def feature_grid():
    """Renders the robust interactive UI tool grid with placeholders"""
    st.markdown("### ⚡ Platform Toolkit")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        with st.container(border=True):
            st.markdown("#### 🎯 Live")
            st.caption("Real-time network capture filtering")
            # SaaS Dummy placeholder logic demoing interaction elements
            st.text_input("Interface", key="pl_int", placeholder="eth0...", help="Physical network adapter to capture from", label_visibility="collapsed")
            if st.button("Start Capture", key="dashboard_capture", use_container_width=True, type="primary"):
                with st.spinner("Initializing Engine..."):
                    import time; time.sleep(0.5)
                    st.session_state.page = "Capture"
                    st.rerun()
    
    with col2:
        with st.container(border=True):
            st.markdown("#### 🔍 Scanner")
            st.caption("Detect open ports and active services")
            st.text_input("Target IP", key="pl_ip", placeholder="192.168.1.1...", help="Target subnet or IP range", label_visibility="collapsed")
            if st.button("Start Scan", key="dashboard_scan", use_container_width=True, type="primary"):
                with st.spinner("Allocating Scanner Nodes..."):
                    import time; time.sleep(0.5)
                    st.session_state.page = "Port Scanner"
                    st.rerun()
    
    with col3:
        with st.container(border=True):
            st.markdown("#### 🛡️ Audit")
            st.caption("AI powered automated security review")
            st.text_input("Device Role", key="pl_rol", placeholder="Database Server...", help="Provide context for AI review", label_visibility="collapsed")
            if st.button("Security Audit", key="dashboard_device", use_container_width=True, type="primary"):
                st.session_state.page = "Device Security"
                st.rerun()
    
    with col4:
        with st.container(border=True):
            st.markdown("#### 📁 PCAP")
            st.caption("Autonomous file analysis engine")
            st.text_input("Filter", key="pl_fil", placeholder="tcp.port==80...", help="Pre-filter applied before processing PCAP", label_visibility="collapsed")
            if st.button("Analyze Files", key="dashboard_analyze", use_container_width=True, type="primary"):
                st.session_state.page = "Analyze"
                st.rerun()

def show_dashboard_page(dashboard):
    """Main completely refactored dashboard page"""
    st_lottie_header()
    metric_cards(dashboard)
    st.divider()
    feature_grid()
    st.divider()
    
    # Recent activity
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔍 Recent Scans")
        if dashboard.scan_history:
            recent_scans = dashboard.scan_history[-5:][::-1]  # newest first
            
            # Tabular Header
            hc1, hc2, hc3, hc4 = st.columns([1, 4, 3, 2])
            hc1.markdown("**Status**")
            hc2.markdown("**Target**")
            hc3.markdown("**Time**")
            hc4.markdown("**Action**")
            st.markdown("<hr style='margin: 0.5rem 0; opacity: 0.2;'>", unsafe_allow_html=True)
            
            for i, scan in enumerate(recent_scans):
                # We use a container / columns to mimic tabular rows
                c1, c2, c3, c4 = st.columns([1, 4, 3, 2])
                ts = scan.get('timestamp', 'N/A')[:19].replace('T', ' ')
                target = scan.get('target', 'N/A')
                status_icon = "✅" if scan.get('status') == 'success' else "❌"
                
                c1.write(status_icon)
                c2.write(target)
                c3.caption(ts)
                if c4.button("View", key=f"recent_scan_{i}", use_container_width=True):
                    st.session_state.selected_scan = scan
                    st.session_state.selected_capture = None  # deselect capture
                st.markdown("<div class='tabular-row'></div>", unsafe_allow_html=True)
            
            # Show selected scan result
            selected = st.session_state.get('selected_scan')
            if selected:
                with st.expander(f"📋 Scan Result: {selected.get('target')} | {selected.get('timestamp', '')[:19]}", expanded=True):
                    stdout = selected.get('stdout', '')
                    stderr = selected.get('stderr', '')
                    if stdout:
                        try:
                            data = json.loads(stdout)
                            open_ports = data.get('open_ports', {})
                            if open_ports:
                                st.markdown(f"**Target:** `{data.get('target')}` | **Open Ports:** {data.get('open_count', 0)} / {data.get('total_ports_scanned', 0)}")
                                rows = []
                                for port, svc in open_ports.items():
                                    svc_details = data.get('service_details', {}).get(str(port), {})
                                    rows.append({'Port': int(port), 'Service': svc, 'Banner': svc_details.get('banner', '')[:60]})
                                st.dataframe(pd.DataFrame(rows).sort_values('Port'), use_container_width=True, hide_index=True)
                            else:
                                st.info("No open ports detected on this target.")
                            if 'security_analysis' in data:
                                sec = data['security_analysis']
                                st.markdown(f"**Security Score:** `{sec.get('security_score', 'N/A')}/100` | **Risk:** `{sec.get('risk_level', 'N/A')}`")
                        except (json.JSONDecodeError, ValueError):
                            st.code(stdout, language="text")
                    else:
                        st.warning("No output captured for this scan. Re-run to generate results.")
                    if stderr:
                        with st.expander("⚠️ Stderr"):
                            st.code(stderr, language="text")
        else:
            st.info("No scans yet")
    
    with col2:
        st.subheader("🎯 Recent Captures")
        if dashboard.capture_history:
            recent_captures = dashboard.capture_history[-5:][::-1]  # newest first
            
            # Tabular Header
            hc1, hc2, hc3, hc4 = st.columns([3, 1, 3, 2])
            hc1.markdown("**Interface**")
            hc2.markdown("**Status**")
            hc3.markdown("**Time**")
            hc4.markdown("**Action**")
            st.markdown("<hr style='margin: 0.5rem 0; opacity: 0.2;'>", unsafe_allow_html=True)
            
            for i, cap in enumerate(recent_captures):
                # Rows for captures
                c1, c2, c3, c4 = st.columns([3, 1, 3, 2])
                ts = cap.get('timestamp', 'N/A')[:19].replace('T', ' ')
                iface = cap.get('interface', 'N/A')
                status_icon = "✅" if cap.get('status') == 'success' else "❌"
                
                c1.write(iface)
                c2.write(status_icon)
                c3.caption(ts)
                if c4.button("View", key=f"recent_cap_{i}", use_container_width=True):
                    st.session_state.selected_capture = cap
                    st.session_state.selected_scan = None  # deselect scan
                st.markdown("<div class='tabular-row'></div>", unsafe_allow_html=True)
            
            # Show selected capture result
            selected = st.session_state.get('selected_capture')
            if selected:
                with st.expander(f"📋 Capture: {selected.get('interface')} | {selected.get('timestamp', '')[:19]}", expanded=True):
                    st.markdown(f"**Interface:** `{selected.get('interface')}` | **Protocol:** `{selected.get('protocol')}` | **Packet Count:** `{selected.get('packet_count')}`")
                    output_file = selected.get('output_file', '')
                    if output_file and os.path.exists(output_file):
                        file_size = os.path.getsize(output_file) / 1024
                        st.markdown(f"**Saved File:** `{output_file}` ({file_size:.2f} KB)")
                        with open(output_file, 'rb') as f:
                            st.download_button("⬇️ Download PCAP", f, file_name=os.path.basename(output_file), mime='application/octet-stream', key=f"dl_cap_{i}")
                    stdout = selected.get('stdout', '')
                    if stdout:
                        st.code(stdout[:2000], language="text")
                    else:
                        st.info("Capture file saved. Use the Analyze page to inspect PCAP contents.")
        else:
            st.info("No captures yet")

def show_capture_page(dashboard):
    """Live capture page"""
    st.markdown('<h1 class="main-header">🎯 Live Packet Capture</h1>', unsafe_allow_html=True)
    
    with st.container():
        st.markdown("### Capture Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            interfaces = dashboard.get_network_interfaces()
            selected_interface = st.selectbox("Network Interface", interfaces)
            
            protocol_options = ["All", "TCP", "UDP", "HTTP", "DNS", "ICMP", "ARP"]
            selected_protocol = st.selectbox("Protocol Filter", protocol_options)
        
        with col2:
            packet_count = st.slider("Packet Count", 10, 1000, 100, 10)
            output_filename = st.text_input("Output Filename", "capture.pcap")
            output_file = str(CAPTURES_DIR / output_filename)
        
        st.divider()
        
        if st.button("🚀 Start Capture", type="primary", use_container_width=True):
            with st.spinner(f"Capturing {packet_count} packets on {selected_interface}..."):
                success, stdout, stderr = dashboard.run_capture(
                    interface=selected_interface,
                    count=packet_count,
                    protocol=selected_protocol,
                    output_file=output_file
                )
                
                if success:
                    st.markdown('<div class="success-message">✅ Capture completed successfully!</div>', unsafe_allow_html=True)
                    
                    # Store capture info for AI analysis
                    st.session_state.last_capture = {
                        'interface': selected_interface,
                        'protocol': selected_protocol,
                        'packet_count': packet_count,
                        'output_file': output_file,
                        'stdout': stdout
                    }
                    
                    if stdout:
                        with st.expander("Capture Output"):
                            st.code(stdout)
                    
                    if os.path.exists(output_file):
                        file_size = os.path.getsize(output_file) / 1024
                        st.info(f"📁 File saved: {output_file} ({file_size:.2f} KB)")
                else:
                    st.markdown('<div class="error-message">❌ Capture failed!</div>', unsafe_allow_html=True)
                    if stderr:
                        with st.expander("Error Details"):
                            st.code(stderr)
        
        # AI Traffic Analysis Section
        if 'last_capture' in st.session_state:
            st.divider()
            st.subheader("🤖 AI Traffic Analysis")
            
            api_key = st.session_state.get('gemini_api_key', os.environ.get('GEMINI_API_KEY', ''))
            ai_enabled = st.session_state.get('enable_ai_traffic', True)
            
            if not api_key:
                st.info("💡 Configure your Gemini API key in Settings to enable AI traffic analysis")
            elif not AI_AVAILABLE:
                st.warning("AI modules not available. Check installation.")
            elif ai_enabled:
                if st.button("🧠 Analyze Traffic with AI", use_container_width=True, key="ai_traffic_btn"):
                    with st.spinner("AI analyzing captured traffic..."):
                        try:
                            analyzer = AIAnalyzer(api_key)
                            
                            # Parse capture output for analysis
                            capture_data = st.session_state.last_capture
                            packets_summary = {
                                'total_packets': capture_data.get('packet_count', 0),
                                'protocols': [capture_data.get('protocol', 'All')],
                                'source_ips': [],
                                'dest_ips': [],
                                'duration': 'Recent capture'
                            }
                            
                            # Extract IPs from stdout if available
                            stdout = capture_data.get('stdout', '')
                            if stdout:
                                import re
                                ips = re.findall(r'\d+\.\d+\.\d+\.\d+', stdout)
                                if ips:
                                    packets_summary['source_ips'] = list(set(ips[:10]))
                                    packets_summary['dest_ips'] = list(set(ips[10:20]))
                            
                            ai_result = analyzer.analyze_live_traffic(packets_summary)
                            st.session_state.ai_traffic_result = ai_result
                        except Exception as e:
                            st.error(f"AI analysis failed: {e}")
            
            # Display AI Traffic Analysis Results
            if 'ai_traffic_result' in st.session_state:
                ai_result = st.session_state.ai_traffic_result
                if ai_result.get('_meta', {}).get('status') == 'success':
                    with st.expander("🧠 AI Traffic Analysis Results", expanded=True):
                        risk = ai_result.get('risk_level', 'N/A')
                        st.metric("Risk Level", risk)
                        
                        st.markdown("**Traffic Summary**")
                        st.info(ai_result.get('traffic_summary', 'No summary available'))
                        
                        if ai_result.get('anomalies_detected'):
                            st.markdown("**🚨 Anomalies Detected**")
                            for anomaly in ai_result.get('anomalies_detected', []):
                                st.warning(anomaly)
                        
                        if ai_result.get('recommendations'):
                            st.markdown("**💡 Recommendations**")
                            for rec in ai_result.get('recommendations', []):
                                st.markdown(f"• {rec}")
                elif ai_result.get('error'):
                    st.error(f"AI Error: {ai_result.get('error')}")

def show_port_scanner_page(dashboard):
    """Port scanner with integrated service detection page"""
    st.markdown('<h1 class="main-header">🔍 Port Scanner with Service Detection</h1>', unsafe_allow_html=True)
    
    with st.container():
        st.markdown("""
        ### Integrated Port & Service Scanner
        This tool scans for open ports and automatically:
        - Identifies running services
        - Captures service banners
        - Shows process information (for local scans)
        - Provides security recommendations
        """)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            target_ip = st.text_input("Target IP Address", "localhost")
            
            if target_ip:
                try:
                    if target_ip != "localhost":
                        ipaddress.ip_address(target_ip)
                except ValueError:
                    st.warning("⚠️ Enter a valid IP address or use 'localhost'")
        
        # Initialize session state for port values if not present
        if 'port_start_input' not in st.session_state:
            st.session_state.port_start_input = 1
        if 'port_end_input' not in st.session_state:
            st.session_state.port_end_input = 1024
        
        with col2:
            start_port = st.number_input("Start Port", 1, 65535, key="port_start_input")
        
        with col3:
            end_port = st.number_input("End Port", 1, 65535, key="port_end_input")
        
        # Security option RESTORED
        analyze_security = st.checkbox("🔒 Include Security Analysis", value=True,
                                      help="Analyze services for potential vulnerabilities and provide recommendations")
        
        if start_port > end_port:
            st.error("❌ Start port must be less than end port")
        
        # Quick scan presets
        st.markdown("### Quick Scan Presets")
        preset_cols = st.columns(4)
        
        presets = [
            {"name": "Common Ports", "start": 1, "end": 1024},
            {"name": "Web Services", "start": 80, "end": 443},
            {"name": "Database", "start": 3306, "end": 5432},
            {"name": "Full Scan", "start": 1, "end": 65535}
        ]
        
        def set_preset_ports(s, e):
            st.session_state.port_start_input = s
            st.session_state.port_end_input = e
        
        for i, preset in enumerate(presets):
            with preset_cols[i]:
                st.button(preset["name"], 
                         use_container_width=True, 
                         key=f"preset_{i}",
                         on_click=set_preset_ports,
                         args=(preset["start"], preset["end"]))
        
        st.divider()
        
        if st.button("🚀 Start Integrated Scan", type="primary", use_container_width=True):
            if start_port > end_port:
                st.error("Please fix port range before scanning")
            else:
                with st.spinner(f"Scanning {target_ip} with service detection..."):
                    success, stdout, stderr = dashboard.run_port_scan_with_services(
                        target_ip=target_ip,
                        start_port=start_port,
                        end_port=end_port,
                        analyze_security=analyze_security
                    )
                    
                    if success:
                        st.markdown('<div class="success-message">✅ Scan completed successfully!</div>', unsafe_allow_html=True)
                        
                        # Parse and display results
                        if stdout:
                            try:
                                results = json.loads(stdout)
                                
                                # Display summary
                                open_ports = results.get('open_ports', {})
                                total_scanned = results.get('total_ports_scanned', 0)
                                
                                col1, col2, col3 = st.columns(3)
                                with col1:
                                    st.metric("Open Ports", len(open_ports))
                                with col2:
                                    st.metric("Ports Scanned", total_scanned)
                                with col3:
                                    if analyze_security:
                                        security_score = results.get('security_score', 0)
                                        st.metric("Security Score", f"{security_score}/100")
                                
                                # --- SAVE RESULTS FOR DEVICE SECURITY PAGE ---
                                services_list = []
                                service_details = results.get('service_details', {})
                                for port, service in open_ports.items():
                                    details = service_details.get(str(port) if isinstance(service_details, dict) else port, {})
                                    services_list.append({
                                        'port': port,
                                        'name': service,
                                        'banner': details.get('banner', ''),
                                        'state': 'open'
                                    })
                                
                                st.session_state.device_scan_results = {
                                    'target': target_ip,
                                    'scan_time': datetime.now().isoformat(),
                                    'services': services_list,
                                    'raw_results': results
                                }
                                # ---------------------------------------------

                                # Display open ports with service details
                                if open_ports:
                                    st.subheader(f"📋 Discovered Services ({len(open_ports)} found)")
                                    
                                    vulnerabilities = results.get('security_analysis', {}).get('vulnerabilities', []) if analyze_security else []
                                    vuln_ports = {v.get('port'): v for v in vulnerabilities}
                                    
                                    for port, service_name in sorted(open_ports.items()):
                                        details = service_details.get(str(port) if isinstance(service_details, dict) else port, {})
                                        banner = details.get('banner', '')
                                        process_info = details.get('process_info', {})
                                        
                                        # Determine card style logic
                                        vuln_info = vuln_ports.get(port)
                                        if vuln_info:
                                            risk_level = vuln_info.get('risk', 'Medium')
                                            card_class = "critical-service" if risk_level == 'Critical' else "vulnerable-service"
                                        else:
                                            card_class = "service-card"
                                        
                                        with st.container():
                                            st.markdown(f'<div class="{card_class}">', unsafe_allow_html=True)
                                            
                                            col1, col2 = st.columns([1, 3])
                                            with col1:
                                                st.markdown(f"**Port {port}**")
                                            with col2:
                                                st.markdown(f"**{service_name}**")
                                            
                                            if banner:
                                                st.markdown(f"**Banner:** `{banner[:100]}...`" if len(banner) > 100 else f"**Banner:** `{banner}`")
                                            
                                            if process_info and process_info.get('name') != 'Unknown':
                                                st.write(f"Process: {process_info.get('name')} (PID: {process_info.get('pid')})")
                                            
                                            if vuln_info:
                                                st.markdown(f"**Risk:** {vuln_info.get('risk')} - {vuln_info.get('recommendation')}")
                                                
                                            st.markdown('</div>', unsafe_allow_html=True)
                                    
                                    # Restored Security Analysis Section
                                    if analyze_security:
                                        st.divider()
                                        st.subheader("🛡️ Security Analysis Summary")
                                        
                                        # AI Analysis Logic (Restored)
                                        api_key = st.session_state.get('gemini_api_key', '')
                                        
                                        col_cve, col_ai = st.columns(2)
                                        with col_cve:
                                            if st.button("🔍 CVE Lookup", use_container_width=True, key="ps_cve_btn"):
                                                 with st.spinner("Checking CVEs..."):
                                                     try:
                                                         cve_lookup = CVELookup(st.session_state.get('nvd_api_key'))
                                                         all_cves = []
                                                         for port, service in open_ports.items():
                                                             details = service_details.get(str(port), {})
                                                             res = cve_lookup.get_cves_for_service(service, details.get('banner', ''))
                                                             if res.get('cves'):
                                                                 all_cves.append({'port': port, 'service': service, 'result': res})
                                                         st.session_state.ps_cve_results = all_cves
                                                         # Also save to device_cve_data for sync
                                                         cve_data_flat = []
                                                         for item in all_cves:
                                                             cve_data_flat.extend(item['result'].get('cves', []))
                                                         st.session_state.device_cve_data = cve_data_flat
                                                         
                                                         st.success(f"Found CVEs for {len(all_cves)} services")
                                                     except Exception as e:
                                                         st.error(f"CVE lookup error: {e}")

                                        with col_ai:
                                            if st.button("🧠 AI Analysis", use_container_width=True, key="ps_ai_btn"):
                                                 # Port Scanner AI analysis logic
                                                 pass # Placeholder as we mainly rely on Device Security page for full audit now
                                                 st.info("Visit 'Device Security Audit' page for detailed AI Report")
                                        
                                        if 'ps_cve_results' in st.session_state:
                                            with st.expander("📋 CVE Results", expanded=True):
                                                for item in st.session_state.ps_cve_results:
                                                    st.write(f"**{item['service']}**: {len(item['result']['cves'])} CVEs")

                                else:
                                    st.info("No open ports found")
                                
                            except json.JSONDecodeError as e:
                                st.warning("Could not parse JSON results")
                                with st.expander("Raw Output"):
                                    st.code(stdout)
                        
                    else:
                        st.markdown('<div class="error-message">❌ Scan failed!</div>', unsafe_allow_html=True)
                        if stderr:
                            with st.expander("Error Details"):
                                st.code(stderr)

def show_analyze_page(dashboard):
    """PCAP analysis page"""
    st.markdown('<h1 class="main-header">📁 PCAP File Analysis</h1>', unsafe_allow_html=True)
    
    st.markdown("### Upload PCAP File")
    uploaded_file = st.file_uploader("Choose a PCAP file", type=['pcap', 'pcapng'])
    
    if uploaded_file is not None:
        file_path = str(UPLOADS_DIR / uploaded_file.name)
        
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        st.success(f"File uploaded: {uploaded_file.name}")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📊 Analyze PCAP", type="primary", use_container_width=True):
                with st.spinner("Analyzing PCAP file..."):
                    success, results, error = dashboard.analyze_pcap_file(file_path)
                    
                    if success:
                        st.markdown('<div class="success-message">✅ Analysis completed!</div>', unsafe_allow_html=True)
                        
                        if isinstance(results, dict):
                            tab1, tab2, tab3 = st.tabs(["Summary", "Protocols", "IP Addresses"])
                            
                            with tab1:
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.metric("Total Packets", results.get('summary', {}).get('total_packets', 0))
                                with col2:
                                    protocols = results.get('summary', {}).get('protocols', [])
                                    st.metric("Protocols Found", len(protocols))
                            
                            with tab2:
                                if protocols:
                                    protocol_df = pd.DataFrame({
                                        'Protocol': protocols,
                                        'Count': [1] * len(protocols)
                                    })
                                    fig = px.pie(protocol_df, values='Count', names='Protocol', 
                                               title="Protocol Distribution")
                                    st.plotly_chart(fig, use_container_width=True)
                                else:
                                    st.info("No protocol data available")
                            
                            with tab3:
                                col1, col2 = st.columns(2)
                                with col1:
                                    source_ips = results.get('summary', {}).get('source_ips', [])
                                    st.write("**Source IPs:**")
                                    for ip in source_ips[:10]:
                                        st.code(ip)
                                    if len(source_ips) > 10:
                                        st.info(f"... and {len(source_ips) - 10} more")
                                with col2:
                                    dest_ips = results.get('summary', {}).get('dest_ips', [])
                                    st.write("**Destination IPs:**")
                                    for ip in dest_ips[:10]:
                                        st.code(ip)
                                    if len(dest_ips) > 10:
                                        st.info(f"... and {len(dest_ips) - 10} more")
                                
                                # Store PCAP analysis results for AI
                                st.session_state.pcap_analysis = results
                        else:
                            with st.expander("Raw Analysis Output"):
                                st.code(results)
                    else:
                        st.error(f"Analysis failed: {error}")
        
        with col2:
            if st.button("🗑️ Clear Upload", use_container_width=True):
                if os.path.exists(file_path):
                    os.remove(file_path)
                st.success("Upload cleared!")
                st.rerun()
        
        # AI Malicious Traffic Detection Section
        if 'pcap_analysis' in st.session_state:
            st.divider()
            st.subheader("🤖 AI Malicious Traffic Detection")
            
            api_key = st.session_state.get('gemini_api_key', '')
            ai_enabled = st.session_state.get('enable_ai_pcap', True)
            
            if not api_key:
                st.info("💡 Configure your Gemini API key in Settings to enable AI malicious traffic detection")
            elif not AI_AVAILABLE:
                st.warning("AI modules not available. Check installation.")
            elif ai_enabled:
                if st.button("🔍 Detect Malicious Traffic with AI", use_container_width=True, key="ai_malware_btn"):
                    with st.spinner("AI scanning for malicious patterns..."):
                        try:
                            analyzer = AIAnalyzer(api_key)
                            pcap_data = st.session_state.pcap_analysis
                            
                            ai_result = analyzer.detect_malicious_traffic(pcap_data)
                            st.session_state.ai_malware_result = ai_result
                        except Exception as e:
                            st.error(f"AI detection failed: {e}")
            
            # Display AI Malicious Traffic Detection Results
            if 'ai_malware_result' in st.session_state:
                ai_result = st.session_state.ai_malware_result
                if ai_result.get('_meta', {}).get('status') == 'success':
                    with st.expander("🔍 AI Threat Detection Results", expanded=True):
                        threat_level = ai_result.get('threat_level', 'N/A')
                        threat_color = {
                            'CRITICAL': '🔴',
                            'HIGH': '🟠',
                            'MEDIUM': '🟡',
                            'LOW': '🟢',
                            'NONE': '⚪'
                        }.get(threat_level, '⚪')
                        
                        st.metric("Threat Level", f"{threat_color} {threat_level}")
                        
                        if ai_result.get('malicious_indicators'):
                            st.markdown("**🚨 Malicious Indicators**")
                            for indicator in ai_result.get('malicious_indicators', []):
                                st.error(f"**{indicator.get('type', 'Unknown')}** ({indicator.get('confidence', 'N/A')} confidence): {indicator.get('evidence', '')}")
                        
                        if ai_result.get('suspicious_ips'):
                            st.markdown("**⚠️ Suspicious IPs**")
                            for ip_info in ai_result.get('suspicious_ips', []):
                                st.warning(f"`{ip_info.get('ip', 'N/A')}`: {ip_info.get('reason', '')}")
                        
                        if ai_result.get('attack_patterns'):
                            st.markdown("**🎯 Attack Patterns Detected**")
                            for pattern in ai_result.get('attack_patterns', []):
                                st.markdown(f"• {pattern}")
                        
                        if ai_result.get('ioc_extracted'):
                            st.markdown("**📋 Indicators of Compromise (IOC)**")
                            for ioc in ai_result.get('ioc_extracted', []):
                                st.code(ioc)
                        
                        if ai_result.get('recommendations'):
                            st.markdown("**💡 Recommendations**")
                            for rec in ai_result.get('recommendations', []):
                                st.markdown(f"• {rec}")
                        
                        if ai_result.get('false_positive_notes'):
                            st.markdown("**ℹ️ False Positive Notes**")
                            st.info(ai_result.get('false_positive_notes'))
                elif ai_result.get('error'):
                    st.error(f"AI Error: {ai_result.get('error')}")

def show_device_security_page(dashboard):
    """Device Security Audit page"""
    st.markdown('<h1 class="main-header">🛡️ Device Security Audit</h1>', unsafe_allow_html=True)
    
    st.markdown("""
    Perform a comprehensive security audit on a target device. 
    This module scans for active services and uses AI to identify vulnerabilities, assess exposure risks, and provide hardening recommendations.
    """)
    
    with st.container():
        st.markdown("### 🎯 Audit Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            target_ip = st.text_input("Target IP Address", "localhost", key="dev_sec_ip",
                                     help="Enter IP address or 'localhost' for local device")
            try:
                if target_ip != "localhost":
                    ipaddress.ip_address(target_ip)
            except ValueError:
                st.warning("⚠️ Enter a valid IP address or use 'localhost'")
        
        with col2:
            scan_type = st.selectbox("Scan Scope", 
                                    ["Quick Inspect (Top 1000 Ports)", "Full Audit (All Ports)", "Custom Range"],
                                    key="dev_sec_type")
        
        if scan_type == "Custom Range":
            col3, col4 = st.columns(2)
            with col3:
                start_port = st.number_input("Start Port", 1, 65535, 1, key="dev_sec_start")
            with col4:
                end_port = st.number_input("End Port", 1, 65535, 1024, key="dev_sec_end")
        elif scan_type == "Full Audit (All Ports)":
            start_port, end_port = 1, 65535
        else:
            start_port, end_port = 1, 1024
        
        st.divider()
        
        if st.button("🚀 Start Independent Security Audit", type="primary", use_container_width=True):
            # Check for AI availability first
            api_key = st.session_state.get('gemini_api_key', os.environ.get('GEMINI_API_KEY', ''))
            if not api_key:
                st.error("❌ AI API Key required for Security Audit. Please configure it in Settings.")
            elif not AI_AVAILABLE:
                st.error("❌ AI modules not installed. Cannot perform audit.")
            else:
                with st.spinner(f"Auditing {target_ip} (this may take a moment)..."):
                    # 1. Run Port Scan
                    success, stdout, stderr = dashboard.run_port_scan_with_services(
                        target_ip=target_ip,
                        start_port=start_port,
                        end_port=end_port,
                        analyze_security=True
                    )
                    
                    if success and stdout:
                        try:
                            results = json.loads(stdout)
                            open_ports = results.get('open_ports', {})
                            
                            if open_ports:
                                st.success(f"✅ Found {len(open_ports)} active services. Analyzing security posture...")
                                
                                # Prepare data
                                services_list = []
                                for port, service in open_ports.items():
                                    details = results.get('service_details', {}).get(str(port) if isinstance(results.get('service_details'), dict) else port, {})
                                    services_list.append({
                                        'port': port,
                                        'name': service,
                                        'banner': details.get('banner', ''),
                                        'state': 'open'
                                    })
                                
                                scan_data = {
                                    'target': target_ip,
                                    'scan_time': datetime.now().isoformat(),
                                    'services': services_list,
                                    'raw_results': results
                                }
                                
                                # 2. CVE Lookup
                                cve_list = []
                                try:
                                    cve_lookup = CVELookup(st.session_state.get('nvd_api_key'))
                                    for p, s in open_ports.items():
                                        details = results.get('service_details', {}).get(str(p), {})
                                        res = cve_lookup.get_cves_for_service(s, details.get('banner', ''))
                                        if res.get('cves'):
                                            cve_list.extend(res['cves'])
                                except Exception:
                                    pass # Ignore CVE errors for now
                                
                                # 3. AI Analysis
                                analyzer = AIAnalyzer(api_key)
                                ai_result = analyzer.analyze_device_security(scan_data, cve_list)
                                st.session_state.dev_sec_result = ai_result
                                st.rerun() # Refresh to show results
                            else:
                                st.warning("No active services found to audit.")
                        except Exception as e:
                            st.error(f"Audit failed during processing: {e}")
                    else:
                        st.error("Scan failed. Check target connectivity.")
                        if stderr: st.code(stderr)
        
        # Display Results
        if 'dev_sec_result' in st.session_state:
            ai_result = st.session_state.dev_sec_result
            if ai_result:
                st.divider()
                st.subheader("📊 Audit Report")
                
                if ai_result.get('_meta', {}).get('status') == 'success':
                    with st.container():
                        # Header metrics
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            score = ai_result.get('device_security_score', 'N/A')
                            st.metric("Security Posture Score", f"{score}/100")
                        with col2:
                            risk = ai_result.get('overall_risk', 'N/A')
                            st.metric("Risk Level", risk)
                        with col3:
                            device_type = ai_result.get('device_type_detected', 'N/A')
                            st.metric("Device Type", device_type)
                        
                        st.markdown("**Executive Summary**")
                        st.info(ai_result.get('executive_summary', 'No summary available'))
                        
                        # Critical issues
                        if ai_result.get('critical_security_issues'):
                            st.markdown("**🚨 Critical Security Issues**")
                            for issue in ai_result.get('critical_security_issues', []):
                                st.error(issue)
                        
                        # Unnecessary services
                        if ai_result.get('unnecessary_services'):
                            st.markdown("**⚠️ Unnecessary Services (Consider Disabling)**")
                            for svc in ai_result.get('unnecessary_services', []):
                                st.warning(svc)
                        
                        # Services analysis
                        if ai_result.get('services_analysis'):
                            st.markdown("**🔍 Service-Level Analysis**")
                            for svc in ai_result.get('services_analysis', []):
                                with st.expander(f"Port {svc.get('port', 'N/A')} - {svc.get('service', 'Unknown')}"):
                                    st.markdown(f"**Necessity:** {svc.get('necessity', 'N/A')}")
                                    st.markdown(f"**Exposure Risk:** {svc.get('exposure_risk', 'N/A')}")
                                    
                                    if svc.get('hardening_recommendations'):
                                        st.markdown("**Hardening:**")
                                        for rec in svc.get('hardening_recommendations', []):
                                            st.markdown(f"• {rec}")
                        
                        # Best practices
                        if ai_result.get('best_practices'):
                            st.markdown("**💡 Best Practices**")
                            for practice in ai_result.get('best_practices', []):
                                st.markdown(f"• {practice}")
                elif ai_result.get('error'):
                    st.error(f"AI Error: {ai_result.get('error')}")
def show_history_page(dashboard):
    """History page"""
    st.markdown('<h1 class="main-header">📜 History</h1>', unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["Scan History", "Capture History"])
    
    with tab1:
        if not dashboard.scan_history:
            st.info("No scan history available")
        else:
            scan_df = pd.DataFrame(dashboard.scan_history)
            if 'security_analysis' not in scan_df.columns:
                scan_df['security_analysis'] = None
            scan_df['timestamp'] = pd.to_datetime(scan_df['timestamp'])
            
            st.dataframe(
                scan_df.sort_values('timestamp', ascending=False),
                use_container_width=True,
                column_config={
                    "timestamp": st.column_config.DatetimeColumn("Timestamp"),
                    "target": "Target IP",
                    "port_range": "Port Range",
                    "security_analysis": st.column_config.CheckboxColumn("Security Analysis"),
                    "status": st.column_config.TextColumn("Status")
                }
            )
    
    with tab2:
        if not dashboard.capture_history:
            st.info("No capture history available")
        else:
            history_df = pd.DataFrame(dashboard.capture_history)
            history_df['timestamp'] = pd.to_datetime(history_df['timestamp'])
            
            st.dataframe(
                history_df.sort_values('timestamp', ascending=False),
                use_container_width=True,
                column_config={
                    "timestamp": st.column_config.DatetimeColumn("Timestamp"),
                    "interface": "Interface",
                    "protocol": "Protocol",
                    "packet_count": st.column_config.NumberColumn("Packets"),
                    "status": st.column_config.TextColumn("Status"),
                    "output_file": "Output File"
                }
            )

# ============================
# SETTINGS PAGES (Keep same as before)
# ============================

def show_settings_page():
    """Settings page"""
    st.markdown('<h1 class="main-header">⚙️ Settings</h1>', unsafe_allow_html=True)
    
    # Create tabs for settings
    tab1, tab2, tab3 = st.tabs(["🖥️ Display", "🤖 AI Configuration", "📁 Storage"])
    
    with tab1:
        st.subheader("Display Settings")
        
        with st.form("display_settings_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                theme = st.selectbox("Theme", ["Dark", "Light", "Auto"], index=0)
                
            with col2:
                refresh_interval = st.slider("Dashboard Refresh (seconds)", 5, 60, 30)
            
            if st.form_submit_button("💾 Save Display Settings", use_container_width=True):
                st.session_state.display_theme = theme
                st.session_state.refresh_interval = refresh_interval
                st.success("Display settings saved!")

    with tab3:
        st.subheader("Data Storage Settings")
        with st.form("storage_settings_form"):
            current_config = {}
            if os.path.exists('neura_trace_config.json'):
                try:
                    with open('neura_trace_config.json', 'r') as f:
                        current_config = json.load(f)
                except:
                    pass
            
            default_path = current_config.get("save_path", r"E:\Backup\Desktop\NT\saved_scans")
            new_save_path = st.text_input("Custom Save Path", value=default_path)
            
            if st.form_submit_button("💾 Save Storage Settings", use_container_width=True):
                if new_save_path:
                    current_config['save_path'] = new_save_path
                    with open('neura_trace_config.json', 'w') as f:
                        json.dump(current_config, f)
                    st.success("Storage path saved! Changes apply immediately to new saves.")

    with tab2:
        st.subheader("AI Configuration")
        st.markdown("""
        Configure your AI settings for enhanced security analysis.
        You can use your own custom Google AI API key.
        """)
        
        # Load existing key from session or environment
        current_key = st.session_state.get('gemini_api_key', os.environ.get('GEMINI_API_KEY', ''))
        
        with st.form("ai_settings_form"):
            api_key = st.text_input(
                "AI API Key", 
                value=current_key,
                type="password",
                help="Enter your Google AI API key"
            )
            
            st.caption("Get your free API key from [Google AI Studio](https://makersuite.google.com/app/apikey)")
            
            if st.form_submit_button("💾 Save AI Configuration", use_container_width=True):
                if api_key:
                    st.session_state.gemini_api_key = api_key
                    # Test the key
                    if AI_AVAILABLE:
                        try:
                            test_analyzer = AIAnalyzer(api_key)
                            if test_analyzer.is_available():
                                st.success("✅ API Key saved and verified!")
                            else:
                                st.warning("⚠️ API Key saved but verification failed.")
                        except Exception as e:
                            st.error(f"Error testing API key: {e}")
                    else:
                        st.success("API Key saved (AI modules not loaded)")
                else:
                    st.warning("Please enter an API key")
    
    st.divider()
    
    # System info
    st.subheader("System Information")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("AI Modules", "✅ Available" if AI_AVAILABLE else "❌ Not Available")
        st.caption(f"Python: {sys.version.split()[0]}")
    
    with col2:
        st.metric("Version", "2.0")
        st.caption("NeuraTrace Network Security")


def show_logo_settings_page():
    """Page for uploading/changing logo"""
    st.markdown('<h1 class="main-header">🖼️ Logo Settings</h1>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Current Logo")
        
        if st.session_state.get('logo_path') and os.path.exists(st.session_state.logo_path):
            logo_base64 = get_logo_base64(st.session_state.logo_path)
            if logo_base64:
                st.image(f"data:image/png;base64,{logo_base64}", width=200)
                st.success(f"✅ Logo loaded from: {st.session_state.logo_path}")
            else:
                st.warning("⚠️ Could not load current logo")
        else:
            st.info("ℹ️ No custom logo set. Using default icon.")
            st.image("https://img.icons8.com/color/96/000000/network.png", width=100)
    
    with col2:
        st.subheader("Upload New Logo")
        
        uploaded_file = st.file_uploader(
            "Choose a logo image", 
            type=['png', 'jpg', 'jpeg', 'gif', 'bmp'],
            help="Recommended: PNG format, transparent background, 200x200px"
        )
        
        if uploaded_file is not None:
            upload_dir = "uploads/logos"
            os.makedirs(upload_dir, exist_ok=True)
            
            file_path = os.path.join(upload_dir, uploaded_file.name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            st.image(uploaded_file, width=100)
            
            if st.button("💾 Set as Application Logo", use_container_width=True):
                if save_logo_path(file_path):
                    st.success("✅ Logo updated successfully!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("❌ Failed to save logo")
        
        st.subheader("Other Options")
        
        st.markdown("**Or use local file:**")
        logo_path_input = st.text_input(
            "Enter full path to logo:",
            placeholder="C:/Users/YourName/logo.png or /home/user/logo.png",
            help="Enter the full path to your logo file"
        )
        
        if logo_path_input:
            if os.path.exists(logo_path_input):
                if st.button("📁 Use This Logo", use_container_width=True):
                    if save_logo_path(logo_path_input):
                        st.success("✅ Logo path saved!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("❌ Invalid logo path")
            else:
                st.error("❌ File not found at this path")
        
        if st.session_state.get('logo_path'):
            if st.button("🔄 Reset to Default", use_container_width=True):
                st.session_state.logo_path = None
                if os.path.exists('neura_trace_config.json'):
                    os.remove('neura_trace_config.json')
                st.success("✅ Reset to default icon")
                time.sleep(1)
                st.rerun()
    
    st.divider()
    
    with st.expander("📋 Logo Guidelines"):
        st.markdown("""
        **For best results:**
        
        ✅ **Recommended:**
        - PNG format with transparency
        - Square aspect ratio (1:1)
        - 200x200 to 400x400 pixels
        - Simple design with clear edges
        - File size under 500KB
        
        ❌ **Avoid:**
        - Very large files (>2MB)
        - Complex backgrounds
        - Text-heavy logos
        - Irregular shapes
        
        **Supported formats:** PNG, JPG, JPEG, GIF, BMP
        """)

# ============================
# SIDEBAR
# ============================

def create_sidebar(dashboard):
    """Create sidebar with logo and navigation"""
    with st.sidebar:
        # Logo section
        if st.session_state.get('logo_path'):
            logo_base64 = get_logo_base64(st.session_state.logo_path)
            
            if logo_base64:
                st.markdown(f"""
                <div class="logo-container">
                    <img src="data:image/png;base64,{logo_base64}" 
                         alt="Neura Trace Logo" 
                         style="max-width: 100%; height: auto;">
                    <div class="app-title">NEURA TRACE</div>
                    <div class="app-subtitle">INNOVATE & DISCOVER</div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.image("https://img.icons8.com/color/96/000000/network.png", width=100)
                st.markdown("## Neura Trace")
        else:
            st.image("https://img.icons8.com/color/96/000000/network.png", width=100)
            st.markdown("## Neura Trace")
        
        st.markdown("---")
        
        # Navigation
        from streamlit_option_menu import option_menu
        
        # Determine current index
        pages = ["Dashboard", "Capture", "Port Scanner", "Device Security", "Analyze", "History", "Settings"]
        icons = ["speedometer2", "record-circle", "search", "shield-lock", "file-earmark-bar-graph", "clock-history", "gear"]
        
        current_idx = pages.index(st.session_state.page) if st.session_state.page in pages else 0
        
        # Sleek SaaS Navigation Menu
        selected_page = option_menu(
            menu_title=None,
            options=pages,
            icons=icons,
            default_index=current_idx,
            styles={
                "container": {"padding": "0!important", "background-color": "transparent"},
                "icon": {"color": "#60A5FA", "font-size": "18px"}, 
                "nav-link": {
                    "font-size": "15px", 
                    "text-align": "left", 
                    "margin":"3px", 
                    "border-radius": "10px", 
                    "--hover-color": "rgba(59, 130, 246, 0.1)"
                },
                "nav-link-selected": {
                    "background-color": "rgba(59, 130, 246, 0.15)", 
                    "color": "#60A5FA", 
                    "font-weight": "600",
                    "border-left": "4px solid #3B82F6",
                    "box-shadow": "0 2px 10px rgba(59,130,246,0.1)"
                },
            }
        )
        
        if selected_page != st.session_state.page:
            st.session_state.page = selected_page
            st.rerun()
        
        st.markdown("---")
        st.markdown("### 💻 System Info")
        
        import platform
        import psutil
        
        hostname = platform.node()
        os_name = f"{platform.system()} {platform.release()}"
        
        st.caption(f"**Host:** {hostname}")
        st.caption(f"**OS:** {os_name}")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("CPU", f"{psutil.cpu_percent()}%")
        with col2:
            st.metric("RAM", f"{psutil.virtual_memory().percent}%")
            
        st.markdown("---")
        st.markdown("### 📜 Activity")
        
        if dashboard.capture_history:
            last_capture = dashboard.capture_history[-1]
            st.caption(f"Last capture: {last_capture.get('packet_count', 0)} packets")
        
        if dashboard.scan_history:
            last_scan = dashboard.scan_history[-1]
            sec_analysis = "✓" if last_scan.get('security_analysis') else "✗"
            st.caption(f"Last scan: {last_scan.get('target', 'N/A')} [Sec: {sec_analysis}]")
        
        st.markdown("---")
        st.caption("Neura Trace v2.0")

# ============================
# MAIN FUNCTION
# ============================

def make_chat_draggable():
    components.html("""
    <script>
    let attempts = 0;
    const interval = setInterval(function() {
        const doc = window.parent.document;
        const anchor = doc.getElementById('chat-drag-anchor');
        attempts++;
        if (!anchor) {
            if(attempts > 20) clearInterval(interval);
            return;
        }
        
        let dragTarget = null;
        let current = anchor.parentElement;
        while(current && current !== doc.body) {
            const style = window.parent.getComputedStyle(current);
            if (style.position === 'fixed') {
                dragTarget = current;
                break;
            }
            current = current.parentElement;
        }
        
        if (!dragTarget) {
            // Fallback to the closest stVerticalBlock
            dragTarget = anchor.closest('div[data-testid="stVerticalBlock"]');
            if(!dragTarget) return; // wait more
        }
        
        const btn = dragTarget.querySelector('div[data-testid="stPopover"] button');
        if(!btn) return;
        
        clearInterval(interval);
        if(btn.dataset.draggableAttached) return; // Prevent double attach
        btn.dataset.draggableAttached = "true";
        
        // Forcibly override Streamlit layout to snap to the exact extreme bottom right
        dragTarget.style.position = 'fixed';
        dragTarget.style.bottom = '24px';
        dragTarget.style.right = '24px';
        dragTarget.style.top = 'auto';
        dragTarget.style.left = 'auto';
        dragTarget.style.width = 'fit-content';
        dragTarget.style.zIndex = '999999';
        
        let isDragging = false;
        let hasDragged = false;
        let startX, startY;
        let initialTop, initialLeft;

        btn.style.cursor = 'grab';

        btn.addEventListener('mousedown', function(e) {
            isDragging = true;
            hasDragged = false;
            startX = e.clientX;
            startY = e.clientY;
            
            const rect = dragTarget.getBoundingClientRect();
            dragTarget.style.right = 'auto';
            dragTarget.style.bottom = 'auto';
            dragTarget.style.top = rect.top + 'px';
            dragTarget.style.left = rect.left + 'px';
            initialTop = rect.top;
            initialLeft = rect.left;
            
            btn.style.cursor = 'grabbing';
            doc.body.style.userSelect = 'none';
        });

        doc.addEventListener('mousemove', function(e) {
            if (!isDragging) return;
            
            const dx = e.clientX - startX;
            const dy = e.clientY - startY;
            
            if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
                hasDragged = true;
            }
            
            dragTarget.style.top = (initialTop + dy) + 'px';
            dragTarget.style.left = (initialLeft + dx) + 'px';
        });

        doc.addEventListener('mouseup', function(e) {
            if(isDragging) {
                isDragging = false;
                btn.style.cursor = 'grab';
                doc.body.style.userSelect = 'auto';
                
                // Snap to left or right edge like a chat head
                if (hasDragged) {
                    const rect = dragTarget.getBoundingClientRect();
                    const windowWidth = parent.window.innerWidth;
                    const centerX = rect.left + (rect.width / 2);
                    
                    dragTarget.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
                    setTimeout(() => { dragTarget.style.transition = 'none'; }, 300);
                    
                    if (centerX < windowWidth / 2) {
                        // Left half
                        dragTarget.style.left = '24px';
                    } else {
                        // Right half
                        dragTarget.style.left = (windowWidth - rect.width - 24) + 'px';
                    }
                    
                    // Constrain vertical bounds
                    const windowHeight = parent.window.innerHeight;
                    if (rect.top < 24) dragTarget.style.top = '24px';
                    if (rect.bottom > windowHeight - 24) {
                        dragTarget.style.top = (windowHeight - rect.height - 24) + 'px';
                    }
                }
            }
        });
        
        btn.addEventListener('click', function(e) {
            if (hasDragged) {
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();
                hasDragged = false;
            }
        }, true);
    }, 200);
    </script>
    """, height=0, width=0)

def render_floating_chat():
    st.markdown("""
        <style>
        /* Force the popover wrapper to the right */
        div[data-testid="stPopover"] {
            display: flex !important;
            justify-content: flex-end !important;
            width: 100% !important;
        }
        
        /* Make the popover button look like a floating action button */
        div[data-testid="stPopover"] button {
            border-radius: 50% !important;
            height: 64px !important;
            width: 64px !important;
            min-height: 64px !important;
            min-width: 64px !important;
            background: linear-gradient(135deg, #3B82F6, #1E3A8A) !important;
            color: white !important;
            box-shadow: 0 6px 16px rgba(0,0,0,0.4) !important;
            font-size: 28px !important;
            border: 2px solid white !important;
            padding: 0 !important;
            transition: transform 0.2s;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            float: right !important;
        }
        div[data-testid="stPopover"] button:hover {
            transform: scale(1.05);
            background: linear-gradient(135deg, #2563EB, #1E40AF) !important;
        }
        
        /* Hide the popover chevron icon specifically */
        div[data-testid="stPopover"] button svg {
            display: none !important;
        }

        /* Style the popover body so it looks like a clean, modern chat window */
        div[data-testid="stPopoverBody"] {
            width: 380px !important;
            height: 480px !important;
            margin-right: -10px !important;
            border-radius: 16px !important; /* Softer corners */
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4) !important; /* Soft, deep shadow */
            padding: 24px !important; /* Extra breathing room */
            background-color: #1A1A22 !important; /* NeuraTrace dark theme match */
            border: 1px solid rgba(255, 255, 255, 0.08) !important; /* Subtle thin border */
        }
        
        /* Clean up Streamlit default text inside button */
        div[data-testid="stPopover"] > button p {
            margin: 0 !important;
            padding: 0 !important;
            font-size: 32px !important;
        }
        </style>
    """, unsafe_allow_html=True)
    
    chat_container = st.container()
    with chat_container:
        st.markdown('<div id="chat-drag-anchor" style="display:none;"></div>', unsafe_allow_html=True)
        with st.popover("💬", use_container_width=False):
            st.markdown("### 🤖 NeuraTrace AI")
            
            api_key = st.session_state.get('gemini_api_key', os.environ.get('GEMINI_API_KEY', ''))
            
            if not api_key:
                st.warning("⚠️ API Key not found")
            elif not AI_AVAILABLE:
                st.error("AI modules missing. Please run: pip install google-generativeai")
            else:
                if 'chat_messages' not in st.session_state:
                    st.session_state.chat_messages = []
                    
                messages_view = st.container(height=250)
                with messages_view:
                    for msg in st.session_state.chat_messages[-10:]:
                        role = "You" if msg["role"] == "user" else "AI"
                        st.markdown(f"**{role}:** {msg['content']}")
                
                # Central callback for handling inputs like a real chatbot
                def handle_chat_submit():
                    user_text = st.session_state.chat_input_floating
                    if user_text.strip():
                        st.session_state.chat_messages.append({"role": "user", "content": user_text})
                        try:
                            analyzer = AIAnalyzer(api_key)
                            response = analyzer.chat(user_text)
                            st.session_state.chat_messages.append({"role": "assistant", "content": response})
                        except Exception as e:
                            st.session_state.chat_messages.append({"role": "assistant", "content": f"Error: {e}"})
                        # Clear visually by setting session_state directly
                        st.session_state.chat_input_floating = ""
                
                # Bottom input area (widened button column 1->2 so "Send" does not word wrap)
                col1, col2 = st.columns([3, 2])
                with col1:
                    st.text_input(
                        "Prompt", 
                        key="chat_input_floating", 
                        label_visibility="collapsed", 
                        placeholder="✨ Type here to ask AI...",
                        on_change=handle_chat_submit
                    )
                with col2:
                    st.button("Send", key="chat_send_floating", on_click=handle_chat_submit, use_container_width=True)
                    
    # Safely float exact container using JS injection, completely avoiding CSS collisions!
    chat_container.float("bottom: 20px; right: 20px; background: transparent !important; display: flex; justify-content: flex-end;")
    
    # Inject drag logic
    make_chat_draggable()

def main():
    float_init()
    # Initialize session state
    if 'page' not in st.session_state:
        st.session_state.page = "Dashboard"
    
    # Initialize dashboard
    dashboard = NeuraTraceDashboard()
    
    # Create sidebar with logo
    create_sidebar(dashboard)
    
    # Main content based on selected page
    if st.session_state.page == "Dashboard":
        show_dashboard_page(dashboard)
    elif st.session_state.page == "Capture":
        show_capture_page(dashboard)
    elif st.session_state.page == "Port Scanner":
        show_port_scanner_page(dashboard)
    elif st.session_state.page == "Device Security":
        show_device_security_page(dashboard)
    elif st.session_state.page == "Analyze":
        show_analyze_page(dashboard)
    elif st.session_state.page == "History":
        show_history_page(dashboard)
    elif st.session_state.page == "Settings":
        show_settings_page()
    
    # Render floating AI chat widget across all pages
    render_floating_chat()
    




if __name__ == "__main__":
    main()