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
from crypto_vault import vault
from PIL import Image
import io
import logging
from streamlit_float import *
import streamlit.components.v1 as components
import requests
try:
    from streamlit_lottie import st_lottie
except ImportError:
    pass
import jwt
from datetime import timedelta
import db_manager
import platform
import psutil

# API Configuration - Load from .env instead of hardcoding
if os.path.exists('.env'):
    with open('.env') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                k, v = line.strip().split('=', 1)
                os.environ[k.strip()] = v.strip().strip("'\"")

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

# Config file lives in the custom save directory, not the project folder
# NEURATRACE_DATA_DIR env var is injected by Docker — falls back to local Windows path
_DEFAULT_SAVE_PATH = os.environ.get("NEURATRACE_DATA_DIR", r"E:\Backup\Desktop\NT\saved_scans")
_CONFIG_FILE = os.path.join(_DEFAULT_SAVE_PATH, 'neura_trace_config.json')

def save_logo_path(logo_path):
    """Save logo path to config file inside DATA_DIR"""
    if logo_path and os.path.exists(logo_path):
        st.session_state.logo_path = logo_path
        os.makedirs(_DEFAULT_SAVE_PATH, exist_ok=True)
        config = {"logo_path": logo_path}
        with open(_CONFIG_FILE, 'w') as f:
            json.dump(config, f)
        return True
    return False

def load_logo_config():
    """Load logo path from config file in DATA_DIR"""
    try:
        if os.path.exists(_CONFIG_FILE):
            with open(_CONFIG_FILE, 'r') as f:
                config = json.load(f)
                return config.get('logo_path')
    except:
        pass
    return None

# ============================
# JWT SECURITY HELPERS
# ============================

def create_jwt_token(username):
    """Generate a signed JWT token valid for 4 hours"""
    secret = os.environ.get("VAULT_MASTER_KEY_B64", "fallback_secret_key_neuratrace")
    payload = {
        "user": username,
        "exp": datetime.utcnow() + timedelta(hours=4),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, secret, algorithm="HS256")

def verify_jwt_token(token):
    """Decode and verify the JWT token"""
    if not token:
        return False
    secret = os.environ.get("VAULT_MASTER_KEY_B64", "fallback_secret_key_neuratrace")
    try:
        jwt.decode(token, secret, algorithms=["HS256"])
        return True
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return False

def get_ai_brain():
    """Safely construct the AI backend without crashing the dashboard."""
    try:
        from ai_brain import AIBrain

        brain = AIBrain(
            gemini_api_key=os.environ.get("GEMINI_API_KEY", ""),
            groq_api_key=os.environ.get("GROQ_API_KEY", ""),
        )
        return brain, None
    except Exception as exc:
        return None, f"AI assistant unavailable: {exc}"

def get_ai_status(brain=None, error_message=None):
    """Return a simple AI status label and detail message."""
    if error_message:
        return "Unavailable", error_message
    if brain is None:
        return "Unavailable", "AI assistant unavailable."
    if brain.is_available():
        return "Ready", getattr(brain, "status_message", "AI assistant ready.")
    return "Unavailable", getattr(brain, "status_message", "Missing GEMINI_API_KEY.")

def render_ai_verdict(verdict, fallback_message):
    """Render verdict-style AI responses consistently."""
    if not verdict:
        st.warning(fallback_message)
    elif "[SAFE]" in verdict:
        st.success(verdict)
    else:
        st.error(verdict)

def show_ai_analysis_result(callback):
    """Execute an AI verdict analysis when the backend is available."""
    brain, ai_error = get_ai_brain()
    _, ai_status_message = get_ai_status(brain, ai_error)

    if brain is None or not brain.is_available():
        st.info(ai_status_message)
        return

    try:
        verdict = callback(brain)
    except Exception as exc:
        st.warning(f"AI assistant unavailable: {exc}")
        return

    render_ai_verdict(verdict, ai_status_message)

def build_scan_context(dashboard):
    """Summarize the latest port scan for the AI assistant."""
    if not dashboard.scan_history:
        return ""

    latest_scan = dashboard.scan_history[-1]
    lines = [
        "Latest port scan context:",
        f"- Target: {latest_scan.get('target', 'N/A')}",
        f"- Status: {latest_scan.get('status', 'unknown')}",
        f"- Timestamp: {latest_scan.get('timestamp', 'N/A')}",
    ]

    stdout = latest_scan.get("stdout", "")
    if stdout:
        try:
            results = json.loads(stdout)
            open_ports = results.get("open_ports", {})
            if open_ports:
                services = [f"{port}/{service}" for port, service in list(open_ports.items())[:10]]
                lines.append(f"- Open services: {', '.join(services)}")
            security_analysis = results.get("security_analysis", {})
            if security_analysis:
                lines.append(
                    f"- Security score: {security_analysis.get('security_score', 'N/A')} "
                    f"(risk: {security_analysis.get('risk_level', 'N/A')})"
                )
        except (json.JSONDecodeError, TypeError, ValueError):
            lines.append(f"- Raw scan excerpt: {stdout[:400]}")

    return "\n".join(lines)

def build_capture_context(dashboard):
    """Summarize the latest packet capture for the AI assistant."""
    latest_capture = st.session_state.get("last_capture")
    if latest_capture is None and dashboard.capture_history:
        latest_capture = dashboard.capture_history[-1]
    if not latest_capture:
        return ""

    lines = [
        "Latest capture context:",
        f"- Interface: {latest_capture.get('interface', 'N/A')}",
        f"- Protocol filter: {latest_capture.get('protocol', 'All')}",
        f"- Packet count: {latest_capture.get('packet_count', 'N/A')}",
        f"- Output file: {latest_capture.get('output_file', 'N/A')}",
    ]

    stdout = latest_capture.get("stdout", "")
    if stdout:
        lines.append(f"- Capture excerpt: {stdout[:400]}")

    return "\n".join(lines)

def build_pcap_context():
    """Summarize the latest PCAP analysis for the AI assistant."""
    results = st.session_state.get("pcap_analysis")
    if not isinstance(results, dict):
        return ""

    summary = results.get("summary", {})
    protocols = summary.get("protocols", [])
    source_ips = summary.get("source_ips", [])
    dest_ips = summary.get("dest_ips", [])

    lines = [
        "Latest PCAP analysis context:",
        f"- Total packets: {summary.get('total_packets', 0)}",
        f"- Protocols: {', '.join(protocols[:10]) if protocols else 'None detected'}",
        f"- Source IP sample: {', '.join(source_ips[:5]) if source_ips else 'No source IPs'}",
        f"- Destination IP sample: {', '.join(dest_ips[:5]) if dest_ips else 'No destination IPs'}",
    ]

    return "\n".join(lines)

def collect_ai_context_sections(dashboard):
    """Collect recent telemetry summaries that the assistant can use."""
    sections = [build_scan_context(dashboard), build_capture_context(dashboard), build_pcap_context()]
    return [section for section in sections if section]

def build_ai_context(dashboard):
    """Combine recent telemetry into a single assistant context payload."""
    return "\n\n".join(collect_ai_context_sections(dashboard))

def ensure_ai_chat_state():
    """Initialize assistant chat history once per session."""
    if "ai_messages" not in st.session_state:
        st.session_state.ai_messages = [{
            "role": "assistant",
            "content": (
                "I am ready to review your latest scans, packet captures, and PCAP analysis. "
                "Ask for a summary, risk assessment, or hardening steps."
            ),
        }]

def submit_ai_prompt(dashboard, prompt):
    """Store a user prompt and append the assistant response."""
    clean_prompt = (prompt or "").strip()
    if not clean_prompt:
        return

    ensure_ai_chat_state()
    st.session_state.ai_messages.append({"role": "user", "content": clean_prompt})

    brain, ai_error = get_ai_brain()
    _, ai_status_message = get_ai_status(brain, ai_error)
    context = build_ai_context(dashboard)

    if brain is None or not brain.is_available():
        reply = ai_status_message
        if context:
            reply = f"{reply}\n\nRecent telemetry available for review:\n{context}"
        else:
            reply = f"{reply}\n\nRun a scan, capture, or PCAP analysis to give the assistant more context."
    else:
        reply = brain.ask_assistant(clean_prompt, context=context)

    st.session_state.ai_messages.append({"role": "assistant", "content": reply})

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
    
    /* Hide specific unwanted elements without breaking the sidebar toggle */
    [data-testid="stToolbar"], [data-testid="stDeployButton"] {
        display: none !important;
    }
    #MainMenu { display: none !important; }
    
    /* Ensure header is visible but transparent, allowing the sidebar button to show */
    header[data-testid="stHeader"] {
        background: rgba(0,0,0,0) !important;
        height: 3rem !important;
    }

    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, rgba(3, 7, 18, 0.97) 0%, rgba(15, 23, 42, 0.98) 100%) !important;
        border-right: 1px solid rgba(96, 165, 250, 0.18) !important;
    }

    section[data-testid="stSidebar"] .block-container {
        padding-top: 1rem !important;
    }

    @media (min-width: 769px) {
        section[data-testid="stSidebar"] {
            min-width: 20rem !important;
            max-width: 20rem !important;
        }
        section[data-testid="stSidebar"][aria-expanded="false"] {
            min-width: 20rem !important;
            max-width: 20rem !important;
            transform: translateX(0) !important;
            visibility: visible !important;
        }
        section[data-testid="stSidebar"][aria-expanded="false"] > div:first-child,
        section[data-testid="stSidebar"][aria-expanded="true"] > div:first-child {
            width: 20rem !important;
        }
        section[data-testid="stSidebar"][aria-expanded="false"] + section[data-testid="stMain"] {
            margin-left: 20rem !important;
        }
    }
    
    footer { visibility: hidden; }
    
    #root > div:first-child > div > div > div > div > section > div {
        padding-top: 2rem !important;
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
        text-align: center !important;
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

    /* Redesigned Login CSS */
    .login-box {
        background: rgba(17, 24, 39, 0.7) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 20px !important;
        padding: 40px !important;
        box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5) !important;
    }
    
    .stTextInput > div > div > input {
        background-color: rgba(55, 65, 81, 0.5) !important;
        color: white !important;
        border-radius: 12px !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        padding: 12px 16px !important;
    }
    
    .stTextInput label {
        color: #9CA3AF !important;
        font-weight: 500 !important;
        margin-bottom: 8px !important;
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

    /* Floating AI assistant bubble */
    div:has(> .element-container div.ai-bubble-scope) .stButton > button {
        width: 4rem !important;
        height: 4rem !important;
        min-width: 4rem !important;
        border-radius: 999px !important;
        padding: 0 !important;
        margin: 0 !important;
        background: linear-gradient(135deg, #0EA5E9 0%, #2563EB 55%, #7C3AED 100%) !important;
        color: white !important;
        border: 1px solid rgba(255, 255, 255, 0.2) !important;
        box-shadow: 0 18px 45px rgba(37, 99, 235, 0.35) !important;
        font-size: 0.95rem !important;
        font-weight: 800 !important;
        letter-spacing: 0.08em !important;
    }
    div:has(> .element-container div.ai-bubble-scope) .stButton > button:hover {
        transform: translateY(-2px) scale(1.03) !important;
        box-shadow: 0 24px 55px rgba(14, 165, 233, 0.4) !important;
    }
    div:has(> .element-container div.ai-bubble-scope) .stButton > button:focus {
        box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.2), 0 18px 45px rgba(37, 99, 235, 0.35) !important;
    }

    /* Floating assistant panel */
    div:has(> .element-container div.ai-panel-scope) .block-container {
        padding-top: 0 !important;
    }
    div:has(> .element-container div.ai-panel-scope) [data-testid="stVerticalBlock"] {
        gap: 0.65rem !important;
    }
    div:has(> .element-container div.ai-panel-scope) .stTextArea textarea {
        min-height: 5rem !important;
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

    components.html(
        """
        <script>
        const expandSidebar = () => {
            const doc = window.parent.document;
            const sidebar = doc.querySelector('section[data-testid="stSidebar"]');
            if (!sidebar || window.parent.innerWidth < 769) return;
            if (sidebar.getAttribute('aria-expanded') !== 'false') return;

            const toggleButton =
                doc.querySelector('[data-testid="collapsedControl"] button') ||
                doc.querySelector('button[aria-label="Open sidebar"]') ||
                doc.querySelector('button[kind="headerNoPadding"]');

            if (toggleButton) {
                toggleButton.click();
            }
        };

        setTimeout(expandSidebar, 100);
        setTimeout(expandSidebar, 700);
        </script>
        """,
        height=0,
        width=0,
    )

# Inject Custom SaaS CSS globally
inject_css()

# ============================
# DASHBOARD CLASS
# ============================

def load_app_config():
    """Load app configurations from config file in DATA_DIR"""
    config = {
        "save_path": _DEFAULT_SAVE_PATH
    }
    try:
        if os.path.exists(_CONFIG_FILE):
            with open(_CONFIG_FILE, 'r') as f:
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
        """Load history from private encrypted vault directory"""
        capture_history_file = HISTORY_DIR / 'capture_history.json'
        scan_history_file = HISTORY_DIR / 'scan_history.json'
        
        try:
            if capture_history_file.exists():
                decrypted = vault.read_and_decrypt(str(capture_history_file))
                if decrypted:
                    self.capture_history = json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            logging.warning(f"Could not load secure capture history: {e}")
            self.capture_history = []
        
        try:
            if scan_history_file.exists():
                decrypted = vault.read_and_decrypt(str(scan_history_file))
                if decrypted:
                    self.scan_history = json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            logging.warning(f"Could not load secure scan history: {e}")
            self.scan_history = []
    
    def save_history(self):
        """Save history to private encrypted vault directory"""
        try:
            data = json.dumps(self.capture_history, indent=2).encode('utf-8')
            vault.encrypt_and_save(data, str(HISTORY_DIR / 'capture_history.json'))
        except Exception as e:
            logging.error(f"Could not secure save capture history: {e}")
        
        try:
            data = json.dumps(self.scan_history, indent=2).encode('utf-8')
            vault.encrypt_and_save(data, str(HISTORY_DIR / 'scan_history.json'))
        except Exception as e:
            logging.error(f"Could not secure save scan history: {e}")
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        try:
            import psutil
            interfaces = psutil.net_if_addrs()
            return list(interfaces.keys())
        except:
            return ['eth0', 'wlan0', 'en0', 'lo', 'any']
    
    def _send_ipc_request(self, payload):
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(300)
            client.connect(('127.0.0.1', 50051))
            client.sendall(json.dumps(payload).encode('utf-8'))
            
            response_data = b""
            while True:
                chunk = client.recv(4096)
                if not chunk: break
                response_data += chunk
            
            client.close()
            resp = json.loads(response_data.decode('utf-8'))
            return resp.get("status") == "success", resp.get("stdout", ""), resp.get("stderr", "")
        except Exception as e:
            return False, "", f"IPC Daemon Error: {str(e)}"
            
    def run_capture(self, interface, count, protocol, output_file):
        """Run packet capture using the CLI tool"""
        import re
        try:
            # JWT Authentication Check
            if not verify_jwt_token(st.session_state.auth_token):
                return False, "", "Please login to continue"

            # Input validation
            if not re.match(r'^[a-zA-Z0-9.\-_ \(\)]+$', interface):
                return False, "", "Security Violation: Invalid network interface characters"
            if not isinstance(count, int) or not (1 <= count <= 50000):
                return False, "", "Security Violation: Packet count exceeds hard limits (50000 max)"

            safe_out = os.path.abspath(output_file)
            allowed_base = os.path.abspath(str(DATA_DIR))
            if not safe_out.startswith(allowed_base):
                return False, "", "Security Violation: Output path must be within the configured save directory"

            req = {
                "action": "capture",
                "interface": interface,
                "count": count,
                "output": safe_out
            }
            
            success, stdout, stderr = self._send_ipc_request(req)

            # Log to Local History (Legacy)
            capture_info = {
                'timestamp': datetime.now().isoformat(),
                'interface': interface,
                'protocol': protocol or 'All',
                'packet_count': count,
                'output_file': safe_out,
                'status': 'success' if success else 'failed',
                'stdout': stdout,
                'stderr': stderr
            }
            self.capture_history.append(capture_info)
            self.save_history()

            # Global Unified History Logging
            if st.session_state.user_info:
                db_manager.add_to_global_history(
                    user_id=st.session_state.user_info['id'],
                    node_id=socket.gethostname(),
                    scan_type="Capture",
                    target=interface,
                    status="success" if success else "failed",
                    local_path=safe_out
                )

            return success, stdout, stderr
        except Exception as e:
            return False, "", str(e)
    
    def run_port_scan_with_services(self, target_ip, start_port, end_port, analyze_security=False):
        """Run port scan with integrated service detection"""
        import re
        try:
            # STRICT TARGET VALIDATION (IPv4/v6 or safe hostname)
            if not re.match(r'^[a-zA-Z0-9.\-_]+$', target_ip):
                 return False, "", "Security Violation: Invalid target format"
             
            # JWT Authentication Check
            if not verify_jwt_token(st.session_state.auth_token):
                return False, "", "Please login to continue"

            # Validate input
            if not self._validate_scan_request(target_ip, start_port, end_port):
                return False, "", "Validation failed"
            
            req = {
                "action": "port_scan",
                "target": target_ip,
                "ports": f'{start_port}-{end_port}'
            }
            
            success, stdout, stderr = self._send_ipc_request(req)
            
            # Log to Local History (Legacy)
            scan_info = {
                'timestamp': datetime.now().isoformat(),
                'target': target_ip,
                'port_range': f'{start_port}-{end_port}',
                'security_analysis': analyze_security,
                'status': 'success' if success else 'failed',
                'stdout': stdout,
                'stderr': stderr
            }
            self.scan_history.append(scan_info)
            self.save_history()

            # Global Unified History Logging
            if st.session_state.user_info:
                db_manager.add_to_global_history(
                    user_id=st.session_state.user_info['id'],
                    node_id=socket.gethostname(),
                    scan_type="Port Scan",
                    target=target_ip,
                    status="success" if success else "failed",
                    local_path=f"{target_ip}:{start_port}-{end_port}"
                )
            
            return success, stdout, stderr
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
            # Path Traversal and File Validation
            abs_path = os.path.abspath(pcap_file)
            if not os.path.exists(abs_path) or not abs_path.lower().endswith(('.pcap', '.pcapng')):
                return False, "", "Security Violation: Invalid PCAP/PCAPNG path or extension"
            if os.path.getsize(abs_path) > 100 * 1024 * 1024:  # 100MB limit DoS Protection
                return False, "", "Security Violation: PCAP file exceeds 100MB parsing limit"

            analyzer_script = os.path.join(os.path.dirname(__file__), 'packet_analyzer.py')
            cmd = [sys.executable, analyzer_script, '--analyze', abs_path, '--json']
            # Strict timeout for parser denial of service
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=os.path.dirname(analyzer_script),
            )
            
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
                            
                        # ---- AUTOMATED AI BRAIN CHECK ----
                        with st.spinner("🧠 AI Brain analyzing capture..."):
                            show_ai_analysis_result(lambda brain: brain.analyze_live_capture(stdout))
                    
                    if os.path.exists(output_file):
                        file_size = os.path.getsize(output_file) / 1024
                        st.info(f"📁 File saved: {output_file} ({file_size:.2f} KB)")
                else:
                    st.markdown('<div class="error-message">❌ Capture failed!</div>', unsafe_allow_html=True)
                    if stderr:
                        with st.expander("Error Details"):
                            st.code(stderr)
        


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
                                    
                                    # ---- AUTOMATED AI BRAIN CHECK ----
                                    st.divider()
                                    with st.spinner("🧠 AI Brain analyzing open ports..."):
                                        port_summary = json.dumps(open_ports)
                                        show_ai_analysis_result(lambda brain: brain.analyze_port_scan(port_summary))

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
                                
                        # ---- AUTOMATED AI BRAIN CHECK ----
                        st.divider()
                        with st.spinner("🧠 AI Brain checking file structure for anomalies..."):
                            pcap_summary = {
                                'total_packets': results.get('summary', {}).get('total_packets', 0),
                                'protocols': results.get('summary', {}).get('protocols', []),
                                'source_ips': results.get('summary', {}).get('source_ips', [])[:50],  # cap for context length
                                'dest_ips': results.get('summary', {}).get('dest_ips', [])[:50]
                            }
                            show_ai_analysis_result(lambda brain: brain.analyze_pcap_structure(json.dumps(pcap_summary)))
                            
                        # Missing block fallback (non-dict results)
                        if not isinstance(results, dict):
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
            with st.spinner(f"Local Engine is auditing {target_ip} (this may take a moment)..."):
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
                                
                                # 3. AUTOMATED AI SECURITY CHECK
                                st.divider()
                                st.subheader("🛡️ AI Security Audit (Gemini API)")
                                show_ai_analysis_result(lambda brain: brain.analyze_device_security(json.dumps(scan_data)))
                                
                            else:
                                st.warning("No active services found to audit.")
                        except Exception as e:
                            st.error(f"Audit failed during processing: {e}")
                    else:
                        st.error("Scan failed. Check target connectivity.")
                        if stderr: st.code(stderr)
def show_history_page(dashboard):
    """Unified Global History page"""
    st.markdown('<h1 class="main-header">📜 Global Network History</h1>', unsafe_allow_html=True)
    st.info("💡 Showing unified history across all sensor nodes in the LAN.")
    
    global_history = db_manager.get_global_history()
    
    if not global_history:
        st.warning("No global activity recorded yet.")
        
        # Fallback to local if empty
        if dashboard.scan_history or dashboard.capture_history:
            st.info("Showing local legacy history only.")
            # ... (omitted for brevity, keeping simple for now)
    else:
        history_df = pd.DataFrame(global_history, columns=[
            "Timestamp", "User", "Node", "Type", "Target", "Status", "Local Path"
        ])
        history_df['Timestamp'] = pd.to_datetime(history_df['Timestamp'])
        
        st.dataframe(
            history_df.sort_values('Timestamp', ascending=False),
            use_container_width=True,
            column_config={
                "Timestamp": st.column_config.DatetimeColumn("Activity Time"),
                "User": "Analyst",
                "Node": "Origin System",
                "Type": "Action",
                "Local Path": st.column_config.TextColumn("Agent Path (Local)")
            }
        )

def render_floating_ai_assistant(dashboard):
    """Render the floating bottom-right AI assistant widget."""
    ensure_ai_chat_state()
    if "ai_widget_open" not in st.session_state:
        st.session_state.ai_widget_open = False

    pending_prompt = st.session_state.pop("ai_pending_prompt", "")
    if pending_prompt:
        st.session_state.ai_widget_open = True
        submit_ai_prompt(dashboard, pending_prompt)

    if st.session_state.ai_widget_open:
        panel_container = st.container()
        with panel_container:
            st.markdown('<div class="ai-panel-scope"></div>', unsafe_allow_html=True)

            brain, ai_error = get_ai_brain()
            ai_status_label, ai_status_message = get_ai_status(brain, ai_error)
            context_sections = collect_ai_context_sections(dashboard)

            header_col, close_col = st.columns([5, 1])
            with header_col:
                st.markdown("#### AI Assistant")
                st.caption(f"{ai_status_label} status")
                st.caption(ai_status_message)
            with close_col:
                if st.button("x", key="ai_widget_close", use_container_width=True):
                    st.session_state.ai_widget_open = False
                    st.rerun()

            quick_col1, quick_col2 = st.columns(2)
            with quick_col1:
                if st.button("Summarize Risk", key="ai_widget_risk", use_container_width=True):
                    submit_ai_prompt(dashboard, "Summarize the latest network risk posture and highlight the top issues.")
                    st.rerun()
                if st.button("Explain Scan", key="ai_widget_scan", use_container_width=True):
                    submit_ai_prompt(dashboard, "Explain the latest scan results in plain language and tell me what matters.")
                    st.rerun()
            with quick_col2:
                if st.button("Hardening", key="ai_widget_hardening", use_container_width=True):
                    submit_ai_prompt(dashboard, "Give me the next hardening steps based on the recent telemetry.")
                    st.rerun()
                if st.button("Clear Chat", key="ai_widget_clear", use_container_width=True):
                    st.session_state.ai_messages = [{
                        "role": "assistant",
                        "content": "Conversation cleared. Ask about scans, captures, PCAP files, or remediation steps.",
                    }]
                    st.rerun()

            with st.expander("Telemetry Context", expanded=False):
                if context_sections:
                    for section in context_sections:
                        st.code(section, language="text")
                else:
                    st.info("Run a scan, packet capture, or PCAP analysis to give the assistant structured context.")

            message_area = st.container(height=280, border=False)
            with message_area:
                for message in st.session_state.ai_messages[-10:]:
                    with st.chat_message(message["role"]):
                        st.markdown(message["content"])

            with st.form("ai_widget_form", clear_on_submit=True):
                prompt = st.text_area(
                    "Message",
                    placeholder="Ask about anomalies, recent scans, or next remediation steps",
                    label_visibility="collapsed",
                    height=90,
                )
                submitted = st.form_submit_button("Send", use_container_width=True, type="primary")

            if submitted and prompt.strip():
                submit_ai_prompt(dashboard, prompt)
                st.rerun()

        panel_container.float(
            "right: 1rem;"
            "bottom: 6.25rem;"
            "width: min(26rem, calc(100vw - 1rem));"
            "max-width: calc(100vw - 1rem);"
            "max-height: 78vh;"
            "overflow-y: auto;"
            "overflow-x: hidden;"
            "background: rgba(8, 15, 30, 0.94);"
            "border: 1px solid rgba(96, 165, 250, 0.22);"
            "border-radius: 1.25rem;"
            "padding: 1rem;"
            "box-shadow: 0 28px 70px rgba(0, 0, 0, 0.45);"
            "backdrop-filter: blur(18px);"
            "z-index: 1000;"
        )

    bubble_container = st.container()
    with bubble_container:
        st.markdown('<div class="ai-bubble-scope"></div>', unsafe_allow_html=True)
        if st.button("AI", key="ai_widget_toggle", help="Open or close the AI assistant", use_container_width=True):
            st.session_state.ai_widget_open = not st.session_state.ai_widget_open
            st.rerun()

    bubble_container.float(
        "right: 1rem;"
        "bottom: 1rem;"
        "width: 4rem;"
        "background: transparent;"
        "z-index: 1001;"
    )

def show_settings_page():
    """System Settings for User Management"""
    st.markdown('<h1 class="main-header">⚙️ System Configuration</h1>', unsafe_allow_html=True)
    
    if not st.session_state.user_info:
        st.error("Please login to access settings")
        return

    tab1, tab2 = st.tabs(["Profile Security", "User Management (Admin)"])
    
    with tab1:
        st.markdown("### Change Your Password")
        with st.form("change_pwd_form"):
            new_pwd = st.text_input("New Password", type="password")
            confirm_pwd = st.text_input("Confirm New Password", type="password")
            if st.form_submit_button("Update Password", type="primary"):
                if new_pwd == confirm_pwd and len(new_pwd) >= 6:
                    db_manager.change_password(st.session_state.user_info['id'], new_pwd)
                    st.success("✅ Password updated successfully")
                else:
                    st.error("❌ Passwords must match and be at least 6 characters")
    
    with tab2:
        if st.session_state.user_info.get('role') != 'admin':
            st.warning("Admin privileges required to manage other users")
        else:
            st.markdown("### Register New System User")
            with st.form("new_user_form"):
                new_user = st.text_input("Username")
                new_user_pwd = st.text_input("Temporary Password", type="password")
                new_user_role = st.selectbox("Role", ["analyst", "admin"])
                if st.form_submit_button("Create User", type="primary"):
                    if db_manager.create_user(new_user, new_user_pwd, new_user_role):
                        st.success(f"✅ User '{new_user}' created")
                    else:
                        st.error("❌ User already exists or invalid data")
            
            st.markdown("---")
            st.markdown("### Active System Users")
            users = db_manager.get_all_users()
            df_users = pd.DataFrame(users, columns=["ID", "Username", "Role", "Created At"])
            st.dataframe(df_users, hide_index=True, use_container_width=True)



# ============================
# UI COMPONENTS
# ============================

def render_universal_header():
    """Universal centered header with high-assurance branding"""
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h1 class="main-header" style="font-size: 3.5rem !important;">🛡️ NeuraTrace</h1>
        <p style='color: #9CA3AF; margin-top: -10px; letter-spacing: 2px; font-size: 0.9rem;'>
            HIGH-ASSURANCE NETWORK INTELLIGENCE PLATFORM
        </p>
    </div>
    """, unsafe_allow_html=True)

# ============================
# AUTHENTICATION MODULE
# ============================

def show_login_module():
    """Redesigned Login Module with premium aesthetics"""
    st.markdown('<div class="login-box">', unsafe_allow_html=True)
    st.markdown("### Authentication Required")
    
    with st.form("login_form", clear_on_submit=True):
        username = st.text_input("Username", placeholder="Enter your identity")
        password = st.text_input("Password", type="password", placeholder="••••••••")
        
        submit = st.form_submit_button("LOGIN", use_container_width=True, type="primary")
        
        if submit:
            user = db_manager.authenticate_user(username, password)
            if user:
                token = create_jwt_token(username)
                st.session_state.auth_token = token
                st.session_state.user_info = user
                st.success(f"🔓 Access Granted. Welcome {username}.")
                time.sleep(1)
                st.rerun()
            else:
                st.error("❌ Invalid credentials")
    
    st.markdown('</div>', unsafe_allow_html=True)
    if st.button("Cancel", use_container_width=True):
        st.session_state.show_login = False
        st.rerun()

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
        
        # --- Authentication Status ---
        st.markdown("### 🔑 System Access")
        is_logged_in = verify_jwt_token(st.session_state.get('auth_token'))
        
        if is_logged_in:
            st.success(f"Active: {st.session_state.user_info.get('username')}")
            if st.button("Logout", use_container_width=True):
                st.session_state.auth_token = None
                st.session_state.user_info = None
                st.rerun()
        else:
            st.warning("Protected Mode")
            if st.button("Login to Execute", use_container_width=True, type="primary"):
                st.session_state.show_login = True
                st.rerun()
        
        st.markdown("---")
        
        # Navigation
        from streamlit_option_menu import option_menu
        st.markdown("### Navigation")
        
        # Determine current index
        pages = ["Dashboard", "Capture", "Port Scanner", "Device Security", "Analyze", "History"]
        icons = ["speedometer2", "record-circle", "search", "shield-lock", "file-earmark-bar-graph", "clock-history"]
        
        if is_logged_in:
            pages.append("Settings")
            icons.append("gear")
        
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
        st.markdown("### System Info")
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



def main():
    float_init()
    inject_css()
    db_manager.init_db()
    
    # Initialize session state
    if 'page' not in st.session_state:
        st.session_state.page = "Dashboard"
    elif st.session_state.page == "AI Assistant":
        st.session_state.page = "Dashboard"
    if 'auth_token' not in st.session_state:
        st.session_state.auth_token = None
    if 'show_login' not in st.session_state:
        st.session_state.show_login = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
    if 'ai_widget_open' not in st.session_state:
        st.session_state.ai_widget_open = False
    
    # Initialize dashboard
    dashboard = NeuraTraceDashboard()
    
    # Create sidebar with logo
    create_sidebar(dashboard)
    
    # Render Universal Header
    render_universal_header()
    
    # Check if we should show the login module
    if st.session_state.show_login:
        show_login_module()
        return
    
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

    render_floating_ai_assistant(dashboard)
    




if __name__ == "__main__":
    main()
