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

st.set_page_config(
    page_title="Neura Trace Dashboard",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        text-align: center;
        margin-bottom: 2rem;
        font-weight: bold;
    }
    .metric-card {
        background-color: #F3F4F6;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 5px solid #3B82F6;
        margin: 0.5rem 0;
    }
    .stButton button {
        width: 100%;
        background-color: #3B82F6;
        color: white;
        font-weight: bold;
    }
    .stButton button:hover {
        background-color: #2563EB;
        color: white;
    }
    .success-message {
        background-color: #D1FAE5;
        color: #065F46;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .error-message {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

class NeuraTraceDashboard:
    def __init__(self):
        self.capture_history = []
        self.load_history()
    
    def load_history(self):
        """Load capture history from file"""
        try:
            if os.path.exists('capture_history.json'):
                with open('capture_history.json', 'r') as f:
                    self.capture_history = json.load(f)
        except Exception as e:
            st.warning(f"Could not load history: {e}")
    
    def save_history(self):
        """Save capture history to file"""
        try:
            with open('capture_history.json', 'w') as f:
                json.dump(self.capture_history, f, indent=2)
        except Exception as e:
            st.error(f"Could not save history: {e}")
    
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
                'command': ' '.join(cmd)
            }
            
            self.capture_history.append(capture_info)
            self.save_history()
            
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            return False, "", str(e)
    
    def analyze_pcap_file(self, pcap_file):
        """Analyze PCAP file"""
        try:
            cmd = ['python', 'packet_analyzer.py', '--analyze', pcap_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                try:
                    return True, json.loads(result.stdout), result.stderr
                except:
                    return True, result.stdout, result.stderr
            return False, "", result.stderr
        except Exception as e:
            return False, "", str(e)

def show_dashboard_page(dashboard):
    """Main dashboard page"""
    st.markdown('<h1 class="main-header">📊 Neura Trace Dashboard</h1>', unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Captures", len(dashboard.capture_history))
    
    with col2:
        successful = sum(1 for c in dashboard.capture_history if c.get('status') == 'success')
        st.metric("Successful", successful)
    
    with col3:
        total_packets = sum(c.get('packet_count', 0) for c in dashboard.capture_history)
        st.metric("Total Packets", total_packets)
    
    with col4:
        if dashboard.capture_history:
            success_rate = (successful / len(dashboard.capture_history)) * 100
            st.metric("Success Rate", f"{success_rate:.1f}%")
        else:
            st.metric("Success Rate", "0%")
    
    st.divider()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Recent Captures")
        if dashboard.capture_history:
            recent_df = pd.DataFrame(dashboard.capture_history[-5:])
            st.dataframe(recent_df[['timestamp', 'interface', 'protocol', 'packet_count', 'status']],
                        use_container_width=True)
        else:
            st.info("No captures yet. Start your first capture!")
    
    with col2:
        st.subheader("Quick Actions")
        if st.button("🔄 List Interfaces", use_container_width=True):
            interfaces = dashboard.get_network_interfaces()
            st.write("Available interfaces:", interfaces)
        
        if st.button("📋 View History", use_container_width=True):
            st.session_state.page = "History"
            st.rerun()
        
        if st.button("⚙️ Settings", use_container_width=True):
            st.session_state.page = "Settings"
            st.rerun()

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
            
            output_file = st.text_input("Output File", "capture.pcap")
        
        st.divider()
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
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
        
        st.divider()
        
        st.subheader("Quick Capture Presets")
        
        preset_cols = st.columns(3)
        presets = [
            {"name": "Quick TCP Scan", "count": 50, "protocol": "TCP"},
            {"name": "HTTP Traffic", "count": 100, "protocol": "HTTP"},
            {"name": "DNS Queries", "count": 30, "protocol": "DNS"}
        ]
        
        for i, preset in enumerate(presets):
            with preset_cols[i]:
                if st.button(f"⚡ {preset['name']}", use_container_width=True):
                    success, stdout, stderr = dashboard.run_capture(
                        interface=interfaces[0] if interfaces else "any",
                        count=preset['count'],
                        protocol=preset['protocol'],
                        output_file=f"preset_{preset['name'].lower().replace(' ', '_')}.pcap"
                    )
                    
                    if success:
                        st.success(f"{preset['name']} completed!")
                        st.rerun()

def show_analyze_page(dashboard):
    """PCAP analysis page"""
    st.markdown('<h1 class="main-header">🔍 PCAP File Analysis</h1>', unsafe_allow_html=True)
    
    st.markdown("### Upload PCAP File")
    uploaded_file = st.file_uploader("Choose a PCAP file", type=['pcap', 'pcapng'])
    
    if uploaded_file is not None:
        file_path = f"uploads/{uploaded_file.name}"
        os.makedirs("uploads", exist_ok=True)
        
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
                                st.metric("Total Packets", results['summary']['total_packets'])
                                st.metric("Protocols Found", len(results['summary']['protocols']))
                            
                            with tab2:
                                if results['summary']['protocols']:
                                    protocol_df = pd.DataFrame({
                                        'Protocol': results['summary']['protocols'],
                                        'Count': [1] * len(results['summary']['protocols'])
                                    })
                                    fig = px.pie(protocol_df, values='Count', names='Protocol', 
                                               title="Protocol Distribution")
                                    st.plotly_chart(fig, use_container_width=True)
                                else:
                                    st.info("No protocol data available")
                            
                            with tab3:
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.write("Source IPs:", results['summary']['source_ips'][:10])
                                with col2:
                                    st.write("Destination IPs:", results['summary']['dest_ips'][:10])
                        else:
                            with st.expander("Raw Analysis Output"):
                                st.code(results)
                    else:
                        st.error(f"Analysis failed: {error}")
        
        with col2:
            if st.button("🗑️ Clear Upload", use_container_width=True):
                if os.path.exists(file_path):
                    os.remove(file_path)
                st.rerun()

def show_history_page(dashboard):
    """Capture history page"""
    st.markdown('<h1 class="main-header">📜 Capture History</h1>', unsafe_allow_html=True)
    
    if not dashboard.capture_history:
        st.info("No capture history available")
        return
    
    history_df = pd.DataFrame(dashboard.capture_history)
    
    # Convert timestamp
    history_df['timestamp'] = pd.to_datetime(history_df['timestamp'])
    
    # Filter options
    col1, col2 = st.columns(2)
    with col1:
        date_filter = st.date_input("Filter by date", [])
    with col2:
        status_filter = st.multiselect("Filter by status", ["success", "failed"], default=["success", "failed"])
    
    # Apply filters
    filtered_df = history_df.copy()
    if status_filter:
        filtered_df = filtered_df[filtered_df['status'].isin(status_filter)]
    
    if len(date_filter) == 2:
        start_date, end_date = date_filter
        filtered_df = filtered_df[
            (filtered_df['timestamp'].dt.date >= start_date) & 
            (filtered_df['timestamp'].dt.date <= end_date)
        ]
    
    # Display filtered history
    st.dataframe(
        filtered_df.sort_values('timestamp', ascending=False),
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
    
    # Export options
    st.divider()
    st.subheader("Export Data")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📥 Export as CSV", use_container_width=True):
            csv = history_df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name="neura_trace_history.csv",
                mime="text/csv"
            )
    
    with col2:
        if st.button("🗑️ Clear All History", use_container_width=True):
            dashboard.capture_history = []
            dashboard.save_history()
            st.success("History cleared!")
            st.rerun()

def show_settings_page():
    """Settings page"""
    st.markdown('<h1 class="main-header">⚙️ Settings</h1>', unsafe_allow_html=True)
    
    st.subheader("Application Settings")
    
    with st.form("settings_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            default_interface = st.selectbox("Default Interface", ["eth0", "wlan0", "en0", "lo", "any"])
            auto_save = st.checkbox("Auto-save captures", value=True)
        
        with col2:
            default_count = st.number_input("Default Packet Count", 10, 5000, 100)
            enable_notifications = st.checkbox("Enable notifications", value=False)
        
        st.subheader("Display Settings")
        theme = st.selectbox("Theme", ["Light", "Dark", "Auto"])
        refresh_interval = st.slider("Refresh Interval (seconds)", 5, 60, 30)
        
        if st.form_submit_button("💾 Save Settings", use_container_width=True):
            st.success("Settings saved successfully!")
            time.sleep(1)
            st.rerun()

def main():
    # Initialize session state
    if 'page' not in st.session_state:
        st.session_state.page = "Dashboard"
    
    # Initialize dashboard
    dashboard = NeuraTraceDashboard()
    
    # Sidebar navigation
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/network.png", width=100)
        st.markdown("## Neura Trace")
        st.markdown("---")
        
        page_options = {
            "📊 Dashboard": "Dashboard",
            "🎯 Live Capture": "Capture",
            "🔍 Analyze PCAP": "Analyze",
            "📜 History": "History",
            "⚙️ Settings": "Settings"
        }
        
        for icon, page in page_options.items():
            if st.button(icon, key=page, use_container_width=True):
                st.session_state.page = page
                st.rerun()
        
        st.markdown("---")
        st.markdown("### System Info")
        
        interfaces = dashboard.get_network_interfaces()
        st.caption(f"Interfaces: {len(interfaces)} available")
        
        if dashboard.capture_history:
            last_capture = dashboard.capture_history[-1]
            st.caption(f"Last capture: {last_capture.get('packet_count', 0)} packets")
        
        st.markdown("---")
        st.caption("Neura Trace v1.0.0")
    
    # Main content based on selected page
    if st.session_state.page == "Dashboard":
        show_dashboard_page(dashboard)
    elif st.session_state.page == "Capture":
        show_capture_page(dashboard)
    elif st.session_state.page == "Analyze":
        show_analyze_page(dashboard)
    elif st.session_state.page == "History":
        show_history_page(dashboard)
    elif st.session_state.page == "Settings":
        show_settings_page()

if __name__ == "__main__":
    main()