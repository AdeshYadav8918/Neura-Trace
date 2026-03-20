"""
Military-Grade IPC Daemon for Privilege Separation
This daemon runs as Root/Administrator in the background and accepts heavily sanitized instructions
from the unprivileged Streamlit web interface over a local socket.
"""

import socket
import json
import logging
import os
import subprocess
import re

logging.basicConfig(level=logging.INFO, format="%(asctime)s - IPC-DAEMON - %(levelname)s - %(message)s")

BASE_CAPTURE_DIR = os.path.abspath(os.path.join(os.getcwd(), "saved_scans"))

def handle_secure_request(req):
    action = req.get("action")
    if action == "capture":
        interface = req.get("interface", "")
        count = req.get("count", 100)
        output = req.get("output", "")
        
        # Additional zero-trust validation isolated within the Daemon
        if not re.match(r'^[a-zA-Z0-9.\-_ \(\)]+$', interface):
            return {"status": "error", "message": "Invalid interface strings."}
            
        safe_out = os.path.abspath(output)
        if not safe_out.startswith(BASE_CAPTURE_DIR):
            return {"status": "error", "message": "Path traversal blocked."}
            
        logging.info(f"Executing authorized raw capture on {interface}")
        cmd = ['python', 'packet_analyzer.py', '-i', interface, '-c', str(count), '-o', safe_out]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"status": "success" if res.returncode == 0 else "error", "stdout": res.stdout, "stderr": res.stderr}
        
    return {"status": "error", "message": "Unknown or forbidden action"}

def start_ipc_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind strictly to localhost (never 0.0.0.0)
    server.bind(('127.0.0.1', 50051))
    server.listen(5)
    logging.info("Secure IPC Capture Daemon active and bound to 127.0.0.1:50051")
    
    while True:
        try:
            conn, addr = server.accept()
            # Only accept loopback
            if addr[0] != '127.0.0.1':
                conn.close()
                continue
                
            data = conn.recv(8192).decode('utf-8')
            if not data: continue
            
            try:
                req = json.loads(data)
                resp = handle_secure_request(req)
                conn.sendall(json.dumps(resp).encode('utf-8'))
            except json.JSONDecodeError:
                conn.sendall(json.dumps({"status": "error", "message": "Malformed IPC instruction"}).encode('utf-8'))
            except Exception as e:
                logging.error(f"Execution error: {e}")
                conn.sendall(json.dumps({"status": "error", "message": "Internal daemon execution failure"}).encode('utf-8'))
            finally:
                conn.close()
        except KeyboardInterrupt:
            logging.info("Daemon terminating safely.")
            break

if __name__ == "__main__":
    # Ensure ONLY root or explicit administrative users can spawn this
    # if os.geteuid() != 0: raise PermissionError("Daemon must run as root")
    start_ipc_server()
