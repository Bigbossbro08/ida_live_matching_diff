import ida_kernwin
import json
import socket
import select
import os
import sys
import importlib
import traceback
from urllib.parse import urlparse, parse_qs

PORT = 28000
SERVER_SOCKET = None
TIMER_ID = None

LOGIC_PATH = os.path.join(os.path.dirname(__file__), "ida_logic.py")
LAST_MTIME = 0
LOGIC_MODULE = None

MATCHER_DIR = os.path.dirname(__file__)
if MATCHER_DIR not in sys.path:
    sys.path.insert(0, MATCHER_DIR)

def load_or_reload_logic():
    global LAST_MTIME, LOGIC_MODULE
    try:
        if not os.path.exists(LOGIC_PATH):
            return
        current_mtime = os.path.getmtime(LOGIC_PATH)
        if current_mtime > LAST_MTIME or LOGIC_MODULE is None:
            if LOGIC_MODULE is None:
                import ida_logic
                LOGIC_MODULE = ida_logic
                print("IDA Live Matcher: Loaded ida_logic.py module.")
            else:
                importlib.reload(LOGIC_MODULE)
                print("IDA Live Matcher: Hot-reloaded updated ida_logic.py!")
            LAST_MTIME = current_mtime
    except Exception as e:
        print(f"IDA Live Matcher: Hot-reload warning (retaining previous logic): {e}")

def handle_client(conn):
    try:
        load_or_reload_logic()
        data = conn.recv(4096).decode('utf-8', errors='ignore')
        if not data:
            return
            
        lines = data.split('\r\n')
        if not lines:
            return
            
        request_line = lines[0]
        parts = request_line.split()
        if len(parts) < 2:
            return
            
        method, path = parts[0], parts[1]
        
        if method == "GET":
            parsed = urlparse(path)
            if parsed.path == '/func':
                qs = parse_qs(parsed.query)
                name = qs.get('name', [None])[0]
                
                response_data = None
                if name and LOGIC_MODULE:
                    response_data = LOGIC_MODULE.get_function_bytes(name)
                
                if response_data:
                    body = json.dumps(response_data)
                    response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
                else:
                    body = '{"error": "not found"}'
                    response = f"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
                
                conn.settimeout(None) 
                conn.sendall(response.encode('utf-8'))
            elif parsed.path == '/refresh':
                if LOGIC_MODULE:
                    LOGIC_MODULE.build_cache()
                body = '{"status": "refreshed"}'
                response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
                conn.settimeout(None)
                conn.sendall(response.encode('utf-8'))
                
    except Exception as e:
        # FIX: Do not swallow exceptions silently. Log them and send a 500 error.
        print(f"IDA Live Matcher Error: {e}")
        traceback.print_exc()
        try:
            err_body = json.dumps({"error": str(e)})
            err_resp = f"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {len(err_body)}\r\nConnection: close\r\n\r\n{err_body}"
            conn.settimeout(None)
            conn.sendall(err_resp.encode('utf-8'))
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

def timer_callback():
    global SERVER_SOCKET
    if not SERVER_SOCKET:
        return -1
        
    try:
        r, _, _ = select.select([SERVER_SOCKET], [], [], 0.0)
        if r:
            conn, addr = SERVER_SOCKET.accept()
            conn.settimeout(0.5) 
            handle_client(conn)
    except Exception:
        pass
        
    return 100

def start_server():
    global SERVER_SOCKET, TIMER_ID
    if SERVER_SOCKET:
        print("IDA Live Matcher: Server is already running.")
        return
        
    SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        SERVER_SOCKET.bind(('127.0.0.1', PORT))
        SERVER_SOCKET.listen(10)
        load_or_reload_logic()
        if LOGIC_MODULE:
            LOGIC_MODULE.build_cache()
        print(f"IDA Live Matcher Server running on port {PORT} (Hot-Reload Enabled)...")
        
        TIMER_ID = ida_kernwin.register_timer(100, timer_callback)
    except Exception as e:
        print(f"IDA Live Matcher: Failed to start server: {e}")
        SERVER_SOCKET = None

def stop_server():
    global SERVER_SOCKET, TIMER_ID
    if TIMER_ID is not None:
        ida_kernwin.unregister_timer(TIMER_ID)
        TIMER_ID = None
    if SERVER_SOCKET:
        SERVER_SOCKET.close()
        SERVER_SOCKET = None
        print("IDA Live Matcher: Server stopped.")

if __name__ == "__main__":
    start_server()