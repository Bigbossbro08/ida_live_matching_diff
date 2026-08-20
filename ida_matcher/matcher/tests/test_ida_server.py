import threading
import time
import socket
import sys

# Mock ida_kernwin to avoid real IDA imports
class MockIdaKernwin:
    @staticmethod
    def register_timer(timeout, callback):
        return 1
    
    @staticmethod
    def unregister_timer(timer_id):
        pass

sys.modules["ida_kernwin"] = MockIdaKernwin()
sys.modules["ida_ida"] = type("MockIdaIda", (), {"inf_is_64bit": lambda: False})()

import ida_matcher.matcher.ida_server as idasrv

def test_ida_server_threading():
    idasrv.start_server()
    assert idasrv.SERVER_SOCKET is not None
    
    try:
        # Check if the server accepts connections on the background thread
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(('127.0.0.1', idasrv.PORT))
        s.sendall(b"GET /func?name=test HTTP/1.1\r\n\r\n")
        time.sleep(0.1)
        resp = s.recv(1024)
        assert b"HTTP" in resp
        s.close()
    finally:
        idasrv.stop_server()
        assert idasrv.SERVER_SOCKET is None


class DummyConn:
    def __init__(self, request_bytes):
        self.request_bytes = request_bytes
        self.sent_bytes = bytearray()

    def settimeout(self, t):
        pass

    def recv(self, size):
        data = self.request_bytes
        self.request_bytes = b""
        return data

    def sendall(self, b):
        self.sent_bytes.extend(b)

    def close(self):
        pass


def test_handle_client_synthetic_obj():
    # Test 404 when not found
    conn = DummyConn(b"GET /synthetic_obj?name=unknown HTTP/1.1\r\n\r\n")
    idasrv.handle_client(conn)
    assert b"404 Not Found" in conn.sent_bytes

    # Test 200 with octet-stream when found
    idasrv.load_or_reload_logic()
    old_build = getattr(idasrv.LOGIC_MODULE, "build_synthetic_obj", None)
    try:
        idasrv.LOGIC_MODULE.build_synthetic_obj = lambda name: b"\x4c\x01\x00\x00" if name == "found" else None
        conn2 = DummyConn(b"GET /synthetic_obj?name=found HTTP/1.1\r\n\r\n")
        idasrv.handle_client(conn2)
        assert b"200 OK" in conn2.sent_bytes
        assert b"Content-Type: application/octet-stream" in conn2.sent_bytes
        assert b"\x4c\x01\x00\x00" in conn2.sent_bytes
    finally:
        if old_build:
            idasrv.LOGIC_MODULE.build_synthetic_obj = old_build
