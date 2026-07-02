import socket
import struct
import binascii
import json
import time
import subprocess
import os
import signal
import sys

class MessageType:
    MSG_CONNECT_REQUEST      = 0x01
    MSG_CONNECT_ACCEPT       = 0x02
    MSG_CONNECT_REJECT       = 0x03
    MSG_DISCONNECT           = 0x04
    MSG_SYSTEM_NOTIFY        = 0x13
    MSG_ROOM_JOIN            = 0x20
    MSG_ERROR                = 0xFF

class TestClient:
    def __init__(self, nickname, port=9500):
        self.nickname = nickname
        self.port = port
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(2.0)
        self.sock.connect(('127.0.0.1', self.port))

    def close(self):
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            self.sock.close()
            self.sock = None

    def send_packet(self, msg_type, payload_dict=None):
        magic = b'\xAB\x53'
        version = 1
        flags = 0
        seq = 0
        
        payload_bytes = b''
        if payload_dict is not None:
            payload_bytes = json.dumps(payload_dict).encode('utf-8')
            
        payload_len = len(payload_bytes)
        checksum = binascii.crc32(payload_bytes) & 0xffffffff
        
        header = struct.pack('<2sBBBIII', magic, version, msg_type, flags, seq, payload_len, checksum)
        self.sock.sendall(header + payload_bytes)

    def recv_packet(self, timeout=2.0):
        self.sock.settimeout(timeout)
        try:
            header_data = b''
            while len(header_data) < 17:
                chunk = self.sock.recv(17 - len(header_data))
                if not chunk:
                    return None
                header_data += chunk
            
            magic, version, msg_type, flags, seq, payload_len, checksum = struct.unpack('<2sBBBIII', header_data)
            
            payload_data = b''
            while len(payload_data) < payload_len:
                chunk = self.sock.recv(payload_len - len(payload_data))
                if not chunk:
                    break
                payload_data += chunk
                
            payload_dict = None
            if payload_len > 0:
                try:
                    payload_dict = json.loads(payload_data.decode('utf-8'))
                except:
                    pass
            return msg_type, payload_dict
        except socket.timeout:
            return None
        except Exception as e:
            return None

def start_server():
    print("Starting server...")
    if os.path.exists("vcs_chat.db"):
        os.remove("vcs_chat.db")
    with open("test_config.json", "w") as f:
        json.dump({
            "server": {
                "port": 9500,
                "max_clients": 100,
                "session_timeout_seconds": 3600
            },
            "security": {
                "enable_encryption": False
            },
            "rooms": {
                "default_room": "general"
            },
            "db_path": "vcs_chat.db"
        }, f)
    
    server_process = subprocess.Popen(["./build/vcs_server", "--config", "test_config.json"], 
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)
    return server_process

def test_room_memory():
    server = start_server()
    try:
        # Step 1: Login and verify default room
        c1 = TestClient("Alice")
        c1.connect()
        c1.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Alice", "password": "pass"})
        
        # Accept packet
        res = c1.recv_packet()
        print("Login 1:", res)
        
        # Room join notify
        res = c1.recv_packet()
        print("Login 1 notify:", res)
        
        # Step 2: Join a new room
        c1.send_packet(MessageType.MSG_ROOM_JOIN, {"room_name": "gaming", "password": ""})
        
        for _ in range(5):
            res = c1.recv_packet(1.0)
            if res:
                print("Join Room Notify:", res)
        
        c1.close()
        time.sleep(1) # wait for server to process disconnect
        
        # Step 3: Login again and verify we join the last room
        c2 = TestClient("Alice")
        c2.connect()
        c2.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Alice", "password": "pass"})
        
        # Accept packet
        res = c2.recv_packet()
        print("Login 2:", res)
        
        for _ in range(5):
            res = c2.recv_packet(1.0)
            if res:
                print("Login 2 Notify:", res)
        
        c2.close()
    except Exception as e:
        print(f"TEST FAILED: {e}")
    finally:
        server.send_signal(signal.SIGINT)
        server.wait()

if __name__ == "__main__":
    test_room_memory()
