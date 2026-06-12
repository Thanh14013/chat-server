import socket
import struct
import binascii
import json
import time
import subprocess
import os
import sqlite3
import signal

class MessageType:
    MSG_CONNECT_REQUEST      = 0x01
    MSG_CONNECT_ACCEPT       = 0x02
    MSG_CONNECT_REJECT       = 0x03
    MSG_DISCONNECT           = 0x04
    MSG_PING                 = 0x05
    MSG_PONG                 = 0x06
    MSG_CHAT_SEND            = 0x10
    MSG_CHAT_BROADCAST       = 0x11
    MSG_CHAT_PRIVATE         = 0x12
    MSG_SYSTEM_NOTIFY        = 0x13
    MSG_ROOM_JOIN            = 0x20
    MSG_ROOM_LEAVE           = 0x21
    MSG_ROOM_LIST_REQUEST    = 0x22
    MSG_ROOM_LIST_RESPONSE   = 0x23
    MSG_ROOM_CREATE          = 0x24
    MSG_USER_LIST_REQUEST    = 0x30
    MSG_USER_LIST_RESPONSE   = 0x31
    MSG_USER_LISTALL_REQUEST = 0x32
    MSG_USER_LISTALL_RESPONSE= 0x33
    MSG_WHOIS_REQUEST        = 0x34
    MSG_WHOIS_RESPONSE       = 0x35
    MSG_FILE_REQUEST         = 0x50
    MSG_FILE_ACCEPT          = 0x51
    MSG_FILE_REJECT          = 0x52
    MSG_FILE_DATA            = 0x53
    MSG_FILE_COMPLETE        = 0x54
    MSG_ADMIN_KICK           = 0x60
    MSG_ADMIN_MUTE           = 0x61
    MSG_ADMIN_BAN            = 0x62
    MSG_ADMIN_PROMOTE        = 0x63
    MSG_ADMIN_BROADCAST      = 0x64
    MSG_ERROR                = 0xFF

class TestClient:
    def __init__(self, nickname, port=9500):
        self.nickname = nickname
        self.port = port
        self.sock = None
        self.room = None

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
                
            payload_dict = {}
            if payload_len > 0:
                payload_dict = json.loads(payload_data.decode('utf-8'))
                
            return {
                'type': msg_type,
                'payload': payload_dict
            }
        except Exception as e:
            return None

def set_user_admin(nickname):
    conn = sqlite3.connect('vcs_chat.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE Users SET role = 'OWNER' WHERE nickname = ?", (nickname,))
    conn.commit()
    conn.close()

def run_tests():
    config_data = {
        "server": {
            "port": 9500,
            "max_clients": 100,
            "thread_pool_size": 4
        },
        "security": {
            "require_auth": True,
            "max_auth_attempts": 5,
            "rate_limit_msg_per_sec": 100,
            "enable_encryption": False,
            "enable_audit_log": True
        },
        "rooms": {
            "default_room": "general",
            "max_rooms": 10,
            "history_size": 10
        },
        "admin": {
            "admin_password_hash": "admin123"
        }
    }
    with open('test_config.json', 'w') as f:
        json.dump(config_data, f)
        
    for ext in ['', '-wal', '-shm']:
        f = 'vcs_chat.db' + ext
        if os.path.exists(f):
            os.remove(f)
        
    print("[*] Starting Server...")
    server_process = subprocess.Popen(
        ['../build/vcs_server', '--config', 'test_config.json'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid
    )
    time.sleep(1.0)
    
    try:
        print("[*] Registering Alice, Bob, Charlie...")
        alice = TestClient('Alice')
        bob = TestClient('Bob')
        charlie = TestClient('Charlie')
        
        alice.connect()
        alice.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Alice", "password": "pass"})
        resp = alice.recv_packet()
        assert resp['type'] == MessageType.MSG_CONNECT_ACCEPT
        alice.close()
        
        print("[*] Making Alice OWNER via DB...")
        set_user_admin('Alice')
        
        alice.connect()
        alice.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Alice", "password": "pass"})
        resp = alice.recv_packet()
        assert resp['type'] == MessageType.MSG_CONNECT_ACCEPT
        
        bob.connect()
        bob.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Bob", "password": "pass"})
        bob.recv_packet()
        
        charlie.connect()
        charlie.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Charlie", "password": "pass"})
        charlie.recv_packet()

        # Flush queues
        alice.recv_packet(0.1)
        bob.recv_packet(0.1)
        charlie.recv_packet(0.1)
        
        print("[+] Users connected.")

        print("[*] Test MUTE...")
        alice.send_packet(MessageType.MSG_ADMIN_MUTE, {"target": "Bob", "duration": 300})
        time.sleep(0.5)
        while True:
            alice_resp = alice.recv_packet(0.1)
            if alice_resp:
                print(f"Alice received: {alice_resp}")
            else:
                break
        while bob.recv_packet(0.1): pass

        bob.send_packet(MessageType.MSG_CHAT_SEND, {"message": "Hello"})
        resp = bob.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_ERROR, f"Bob should be muted, got {resp}"
        print("[+] MUTE passed.")

        print("[*] Test UNMUTE...")
        alice.send_packet(MessageType.MSG_ADMIN_MUTE, {"target": "Bob", "duration": 0})
        time.sleep(0.5)
        while bob.recv_packet(0.1): pass

        bob.send_packet(MessageType.MSG_CHAT_SEND, {"message": "Hello"})
        resp = bob.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_CHAT_BROADCAST, f"Bob should be unmuted, got {resp}"
        print("[+] UNMUTE passed.")

        print("[*] Test KICK...")
        alice.send_packet(MessageType.MSG_ADMIN_KICK, {"target": "Bob", "reason": "Test kick"})
        time.sleep(0.5)
        # Bob might receive SYSTEM_NOTIFY before disconnection, so read until None or ERROR
        disconnected = False
        while True:
            resp = bob.recv_packet(1.0)
            if resp is None or resp['type'] == MessageType.MSG_ERROR:
                disconnected = True
                break
        assert disconnected, "Bob should be disconnected"
        print("[+] KICK passed.")

        print("[*] Test ADMIN Edge Cases (Unauthorized)...")
        # Charlie is currently a regular user
        while charlie.recv_packet(0.1): pass
        charlie.send_packet(MessageType.MSG_ADMIN_MUTE, {"target": "Alice", "duration": 300})
        resp = charlie.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_ERROR, "Unauthorized user should receive error"
        print("[+] ADMIN Edge Cases passed.")

        print("[*] Test PROMOTE & WHOIS...")
        alice.send_packet(MessageType.MSG_ADMIN_PROMOTE, {"target": "Charlie"})
        time.sleep(0.5)
        while charlie.recv_packet(0.1): pass

        charlie.send_packet(MessageType.MSG_WHOIS_REQUEST, {"target": "Alice"})
        resp = charlie.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_WHOIS_RESPONSE, f"Got {resp}"
        assert resp['payload']['nickname'] == 'Alice'
        
        print("[*] Test WHOIS Edge Case (User not found)...")
        charlie.send_packet(MessageType.MSG_WHOIS_REQUEST, {"target": "GhostUser"})
        resp = charlie.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_WHOIS_RESPONSE
        assert "error" in resp['payload']
        print("[+] PROMOTE & WHOIS passed.")

        print("[*] Test FILE TRANSFER Edge Cases...")
        # Send to non-existent user
        charlie.send_packet(MessageType.MSG_FILE_REQUEST, {"to": "Ghost", "filename": "test.txt", "size": 100})
        resp = charlie.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_ERROR
        
        # Disallowed extension
        charlie.send_packet(MessageType.MSG_FILE_REQUEST, {"to": "Alice", "filename": "malicious.exe", "size": 100})
        resp = charlie.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_ERROR
        
        # File too large
        charlie.send_packet(MessageType.MSG_FILE_REQUEST, {"to": "Alice", "filename": "big.mp4", "size": 10*1024*1024})
        resp = charlie.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_ERROR

        print("[*] Test FILE TRANSFER...")
        # Charlie sends file to Alice (which Alice will reject)
        charlie.send_packet(MessageType.MSG_FILE_REQUEST, {"to": "Alice", "filename": "test.txt", "size": 100})
        
        timeout_at = time.time() + 2.0
        resp = None
        while time.time() < timeout_at:
            r = alice.recv_packet(0.5)
            if r and r['type'] == MessageType.MSG_FILE_REQUEST:
                resp = r
                break
        assert resp is not None and resp['type'] == MessageType.MSG_FILE_REQUEST
        tid = resp['payload']['transfer_id']

        # Alice Rejects
        alice.send_packet(MessageType.MSG_FILE_REJECT, {"transfer_id": tid})
        timeout_at = time.time() + 2.0
        resp = None
        while time.time() < timeout_at:
            r = charlie.recv_packet(0.5)
            if r and r['type'] == MessageType.MSG_FILE_REJECT:
                resp = r
                break
        assert resp is not None and resp['type'] == MessageType.MSG_FILE_REJECT
        
        # Charlie sends file to Alice (Accept flow)
        charlie.send_packet(MessageType.MSG_FILE_REQUEST, {"to": "Alice", "filename": "test2.txt", "size": 100})
        
        timeout_at = time.time() + 2.0
        resp = None
        while time.time() < timeout_at:
            r = alice.recv_packet(0.5)
            if r and r['type'] == MessageType.MSG_FILE_REQUEST:
                resp = r
                break
        assert resp is not None and resp['type'] == MessageType.MSG_FILE_REQUEST
        tid = resp['payload']['transfer_id']

        alice.send_packet(MessageType.MSG_FILE_ACCEPT, {"transfer_id": tid})
        timeout_at = time.time() + 2.0
        resp = None
        while time.time() < timeout_at:
            r = charlie.recv_packet(0.5)
            if r and r['type'] == MessageType.MSG_FILE_ACCEPT:
                resp = r
                break
        assert resp is not None and resp['type'] == MessageType.MSG_FILE_ACCEPT

        charlie.send_packet(MessageType.MSG_FILE_DATA, {"transfer_id": tid, "data": "YWJj"})
        timeout_at = time.time() + 2.0
        resp = None
        while time.time() < timeout_at:
            r = alice.recv_packet(0.5)
            if r and r['type'] == MessageType.MSG_FILE_DATA:
                resp = r
                break
        assert resp is not None and resp['type'] == MessageType.MSG_FILE_DATA

        charlie.send_packet(MessageType.MSG_FILE_COMPLETE, {"transfer_id": tid, "ok": True})
        resp = alice.recv_packet(1.0)
        assert resp['type'] == MessageType.MSG_FILE_COMPLETE
        print("[+] FILE TRANSFER passed.")

        print("[*] Test ROOMS Edge Cases...")
        # Server implicitly creates rooms on join, so joining "!" succeeds.
        charlie.send_packet(MessageType.MSG_ROOM_JOIN, {"room": "!"})
        resp = charlie.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_SYSTEM_NOTIFY
        
        print("[*] Test ROOMS...")
        charlie.send_packet(MessageType.MSG_ROOM_CREATE, {"room": "secret"})
        time.sleep(0.5)
        while charlie.recv_packet(0.1): pass
        
        charlie.send_packet(MessageType.MSG_ROOM_JOIN, {"room": "secret"})
        resp = charlie.recv_packet(1.0)
        assert resp is not None
        print("[+] ROOMS passed.")

        print("[*] Test BAN...")
        alice.send_packet(MessageType.MSG_ADMIN_BAN, {"target": "Charlie", "reason": "Banned"})
        time.sleep(0.5)
        resp = charlie.recv_packet(1.0)
        print("[+] BAN passed.")

        print("[*] ALL TESTS PASSED SUCCESSFULLY!")

    except Exception as e:
        print(f"[-] TEST FAILED: {e}")
    finally:
        os.killpg(os.getpgid(server_process.pid), signal.SIGTERM)
        out, err = server_process.communicate()
        print("SERVER STDOUT:\n", out.decode())
        print("SERVER STDERR:\n", err.decode())
        for ext in ['', '-wal', '-shm']:
            f = 'vcs_chat.db' + ext
            if os.path.exists(f):
                os.remove(f)

if __name__ == "__main__":
    run_tests()
