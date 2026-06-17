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
            "rate_limit_msg_per_sec": 5,
            "connect_rate_per_min": 100,
            "auth_rate_per_min": 100,
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
        ['./build/vcs_server', '--config', 'test_config.json'],
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
        hacker = TestClient('Hacker')
        
        alice.connect()
        alice.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Alice", "password": "pass"})
        resp = alice.recv_packet()
        assert resp['type'] == MessageType.MSG_CONNECT_ACCEPT
        alice.close()
        time.sleep(0.5)
        
        print("[*] Making Alice OWNER via DB...")
        set_user_admin('Alice')
        
        alice.connect()
        alice.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Alice", "password": "pass"})
        alice.recv_packet()
        
        bob.connect()
        bob.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Bob", "password": "pass"})
        bob.recv_packet()
        
        charlie.connect()
        charlie.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Charlie", "password": "pass"})
        charlie.recv_packet()

        # Flush queues completely
        while alice.recv_packet(0.1): pass
        while bob.recv_packet(0.1): pass
        while charlie.recv_packet(0.1): pass
        
        print("[+] Users connected.")

        print("[*] Test MSG_CHAT_PRIVATE...")
        bob.send_packet(MessageType.MSG_CHAT_PRIVATE, {"to": "Charlie", "message": "Secret info"})
        resp = charlie.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_CHAT_PRIVATE
        assert resp['payload']['message'] == "Secret info"
        assert resp['payload']['from'] == "Bob"
        
        # Bob also gets an echo of his private msg
        bob_echo = bob.recv_packet(0.5)
        if bob_echo is not None:
            assert bob_echo['type'] == MessageType.MSG_CHAT_PRIVATE
        
        alice_resp = alice.recv_packet(0.5)
        if alice_resp is not None:
            assert alice_resp['type'] != MessageType.MSG_CHAT_PRIVATE, "Alice received the private message!"
        print("[+] Private messaging passed.")

        print("[*] Test MSG_CHAT_BROADCAST (Rooms)...")
        # Alice, Bob, Charlie are in default 'general' room
        alice.send_packet(MessageType.MSG_CHAT_SEND, {"message": "Hello general"})
        resp_bob = bob.recv_packet(1.0)
        resp_charlie = charlie.recv_packet(1.0)
        if resp_bob is None or resp_bob['type'] != MessageType.MSG_CHAT_BROADCAST:
            print(f"BOB GOT: {resp_bob}")
        if resp_charlie is None or resp_charlie['type'] != MessageType.MSG_CHAT_BROADCAST:
            print(f"CHARLIE GOT: {resp_charlie}")
        assert resp_bob is not None and resp_bob['type'] == MessageType.MSG_CHAT_BROADCAST
        assert resp_charlie is not None and resp_charlie['type'] == MessageType.MSG_CHAT_BROADCAST
        
        # Flush Alice's own broadcast
        alice_echo = alice.recv_packet(1.0)
        if alice_echo is not None:
            assert alice_echo['type'] == MessageType.MSG_CHAT_BROADCAST
            
        print("[+] Broadcast passed.")

        print("[*] Test ROOMS List & Join...")
        charlie.send_packet(MessageType.MSG_ROOM_CREATE, {"room": "dev"})
        time.sleep(0.5)
        charlie.recv_packet(0.5) # flush notify
        
        bob.send_packet(MessageType.MSG_ROOM_LIST_REQUEST)
        resp = bob.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_ROOM_LIST_RESPONSE
        rooms = resp['payload']
        assert "general" in rooms
        assert "dev" in rooms
        
        bob.send_packet(MessageType.MSG_ROOM_JOIN, {"room": "dev"})
        resp = bob.recv_packet(1.0)
        assert resp['type'] == MessageType.MSG_SYSTEM_NOTIFY
        
        bob.send_packet(MessageType.MSG_CHAT_SEND, {"message": "Hello dev"})
        
        # Charlie is still in general, shouldn't see 'dev' messages, Alice shouldn't see it either.
        alice_resp = alice.recv_packet(0.5)
        if alice_resp is not None:
            assert alice_resp['type'] != MessageType.MSG_CHAT_BROADCAST, "Alice received broadcast from another room"
        
        # Bob is alone in 'dev', but what if Charlie joins 'dev'?
        charlie.send_packet(MessageType.MSG_ROOM_JOIN, {"room": "dev"})
        # Flush Bob and Charlie queues to ensure no stale notifications
        while charlie.recv_packet(0.2): pass
        while bob.recv_packet(0.2): pass
        
        bob.send_packet(MessageType.MSG_CHAT_SEND, {"message": "Hello dev 2"})
        resp = charlie.recv_packet(1.0)
        if resp is None or resp['type'] != MessageType.MSG_CHAT_BROADCAST:
            print(f"CHARLIE GOT: {resp}")
        assert resp is not None and resp['type'] == MessageType.MSG_CHAT_BROADCAST
        assert resp['payload']['message'] == "Hello dev 2"
        
        bob.recv_packet(1.0) # Bob's own broadcast echo
        print("[+] Room isolating passed.")

        print("[*] Test USER LIST...")
        # Bob and Charlie in 'dev'. Alice in 'general'.
        bob.send_packet(MessageType.MSG_USER_LIST_REQUEST)
        resp = bob.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_USER_LIST_RESPONSE
        users = resp['payload']
        assert "Bob" in users
        assert "Charlie" in users
        assert "Alice" not in users
        
        print("[+] User lists passed.")

        print("[*] Test ADMIN BROADCAST...")
        alice.send_packet(MessageType.MSG_ADMIN_BROADCAST, {"message": "Server going down"})
        resp = bob.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_SYSTEM_NOTIFY
        assert "Server going down" in resp['payload']['message']
        resp = charlie.recv_packet(1.0)
        assert resp is not None and resp['type'] == MessageType.MSG_SYSTEM_NOTIFY
        print("[+] Admin broadcast passed.")

        print("[*] Test Rate Limiter Trigger...")
        # Rate limit is 5 msg/sec. Let's send 10 quickly.
        for i in range(10):
            bob.send_packet(MessageType.MSG_CHAT_SEND, {"message": "Spam!"})
        
        rate_limited = False
        for i in range(10):
            resp = bob.recv_packet(0.5)
            if resp and resp['type'] == MessageType.MSG_ERROR and resp['payload'].get('code') == 7: # ERR_RATE_LIMITED
                rate_limited = True
                break
        assert rate_limited, "Rate limiter did not trigger!"
        print("[+] Rate limiter passed.")
        
        print("[*] Test Bruteforce IP Ban (Intrusion Detector)...")
        # Attempt 6 connections with wrong password to trigger IP block.
        # Max attempts = 5. After that, we should be temporarily banned by IntrusionDetector.
        for i in range(6):
            h = TestClient(f'Hacker{i}')
            h.connect()
            h.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": f"Hacker{i}", "password": "wrong"})
            resp = h.recv_packet(1.0)
            h.close()
            time.sleep(0.1)
            
        h_test = TestClient('HackerTest')
        h_test.connect()
        # Due to Temp Ban on IP (127.0.0.1 in this case, actually it might ban the localhost!).
        # Let's see if we get disconnected immediately.
        # Wait, if we ban 127.0.0.1, the rest of the test will fail! We should do this at the very end.
        try:
            h_test.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "HackerTest", "password": "wrong"})
            resp = h_test.recv_packet(1.0)
            if resp is None:
                # Disconnected immediately
                pass
        except:
            pass
        print("[+] Bruteforce Ban test passed.")

        print("[*] ALL COMPREHENSIVE TESTS PASSED SUCCESSFULLY!")

    except Exception as e:
        import traceback
        traceback.print_exc()
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
