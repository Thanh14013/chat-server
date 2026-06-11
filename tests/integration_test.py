import socket
import struct
import binascii
import json
import time
import subprocess
import os
import signal
import sys

# MessageTypes matching MessageTypes.h
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
    MSG_ERROR                = 0xFF

# ErrorCodes matching ErrorCodes.h
class ErrorCode:
    ERR_OK                     = 0x00
    ERR_NICKNAME_TAKEN         = 0x01
    ERR_NICKNAME_INVALID       = 0x02
    ERR_ROOM_FULL              = 0x03
    ERR_ROOM_NOT_FOUND         = 0x04
    ERR_AUTH_FAILED            = 0x05
    ERR_AUTH_TOO_MANY_ATTEMPTS = 0x06
    ERR_RATE_LIMITED           = 0x07
    ERR_MESSAGE_TOO_LONG       = 0x08
    ERR_FILE_TOO_LARGE         = 0x09
    ERR_PERMISSION_DENIED      = 0x0A
    ERR_CRYPTO_HANDSHAKE_FAIL  = 0x0B
    ERR_INVALID_TOKEN          = 0x0C
    ERR_REPLAY_DETECTED        = 0x0D
    ERR_SERVER_FULL            = 0x0E
    ERR_INTERNAL               = 0xFF

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
                    raise ConnectionError("Connection closed by peer while reading header")
                header_data += chunk
            
            magic, version, msg_type, flags, seq, payload_len, checksum = struct.unpack('<2sBBBIII', header_data)
            
            payload_data = b''
            while len(payload_data) < payload_len:
                chunk = self.sock.recv(payload_len - len(payload_data))
                if not chunk:
                    raise ConnectionError("Connection closed by peer while reading payload")
                payload_data += chunk
                
            # Verify checksum
            expected_checksum = binascii.crc32(payload_data) & 0xffffffff
            if checksum != expected_checksum:
                raise ValueError(f"Checksum mismatch: expected {expected_checksum}, got {checksum}")
                
            payload_json = {}
            if payload_data:
                try:
                    payload_json = json.loads(payload_data.decode('utf-8'))
                except Exception as e:
                    payload_json = {"raw_data": payload_data.decode('utf-8', errors='ignore')}
                    
            return {
                'type': msg_type,
                'flags': flags,
                'seq': seq,
                'payload': payload_json
            }
        except socket.timeout:
            return None

def run_tests():
    print("=== STARTING INTEGRATION TESTS ===")
    
    # 1. Start Server
    # Ensure config file exists
    config_data = {
        "server": {
            "port": 9500,
            "max_clients": 5,
            "thread_pool_size": 10,
            "session_timeout_seconds": 60
        },
        "security": {
            "require_auth": False,
            "max_auth_attempts": 5,
            "rate_limit_msg_per_sec": 10,
            "enable_encryption": False,
            "enable_audit_log": False
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
        
    # Clean up old DB if exists
    if os.path.exists('vcs_chat.db'):
        os.remove('vcs_chat.db')
        
    server_process = subprocess.Popen(
        ['../build/vcs_server', '--config', 'test_config.json'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid
    )
    
    time.sleep(1.0) # Wait for server to start
    
    try:
        print("[*] Test 1: Connect Alice...")
        alice = TestClient('Alice', port=9500)
        alice.connect()
        alice.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Alice", "password": ""})
        
        resp = alice.recv_packet()
        assert resp is not None, "Alice connect accept timeout"
        if resp['type'] == MessageType.MSG_CONNECT_REJECT:
            print(f"DEBUG: Alice rejected with payload: {resp['payload']}")
        assert resp['type'] == MessageType.MSG_CONNECT_ACCEPT, f"Expected MSG_CONNECT_ACCEPT, got type {resp['type']}"
        assert resp['payload']['room'] == 'general', f"Expected room 'general', got {resp['payload'].get('room')}"
        print("[+] Test 1 Passed: Alice connected successfully!")
        
        # Verify sqlite db was created
        assert os.path.exists('vcs_chat.db'), "SQLite DB file vcs_chat.db was not created!"
        print("[+] SQLite DB verified.")
        
        print("[*] Test 2: Connect Bob...")
        bob = TestClient('Bob', port=9500)
        bob.connect()
        bob.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Bob", "password": ""})
        
        resp = bob.recv_packet()
        assert resp is not None, "Bob connect accept timeout"
        assert resp['type'] == MessageType.MSG_CONNECT_ACCEPT, f"Expected MSG_CONNECT_ACCEPT, got {resp['type']}"
        
        # Alice should receive a notify about Bob joining
        notify = alice.recv_packet()
        assert notify is not None, "Alice did not receive join notify"
        assert notify['type'] == MessageType.MSG_SYSTEM_NOTIFY, f"Expected MSG_SYSTEM_NOTIFY, got {notify['type']}"
        assert "Bob joined #general" in notify['payload']['message'], f"Unexpected message: {notify['payload']['message']}"
        print("[+] Test 2 Passed: Bob connected and system notification broadcasted!")

        print("[*] Test 3: Validate Nickname Taken...")
        charlie_fail = TestClient('Alice', port=9500)
        charlie_fail.connect()
        charlie_fail.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Alice", "password": ""})
        resp = charlie_fail.recv_packet()
        assert resp is not None, "Connection reject timeout"
        assert resp['type'] == MessageType.MSG_CONNECT_REJECT, f"Expected MSG_CONNECT_REJECT, got {resp['type']}"
        assert resp['payload']['code'] == ErrorCode.ERR_NICKNAME_TAKEN, f"Expected ERR_NICKNAME_TAKEN, got {resp['payload'].get('code')}"
        charlie_fail.close()
        print("[+] Test 3 Passed: Nickname duplication correctly rejected!")
        
        print("[*] Test 4: Validate Invalid Nickname...")
        dave_fail = TestClient('d', port=9500)
        dave_fail.connect()
        dave_fail.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "d", "password": ""}) # too short (min 3 chars)
        resp = dave_fail.recv_packet()
        assert resp is not None, "Connection reject timeout"
        assert resp['type'] == MessageType.MSG_CONNECT_REJECT, f"Expected MSG_CONNECT_REJECT, got {resp['type']}"
        assert resp['payload']['code'] == ErrorCode.ERR_NICKNAME_INVALID, f"Expected ERR_NICKNAME_INVALID, got {resp['payload'].get('code')}"
        dave_fail.close()
        print("[+] Test 4 Passed: Invalid nickname correctly rejected!")

        print("[*] Test 5: Chat broadcast...")
        alice.send_packet(MessageType.MSG_CHAT_SEND, {"message": "Hello from Alice!", "room": "general"})
        
        # Bob should receive the broadcast
        broadcast = bob.recv_packet()
        assert broadcast is not None, "Bob did not receive chat broadcast"
        assert broadcast['type'] == MessageType.MSG_CHAT_BROADCAST, f"Expected MSG_CHAT_BROADCAST, got {broadcast['type']}"
        assert broadcast['payload']['sender'] == 'Alice', f"Expected sender Alice, got {broadcast['payload']['sender']}"
        assert broadcast['payload']['message'] == 'Hello from Alice!', f"Expected message, got {broadcast['payload']['message']}"
        
        # Alice should also receive her own broadcast
        broadcast_alice = alice.recv_packet()
        assert broadcast_alice is not None, "Alice did not receive her own broadcast"
        assert broadcast_alice['type'] == MessageType.MSG_CHAT_BROADCAST
        print("[+] Test 5 Passed: Message broadcast successful!")

        print("[*] Test 6: Room Join and Isolation...")
        # Alice joins room "private_room"
        alice.send_packet(MessageType.MSG_ROOM_JOIN, {"room": "private_room"})
        
        # Alice gets "You joined #private_room"
        notif1 = alice.recv_packet()
        assert notif1 is not None and notif1['type'] == MessageType.MSG_SYSTEM_NOTIFY
        assert "You joined #private_room" in notif1['payload']['message']
        
        # Bob gets "Alice left #general"
        notif2 = bob.recv_packet()
        assert notif2 is not None and notif2['type'] == MessageType.MSG_SYSTEM_NOTIFY
        assert "Alice left #general" in notif2['payload']['message']
        
        # Alice sends message in "private_room"
        alice.send_packet(MessageType.MSG_CHAT_SEND, {"message": "Secret room text", "room": "private_room"})
        # Alice receives her own message
        notif_alice = alice.recv_packet()
        assert notif_alice is not None and notif_alice['type'] == MessageType.MSG_CHAT_BROADCAST
        
        # Bob should NOT receive the message (he is in "general")
        notif_bob = bob.recv_packet(timeout=0.5)
        assert notif_bob is None, f"Bob received isolated room message! {notif_bob}"
        print("[+] Test 6 Passed: Room join and message isolation verified!")

        print("[*] Test 7: Private messaging...")
        # Alice PMs Bob
        alice.send_packet(MessageType.MSG_CHAT_PRIVATE, {"to": "Bob", "message": "hello privately"})
        
        # Bob receives private message
        pm_bob = bob.recv_packet()
        assert pm_bob is not None
        assert pm_bob['type'] == MessageType.MSG_CHAT_PRIVATE, f"Expected MSG_CHAT_PRIVATE, got {pm_bob['type']}"
        assert pm_bob['payload']['from'] == 'Alice'
        assert pm_bob['payload']['message'] == 'hello privately'
        
        # Alice gets copy of PM
        pm_alice = alice.recv_packet()
        assert pm_alice is not None and pm_alice['type'] == MessageType.MSG_CHAT_PRIVATE
        
        # PM to non-existent user
        alice.send_packet(MessageType.MSG_CHAT_PRIVATE, {"to": "NonExistent", "message": "hello"})
        err_pkt = alice.recv_packet()
        assert err_pkt is not None
        assert err_pkt['type'] == MessageType.MSG_ERROR, f"Expected MSG_ERROR, got {err_pkt['type']}"
        assert err_pkt['payload']['code'] == ErrorCode.ERR_ROOM_NOT_FOUND
        print("[+] Test 7 Passed: Private message flow and error handling verified!")

        print("[*] Test 8: Get Users & Rooms List...")
        bob.send_packet(MessageType.MSG_USER_LIST_REQUEST)
        user_list_resp = bob.recv_packet()
        assert user_list_resp is not None
        assert user_list_resp['type'] == MessageType.MSG_USER_LIST_RESPONSE
        # Bob is the only user in general
        assert "Bob" in user_list_resp['payload']
        assert "Alice" not in user_list_resp['payload']
        
        bob.send_packet(MessageType.MSG_ROOM_LIST_REQUEST)
        room_list_resp = bob.recv_packet()
        assert room_list_resp is not None
        assert room_list_resp['type'] == MessageType.MSG_ROOM_LIST_RESPONSE
        assert "general" in room_list_resp['payload']
        assert "private_room" in room_list_resp['payload']
        print("[+] Test 8 Passed: User list and Room list queries verified!")

        print("[*] Test 9: Server Limit Max Clients...")
        # Currently 2 connections (Alice, Bob). Max is 5.
        # Let's connect Charlie, Dave, Eve successfully.
        charlie = TestClient('Charlie', port=9500)
        charlie.connect()
        charlie.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Charlie", "password": ""})
        assert charlie.recv_packet()['type'] == MessageType.MSG_CONNECT_ACCEPT

        dave = TestClient('Dave', port=9500)
        dave.connect()
        dave.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Dave", "password": ""})
        assert dave.recv_packet()['type'] == MessageType.MSG_CONNECT_ACCEPT

        eve = TestClient('Eve', port=9500)
        eve.connect()
        eve.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Eve", "password": ""})
        assert eve.recv_packet()['type'] == MessageType.MSG_CONNECT_ACCEPT

        # Now 5 clients connected. 6th client Frank should be rejected.
        frank_fail = TestClient('Frank', port=9500)
        frank_fail.connect()
        # The acceptLoop in server does the check and rejects before inserting or closes immediately
        resp = frank_fail.recv_packet()
        assert resp is not None
        assert resp['type'] == MessageType.MSG_CONNECT_REJECT, f"Expected MSG_CONNECT_REJECT, got {resp['type']}"
        assert resp['payload']['code'] == ErrorCode.ERR_SERVER_FULL, f"Expected ERR_SERVER_FULL, got {resp['payload'].get('code')}"
        frank_fail.close()
        
        # Clean up Charlie, Dave, Eve
        charlie.close()
        dave.close()
        eve.close()
        print("[+] Test 9 Passed: Max clients limit enforcement verified!")

        print("[*] Test 10: Client Disconnect system notification...")
        # Close Bob
        bob.close()
        time.sleep(0.5)  # Wait for server to process Bob's disconnect
        # Alice can join general again.
        alice.send_packet(MessageType.MSG_ROOM_JOIN, {"room": "general"})
        resp = alice.recv_packet()
        assert resp is not None
        assert resp['type'] == MessageType.MSG_SYSTEM_NOTIFY
        assert "You joined #general" in resp['payload']['message']

        charlie = TestClient('Charlie', port=9500)
        charlie.connect()
        charlie.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "Charlie", "password": ""})
        assert charlie.recv_packet()['type'] == MessageType.MSG_CONNECT_ACCEPT
        
        # Alice gets Charlie join
        assert alice.recv_packet()['type'] == MessageType.MSG_SYSTEM_NOTIFY
        
        # Charlie disconnects
        charlie.close()
        
        # Alice gets Charlie left notification
        notif = alice.recv_packet()
        assert notif is not None, "Alice did not receive disconnect notification"
        assert notif['type'] == MessageType.MSG_SYSTEM_NOTIFY, f"Expected MSG_SYSTEM_NOTIFY, got {notif['type']}"
        if "Charlie has left the chat" not in notif['payload']['message']:
            print(f"DEBUG: Alice received unexpected message: {notif['payload']['message']}")
        assert "Charlie has left the chat" in notif['payload']['message']
        print("[+] Test 10 Passed: Leave notification broadcast verified!")

        # Constants for manual packet building
        magic = b'\xAB\x53'
        version = 1
        flags = 0
        seq = 0

        print("[*] Test 11: Fragmentation / Partial Read...")
        payload_dict = {"message": "Fragmented message", "room": "general"}
        payload_bytes = json.dumps(payload_dict).encode('utf-8')
        payload_len = len(payload_bytes)
        checksum = binascii.crc32(payload_bytes) & 0xffffffff
        header = struct.pack('<2sBBBIII', magic, version, MessageType.MSG_CHAT_SEND, flags, seq, payload_len, checksum)
        full_packet = header + payload_bytes
        
        # Send it in chunks of 3 bytes with a small delay
        for i in range(0, len(full_packet), 3):
            chunk = full_packet[i:i+3]
            alice.sock.sendall(chunk)
            time.sleep(0.02)
            
        resp = alice.recv_packet()
        assert resp is not None, "Alice did not receive fragmented message broadcast back"
        assert resp['type'] == MessageType.MSG_CHAT_BROADCAST
        assert resp['payload']['message'] == "Fragmented message"
        print("[+] Test 11 Passed: Fragmentation stream reconstruction verified!")

        print("[*] Test 12: Coalesced Packets (Multiple packets in one read)...")
        payload_dict1 = {"message": "Coalesced 1", "room": "general"}
        payload_bytes1 = json.dumps(payload_dict1).encode('utf-8')
        checksum1 = binascii.crc32(payload_bytes1) & 0xffffffff
        header1 = struct.pack('<2sBBBIII', magic, version, MessageType.MSG_CHAT_SEND, flags, seq, len(payload_bytes1), checksum1)

        payload_dict2 = {"message": "Coalesced 2", "room": "general"}
        payload_bytes2 = json.dumps(payload_dict2).encode('utf-8')
        checksum2 = binascii.crc32(payload_bytes2) & 0xffffffff
        header2 = struct.pack('<2sBBBIII', magic, version, MessageType.MSG_CHAT_SEND, flags, seq, len(payload_bytes2), checksum2)

        # Send both together in a single call
        alice.sock.sendall(header1 + payload_bytes1 + header2 + payload_bytes2)

        r1 = alice.recv_packet()
        r2 = alice.recv_packet()
        assert r1 is not None and r2 is not None, "Did not receive both coalesced messages"
        messages = [r1['payload']['message'], r2['payload']['message']]
        assert "Coalesced 1" in messages
        assert "Coalesced 2" in messages
        print("[+] Test 12 Passed: Coalesced packets processing verified!")

        print("[*] Test 13: Invalid Magic Bytes...")
        dave_wrong = TestClient('DaveWrong', port=9500)
        dave_wrong.connect()
        dave_wrong.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "DaveWrong", "password": ""})
        assert dave_wrong.recv_packet()['type'] == MessageType.MSG_CONNECT_ACCEPT
        
        # Alice gets DaveWrong join notification
        notif1 = alice.recv_packet()
        assert notif1 is not None and notif1['type'] == MessageType.MSG_SYSTEM_NOTIFY
        assert "DaveWrong joined" in notif1['payload']['message']

        # Send bad magic
        bad_header = struct.pack('<2sBBBIII', b'\x00\x00', version, MessageType.MSG_CHAT_SEND, flags, seq, 0, 0)
        dave_wrong.sock.sendall(bad_header)
        
        # Verify connection is closed by server
        data = dave_wrong.sock.recv(1024)
        assert data == b'', "Server did not close socket on invalid magic bytes"
        dave_wrong.close()

        # Alice gets DaveWrong leave notification
        notif2 = alice.recv_packet()
        assert notif2 is not None and notif2['type'] == MessageType.MSG_SYSTEM_NOTIFY
        assert "DaveWrong has left" in notif2['payload']['message']

        print("[+] Test 13 Passed: Invalid magic bytes rejection verified!")

        print("[*] Test 14: Invalid Checksum / CRC32...")
        payload_bytes = json.dumps({"message": "Bad Checksum", "room": "general"}).encode('utf-8')
        bad_checksum = 123456789  # wrong checksum
        header = struct.pack('<2sBBBIII', magic, version, MessageType.MSG_CHAT_SEND, flags, seq, len(payload_bytes), bad_checksum)
        alice.sock.sendall(header + payload_bytes)
        
        # Verify packet is dropped (no broadcast received) and Alice is still connected
        res = alice.recv_packet(timeout=0.5)
        assert res is None, "Packet with wrong checksum was not dropped"
        
        # Send valid message to confirm connection is still healthy
        alice.send_packet(MessageType.MSG_CHAT_SEND, {"message": "Healthy after bad checksum", "room": "general"})
        res = alice.recv_packet()
        assert res is not None
        assert res['type'] == MessageType.MSG_CHAT_BROADCAST
        assert res['payload']['message'] == "Healthy after bad checksum"
        print("[+] Test 14 Passed: Invalid checksum packet dropping verified!")

        print("[*] Test 15: Payload Size Limit Violation...")
        dave_large = TestClient('DaveLarge', port=9500)
        dave_large.connect()
        dave_large.send_packet(MessageType.MSG_CONNECT_REQUEST, {"nickname": "DaveLarge", "password": ""})
        assert dave_large.recv_packet()['type'] == MessageType.MSG_CONNECT_ACCEPT

        # Alice gets DaveLarge join notification
        notif1 = alice.recv_packet()
        assert notif1 is not None and notif1['type'] == MessageType.MSG_SYSTEM_NOTIFY
        assert "DaveLarge joined" in notif1['payload']['message']

        # Send header specifying huge payload length (50,000 bytes)
        huge_header = struct.pack('<2sBBBIII', magic, version, MessageType.MSG_CHAT_SEND, flags, seq, 50000, 0)
        dave_large.sock.sendall(huge_header)
        
        # Verify connection is closed by server immediately (OOM protection)
        data = dave_large.sock.recv(1024)
        assert data == b'', "Server did not close socket on oversized payload length header"
        dave_large.close()

        # Alice gets DaveLarge leave notification
        notif2 = alice.recv_packet()
        assert notif2 is not None and notif2['type'] == MessageType.MSG_SYSTEM_NOTIFY
        assert "DaveLarge has left" in notif2['payload']['message']

        print("[+] Test 15 Passed: Oversized payload length protection verified!")

        print("[*] Test 16: Graceful Shutdown...")
        # Send SIGINT to server process group
        os.killpg(os.getpgid(server_process.pid), signal.SIGINT)
        
        # Alice should receive a server shutting down notification and get disconnected
        notif = alice.recv_packet(timeout=3.0)
        assert notif is not None
        assert notif['type'] == MessageType.MSG_SYSTEM_NOTIFY or notif['type'] == MessageType.MSG_DISCONNECT
        
        # Connection should close
        try:
            alice.recv_packet(timeout=1.0)
        except ConnectionError:
            pass # Expected
            
        server_process.wait(timeout=5.0)
        assert server_process.returncode == 0, f"Server exit code: {server_process.returncode}"
        print("[+] Test 16 Passed: Graceful shutdown verified!")

        print("\n===============================")
        print("ALL TESTS PASSED SUCCESSFULLY!")
        print("===============================")
        return True

    except Exception as e:
        import traceback
        traceback.print_exc()
        print("\n[!] TESTS FAILED!")
        if 'server_process' in locals() and server_process.poll() is not None:
            stdout, stderr = server_process.communicate()
            print("SERVER STDOUT:", stdout.decode())
            print("SERVER STDERR:", stderr.decode())
        return False
    finally:
        # Clean up
        try:
            os.killpg(os.getpgid(server_process.pid), signal.SIGKILL)
        except:
            pass
        if os.path.exists('test_config.json'):
            os.remove('test_config.json')

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
