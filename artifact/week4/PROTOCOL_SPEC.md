# VCS SecureChat — Protocol Specification v1.0

## 1. Overview & Design Goals

VCS SecureChat uses a custom binary protocol over TCP with the following goals:

- **Unambiguous framing**: fixed-length header with length-prefix payload — no delimiter scanning
- **Integrity**: CRC32 checksum on every packet
- **Versioning**: protocol version field allows future upgrades without breaking existing clients
- **Identification**: magic bytes `0xAB 0x53` identify VCS SecureChat traffic

---

## 2. Packet Wire Format

```
 0       1       2       3       4       5       6       7       8
 +-------+-------+-------+-------+-------+-------+-------+-------+
 | magic[0]=0xAB | magic[1]=0x53 | version=0x01  | msg_type      |
 +-------+-------+-------+-------+-------+-------+-------+-------+
 | flags         |         sequence_number (uint32, big-endian)   |
 +-------+-------+-------+-------+-------+-------+-------+-------+
 |         payload_length (uint32, big-endian)                    |
 +-------+-------+-------+-------+-------+-------+-------+-------+
 |         checksum CRC32 (uint32, big-endian)                    |
 +-------+-------+-------+-------+-------+-------+-------+-------+
 |  PAYLOAD (payload_length bytes, JSON-encoded)                  |
 +-------+-------+-------+-------+-------+-------+-------+-------+
```

**Header fields (17 bytes total, packed):**

| Offset | Size | Field            | Description                                     |
|--------|------|------------------|-------------------------------------------------|
| 0      | 2    | `magic`          | `0xAB 0x53` — VCS signature                    |
| 2      | 1    | `version`        | Protocol version, currently `0x01`             |
| 3      | 1    | `msg_type`       | Message type enum (see §3)                     |
| 4      | 1    | `flags`          | Bit flags: `0x01`=ENCRYPTED `0x02`=COMPRESSED  |
| 5      | 4    | `sequence_num`   | Per-session monotonic counter, anti-replay     |
| 9      | 4    | `payload_length` | Byte count of payload following header         |
| 13     | 4    | `checksum`       | CRC32 of payload bytes only                    |

**Payload:** JSON-encoded string (UTF-8). Max 4096 bytes.

---

## 3. Message Types

### Connection Group

| Type                  | Value  | Direction      | Payload Fields                          |
|-----------------------|--------|----------------|-----------------------------------------|
| `MSG_CONNECT_REQUEST` | `0x01` | Client→Server  | `nickname`, `password`                 |
| `MSG_CONNECT_ACCEPT`  | `0x02` | Server→Client  | `token`, `room`                        |
| `MSG_CONNECT_REJECT`  | `0x03` | Server→Client  | `code`, `reason`                       |
| `MSG_DISCONNECT`      | `0x04` | Both           | `reason`                               |
| `MSG_PING`            | `0x05` | Server→Client  | *(empty)*                              |
| `MSG_PONG`            | `0x06` | Client→Server  | *(empty)*                              |

### Chat Group

| Type                  | Value  | Direction      | Payload Fields                          |
|-----------------------|--------|----------------|-----------------------------------------|
| `MSG_CHAT_SEND`       | `0x10` | Client→Server  | `message`, `room`                      |
| `MSG_CHAT_BROADCAST`  | `0x11` | Server→Client  | `sender`, `room`, `message`            |
| `MSG_CHAT_PRIVATE`    | `0x12` | Both           | `from`, `to`, `message`               |
| `MSG_SYSTEM_NOTIFY`   | `0x13` | Server→Client  | `message`                              |

### Room Group

| Type                    | Value  | Direction      | Payload Fields     |
|-------------------------|--------|----------------|--------------------|
| `MSG_ROOM_JOIN`         | `0x20` | Client→Server  | `room`            |
| `MSG_ROOM_LEAVE`        | `0x21` | Client→Server  | *(empty)*         |
| `MSG_ROOM_LIST_REQUEST` | `0x22` | Client→Server  | *(empty)*         |
| `MSG_ROOM_LIST_RESPONSE`| `0x23` | Server→Client  | `["room1",...]`   |
| `MSG_ROOM_CREATE`       | `0x24` | Client→Server  | `room`            |

### File Transfer Group

| Type                  | Value  | Direction      | Payload Fields                               |
|-----------------------|--------|----------------|----------------------------------------------|
| `MSG_FILE_REQUEST`    | `0x50` | Both (relay)   | `transfer_id`, `from`, `filename`, `size`, `sha256` |
| `MSG_FILE_ACCEPT`     | `0x51` | Client→Server  | `transfer_id`                               |
| `MSG_FILE_REJECT`     | `0x52` | Client→Server  | `transfer_id`                               |
| `MSG_FILE_DATA`       | `0x53` | Both (relay)   | `transfer_id`, `data` (base64)              |
| `MSG_FILE_COMPLETE`   | `0x54` | Both (relay)   | `transfer_id`, `ok`                         |

### Admin Group

| Type                  | Value  | Direction      | Payload Fields                  |
|-----------------------|--------|----------------|---------------------------------|
| `MSG_ADMIN_KICK`      | `0x60` | Client→Server  | `target`, `reason`             |
| `MSG_ADMIN_MUTE`      | `0x61` | Client→Server  | `target`, `duration`           |
| `MSG_ADMIN_BAN`       | `0x62` | Client→Server  | `target`, `reason`, `unban?`   |
| `MSG_ADMIN_PROMOTE`   | `0x63` | Client→Server  | `target`, `demote?`            |

### Error

| Type        | Value  | Direction      | Payload Fields   |
|-------------|--------|----------------|------------------|
| `MSG_ERROR` | `0xFF` | Server→Client  | `code`, `detail` |

---

## 4. Connection Handshake (Week 1 baseline)

```
Client                          Server
  |                                |
  |----TCP connect---------------->|
  |                                |
  |----MSG_CONNECT_REQUEST-------->|  {nickname, password}
  |                                |
  |<---MSG_CONNECT_ACCEPT----------|  {token, room}
  |         OR                     |
  |<---MSG_CONNECT_REJECT----------|  {code, reason}
  |                                |
  |====== Chat session active ======|
  |                                |
  |----MSG_PING (every 30s)------->|  (keepalive from server)
  |<---MSG_PONG--------------------|
```

---

## 5. Error Codes

| Code   | Name                        | Description                    |
|--------|-----------------------------|--------------------------------|
| `0x00` | `ERR_OK`                    | Success                        |
| `0x01` | `ERR_NICKNAME_TAKEN`        | Nickname already in use        |
| `0x02` | `ERR_NICKNAME_INVALID`      | Invalid format                 |
| `0x03` | `ERR_ROOM_FULL`             | Room at capacity               |
| `0x04` | `ERR_ROOM_NOT_FOUND`        | Room does not exist            |
| `0x05` | `ERR_AUTH_FAILED`           | Bad credentials                |
| `0x06` | `ERR_AUTH_TOO_MANY_ATTEMPTS`| Account locked                 |
| `0x07` | `ERR_RATE_LIMITED`          | Message rate exceeded          |
| `0x08` | `ERR_MESSAGE_TOO_LONG`      | Payload > 4096 bytes           |
| `0x09` | `ERR_FILE_TOO_LARGE`        | File > 3 MB                    |
| `0x0A` | `ERR_PERMISSION_DENIED`     | Insufficient role              |
| `0x0B` | `ERR_CRYPTO_HANDSHAKE_FAIL` | Encryption setup failed        |
| `0x0C` | `ERR_INVALID_TOKEN`         | Session token rejected         |
| `0x0D` | `ERR_REPLAY_DETECTED`       | Duplicate sequence number      |
| `0x0E` | `ERR_SERVER_FULL`           | Max connections reached        |
| `0xFF` | `ERR_INTERNAL`              | Unspecified server error       |

---

## 6. Versioning Strategy

The `version` field in the header allows non-breaking upgrades. Rules:

- Server **must** reject packets with `version > PROTOCOL_VERSION`
- Minor additions (new msg_type values) increment minor version only
- Structural header changes increment major version

---

## 7. Packet Example (Hex)

`MSG_CONNECT_REQUEST` — nickname="Alice", password=""

```
Offset  Hex            Description
0x00    AB 53          Magic bytes (VCS)
0x02    01             Protocol version = 1
0x03    01             msg_type = MSG_CONNECT_REQUEST
0x04    00             flags = NONE
0x05    00 00 00 01    sequence_num = 1
0x09    00 00 00 23    payload_length = 35 bytes
0x0D    XX XX XX XX    CRC32 of payload
0x11    7B 22 6E 69... {"nickname":"Alice","password":""}
```
