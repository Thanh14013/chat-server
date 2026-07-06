# VCS SecureChat — API & Commands Reference

## Client Commands

These commands can be typed directly into the client terminal by standard users.

| Command | Arguments | Description |
|---|---|---|
| `/join` | `<room_name> [password]` | Join a chat room. |
| `/leave` | | Leave the current chat room. |
| `/create` | `<room_name> [password]` | Create a new chat room. |
| `/delete` | `<room_name>` | Delete a room. Requires Room Creator, Admin, or Owner. |
| `/list` | | List all users in the current room. |
| `/listall` | | List all active public rooms (alias for `/rooms`). |
| `/rooms` | | List all active public rooms. |
| `/msg` | `<username> <message>` | Send a private message to a specific user. |
| `/send` | `<username> <filepath>` | Request to send a file securely to a user. |
| `/accept` | `<transfer_id>` | Accept an incoming file transfer. |
| `/reject` | `<transfer_id>` | Reject an incoming file transfer. |
| `/whois` | `<username>` | Request public profile info about a user. |
| `/help` | | Display the help menu. |
| `/quit` | | Disconnect and exit. |

## Admin Commands

These commands are restricted to users with `ADMIN` or `OWNER` privileges.

| Command | Arguments | Description |
|---|---|---|
| `/kick` | `<username> [reason]` | Kick a user from their current room. |
| `/unkick` | `<username> <room_name>` | Remove a user from a room's kick list. |
| `/mute` | `<username> [seconds]` | Prevent a user from sending messages. |
| `/unmute` | `<username>` | Remove a mute restriction. |
| `/ban` | `<username> [reason]` | Permanently ban a user (IP + Account). |
| `/unban` | `<username>` | Remove a ban from a user. |
| `/broadcast`| `<message>` | Send a global system message to all users. |
| `/rooms_admin` | | View detailed info of all rooms (creator, member count). |

## Owner Commands

These commands are restricted to users with `OWNER` privileges.

| Command | Arguments | Description |
|---|---|---|
| `/promote` | `<username>` | Promote a user to ADMIN role. |
| `/demote` | `<username>` | Demote an ADMIN to USER role. |

## Protocol Headers

All network communication uses a custom binary protocol with the following structure:

```cpp
struct PacketHeader {
    uint8_t magic[2];      // 'V', 'C'
    uint8_t version;       // 1
    uint8_t msg_type;      // MessageType enum
    uint32_t payload_length;
    uint32_t checksum;     // CRC32 of payload
};
```
