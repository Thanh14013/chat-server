# VCS SecureChat — API & Commands Reference

## Client Commands

These commands can be typed directly into the client terminal by standard users.

| Command | Arguments | Description |
|---|---|---|
| `/register` | `<username> <password>` | Register a new account. |
| `/login` | `<username> <password>` | Login to an existing account. |
| `/join` | `<room_name>` | Join a chat room. |
| `/leave` | | Leave the current chat room. |
| `/msg` | `<username> <message>` | Send a private message to a specific user. |
| `/file` | `send <username> <filepath>` | Send a file securely to a user. |
| `/file` | `recv <file_id>` | Accept an incoming file transfer. |
| `/whois` | `<username>` | Request public profile info about a user. |
| `/users` | | List all users in the current room. |
| `/rooms` | | List all active public rooms. |
| `/clear` | | Clear terminal screen. |
| `/quit` | | Disconnect and exit. |

## Admin Commands

These commands are restricted to users with `ADMIN` privileges.

| Command | Arguments | Description |
|---|---|---|
| `/admin kick` | `<username> [reason]` | Kick a user from the server. |
| `/admin ban` | `<username> [reason]` | Permanently ban a user (IP + Account). |
| `/admin tempban` | `<username> <seconds> [reason]` | Temporarily ban a user. |
| `/admin mute` | `<username> <seconds> [reason]` | Prevent a user from sending messages. |
| `/admin unmute` | `<username>` | Remove a mute restriction. |
| `/admin broadcast`| `<message>` | Send a global system message to all users. |
| `/admin shutdown` | | Gracefully shutdown the server. |

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
