#pragma once
#include <cstdint>

enum class MessageType : uint8_t {
    MSG_CONNECT_REQUEST      = 0x01,
    MSG_CONNECT_ACCEPT       = 0x02,
    MSG_CONNECT_REJECT       = 0x03,
    MSG_DISCONNECT           = 0x04,
    MSG_PING                 = 0x05,
    MSG_PONG                 = 0x06,
    MSG_RECONNECT_REQUEST    = 0x07,

    MSG_CHAT_SEND            = 0x10,
    MSG_CHAT_BROADCAST       = 0x11,
    MSG_CHAT_PRIVATE         = 0x12,
    MSG_SYSTEM_NOTIFY        = 0x13,

    MSG_ROOM_JOIN            = 0x20,
    MSG_ROOM_LEAVE           = 0x21,
    MSG_ROOM_LIST_REQUEST    = 0x22,
    MSG_ROOM_LIST_RESPONSE   = 0x23,
    MSG_ROOM_CREATE          = 0x24,

    MSG_USER_LIST_REQUEST    = 0x30,
    MSG_USER_LIST_RESPONSE   = 0x31,
    MSG_USER_LISTALL_REQUEST = 0x32,
    MSG_USER_LISTALL_RESPONSE= 0x33,
    MSG_WHOIS_REQUEST        = 0x34,
    MSG_WHOIS_RESPONSE       = 0x35,

    MSG_CRYPTO_HELLO         = 0x40,
    MSG_CRYPTO_KEY_OFFER     = 0x41,
    MSG_CRYPTO_KEY_ACCEPT    = 0x42,
    MSG_CRYPTO_HANDSHAKE_OK  = 0x43,

    MSG_FILE_REQUEST         = 0x50,
    MSG_FILE_ACCEPT          = 0x51,
    MSG_FILE_REJECT          = 0x52,
    MSG_FILE_DATA            = 0x53,
    MSG_FILE_COMPLETE        = 0x54,

    MSG_ADMIN_KICK           = 0x60,
    MSG_ADMIN_MUTE           = 0x61,
    MSG_ADMIN_BAN            = 0x62,
    MSG_ADMIN_PROMOTE        = 0x63,
    MSG_ADMIN_BROADCAST      = 0x64,

    MSG_ERROR                = 0xFF
};
