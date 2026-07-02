#pragma once
#include <cstdint>

enum class ErrorCode : uint8_t {
    ERR_OK                     = 0x00,
    ERR_NICKNAME_TAKEN         = 0x01,
    ERR_NICKNAME_INVALID       = 0x02,
    ERR_ROOM_FULL              = 0x03,
    ERR_ROOM_NOT_FOUND         = 0x04,
    ERR_AUTH_FAILED            = 0x05,
    ERR_AUTH_TOO_MANY_ATTEMPTS = 0x06,
    ERR_RATE_LIMITED           = 0x07,
    ERR_MESSAGE_TOO_LONG       = 0x08,
    ERR_FILE_TOO_LARGE         = 0x09,
    ERR_PERMISSION_DENIED      = 0x0A,
    ERR_CRYPTO_HANDSHAKE_FAIL  = 0x0B,
    ERR_INVALID_TOKEN          = 0x0C,
    ERR_REPLAY_DETECTED        = 0x0D,
    ERR_SERVER_FULL            = 0x0E,
    ERR_MESSAGE_BLOCKED        = 0x0F,
    ERR_INTERNAL               = 0xFF
};
