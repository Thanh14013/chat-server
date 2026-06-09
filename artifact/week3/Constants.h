#pragma once
#include <cstdint>

namespace Constants {
    constexpr uint16_t DEFAULT_PORT          = 9000;
    constexpr int      MAX_CLIENTS           = 256;
    constexpr int      THREAD_POOL_SIZE      = 32;
    constexpr int      MAX_NICKNAME_LEN      = 32;
    constexpr int      MAX_MESSAGE_LEN       = 4096;
    constexpr int      MAX_ROOM_NAME_LEN     = 64;
    constexpr int      MAX_ROOMS             = 32;
    constexpr int      SESSION_TIMEOUT_SEC   = 3600;
    constexpr int      RATE_LIMIT_MSG_PER_SEC= 10;
    constexpr uint8_t  MAGIC_BYTE_0          = 0xAB;
    constexpr uint8_t  MAGIC_BYTE_1          = 0x53;
    constexpr uint8_t  PROTOCOL_VERSION      = 1;
    constexpr int      MAX_FILE_SIZE_MB      = 3;
    constexpr int      HISTORY_BUFFER_SIZE   = 100;
    constexpr int      AUTH_MAX_ATTEMPTS     = 5;
    constexpr int      NONCE_SIZE            = 16;
    constexpr int      HEADER_SIZE           = 17;
    constexpr int      PING_INTERVAL_SEC     = 30;
    constexpr int      PONG_TIMEOUT_SEC      = 60;
}
