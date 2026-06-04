#pragma once
#include <cstdint>
#include <vector>
#include "Constants.h"
#include "MessageTypes.h"

namespace Flags {
    constexpr uint8_t NONE        = 0x00;
    constexpr uint8_t ENCRYPTED   = 0x01;
    constexpr uint8_t COMPRESSED  = 0x02;
    constexpr uint8_t FRAGMENTED  = 0x04;
}

#pragma pack(push, 1)
struct PacketHeader {
    uint8_t  magic[2];
    uint8_t  version;
    uint8_t  msg_type;
    uint8_t  flags;
    uint32_t sequence_num;
    uint32_t payload_length;
    uint32_t checksum;
};
#pragma pack(pop)

static_assert(sizeof(PacketHeader) == 15, "PacketHeader must be exactly 15 bytes");

struct Packet {
    PacketHeader          header;
    std::vector<uint8_t>  payload;

    Packet() {
        header.magic[0]      = Constants::MAGIC_BYTE_0;
        header.magic[1]      = Constants::MAGIC_BYTE_1;
        header.version       = Constants::PROTOCOL_VERSION;
        header.msg_type      = 0x00;
        header.flags         = Flags::NONE;
        header.sequence_num  = 0;
        header.payload_length= 0;
        header.checksum      = 0;
    }

    Packet(MessageType type, const std::vector<uint8_t>& data)
        : Packet()
    {
        header.msg_type       = static_cast<uint8_t>(type);
        header.payload_length = static_cast<uint32_t>(data.size());
        payload               = data;
    }
};
