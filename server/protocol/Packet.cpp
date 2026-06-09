#include "Packet.h"
#include "../../common/Constants.h"
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>

uint32_t computeCRC32(const std::vector<uint8_t> &data)
{
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data)
    {
        crc ^= byte;
        for (int i = 0; i < 8; i++)
        {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}

std::vector<uint8_t> packetToBytes(const Packet &pkt)
{
    uint32_t checksum = computeCRC32(pkt.payload);
    std::vector<uint8_t> result(sizeof(PacketHeader) + pkt.payload.size());
    std::memcpy(result.data(), &pkt.header, sizeof(PacketHeader));

    uint32_t *checksum_ptr = reinterpret_cast<uint32_t *>(result.data() + sizeof(PacketHeader) - sizeof(uint32_t));
    *checksum_ptr = checksum;

    if (!pkt.payload.empty())
    {
        std::memcpy(result.data() + sizeof(PacketHeader), pkt.payload.data(), pkt.payload.size());
    }

    return result;
}

static bool recvAll(int fd, uint8_t *buf, size_t len)
{
    size_t received = 0;
    while (received < len)
    {
        ssize_t n = recv(fd, buf + received, len - received, 0);
        if (n <= 0)
            return false;
        received += n;
    }
    return true;
}

bool readPacketFromFd(int fd, Packet &out)
{
    uint8_t headerBuf[sizeof(PacketHeader)];
    if (!recvAll(fd, headerBuf, sizeof(PacketHeader)))
        return false;
    PacketHeader hdr;
    std::memcpy(&hdr, headerBuf, sizeof(PacketHeader));

    if (hdr.magic[0] != Constants::MAGIC_BYTE_0 || hdr.magic[1] != Constants::MAGIC_BYTE_1)
        return false;
    if (hdr.version != Constants::PROTOCOL_VERSION)
        return false;
    if (hdr.payload_length > static_cast<uint32_t>(Constants::MAX_MESSAGE_LEN + 256))
        return false;

    std::vector<uint8_t> payload(hdr.payload_length);
    if (hdr.payload_length > 0)
    {
        if (!recvAll(fd, payload.data(), hdr.payload_length))
            return false;
    }

    uint32_t expected = computeCRC32(payload);
    if (hdr.checksum != expected)
        return false;

    out.header = hdr;
    out.payload = std::move(payload);
    return true;
}