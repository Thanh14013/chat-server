#pragma once
#include "../../common/Protocol.h"
#include <vector>
#include <cstdint>

uint32_t computeCRC32(const std::vector<uint8_t>& data);

std::vector<uint8_t> packetToBytes(const Packet& pkt);

bool readPacketFromFd(int fd, Packet& out);
