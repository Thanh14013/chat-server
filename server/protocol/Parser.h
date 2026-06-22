#pragma once
#include "../../common/Protocol.h"
#include <string>

struct ParsedConnect {
    std::string nickname;
    std::string password;
};

struct ParsedChat {
    std::string message;
    std::string room;
};

struct ParsedPrivate {
    std::string to;
    std::string message;
};

struct ParsedRoomOp {
    std::string room_name;
    std::string password;
};

namespace Parser {
    ParsedConnect  parseConnectRequest(const Packet& pkt);
    std::string    parseReconnectRequest(const Packet& pkt);
    ParsedChat     parseChatSend(const Packet& pkt);
    ParsedPrivate  parseChatPrivate(const Packet& pkt);
    ParsedRoomOp   parseRoomJoin(const Packet& pkt);
    ParsedRoomOp   parseRoomCreate(const Packet& pkt);
    ParsedRoomOp   parseRoomDelete(const Packet& pkt);
    std::string    payloadToString(const Packet& pkt);
}