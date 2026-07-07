#include "Builder.h"
#include <nlohmann/json.hpp>
#include <ctime>

using json = nlohmann::json;

static Packet makePacket(MessageType type, const std::string &jsonStr)
{
    std::vector<uint8_t> payload(jsonStr.begin(), jsonStr.end());
    return Packet(type, payload);
}

namespace Builder
{
    Packet makeSystemNotify(const std::string &message)
    {
        json j;
        j["message"] = message;
        return makePacket(MessageType::MSG_SYSTEM_NOTIFY, j.dump());
    }

    Packet makeConnectAccept(const std::string &token, const std::string &room, const std::string &nickname, bool isAdmin)
    {
        json j;
        j["token"] = token;
        j["room"] = room;
        j["nickname"] = nickname;
        j["is_admin"] = isAdmin;
        return makePacket(MessageType::MSG_CONNECT_ACCEPT, j.dump());
    }

    Packet makeConnectReject(ErrorCode code, const std::string &reason)
    {
        json j;
        j["code"] = static_cast<uint8_t>(code);
        j["reason"] = reason;
        return makePacket(MessageType::MSG_CONNECT_REJECT, j.dump());
    }

    Packet makeReconnectRequest(const std::string &token)
    {
        json j;
        j["token"] = token;
        return makePacket(MessageType::MSG_RECONNECT_REQUEST, j.dump());
    }

    Packet makeChatBroadcast(const std::string &sender, const std::string &room, const std::string &message)
    {
        json j;
        j["sender"] = sender;
        j["room"] = room;
        j["message"] = message;
        j["ts"] = (long long)std::time(nullptr);
        return makePacket(MessageType::MSG_CHAT_BROADCAST, j.dump());
    }

    Packet makeUserListResponse(const std::string &jsonList)
    {
        return makePacket(MessageType::MSG_USER_LIST_RESPONSE, jsonList);
    }

    Packet makeRoomListResponse(const std::string &jsonList)
    {
        return makePacket(MessageType::MSG_ROOM_LIST_RESPONSE, jsonList);
    }

    Packet makeAdminRoomInfoResponse(const std::string &jsonList)
    {
        return makePacket(MessageType::MSG_ADMIN_ROOM_INFO_RESPONSE, jsonList);
    }

    Packet makePing()
    {
        return Packet(MessageType::MSG_PING, {});
    }

    Packet makePong()
    {
        return Packet(MessageType::MSG_PONG, {});
    }

    Packet makeError(ErrorCode code, const std::string &detail)
    {
        json j;
        j["code"] = static_cast<uint8_t>(code);
        j["detail"] = detail;
        return makePacket(MessageType::MSG_ERROR, j.dump());
    }

    Packet makeDisconnect(const std::string &reason)
    {
        json j;
        j["reason"] = reason;
        return makePacket(MessageType::MSG_DISCONNECT, j.dump());
    }
}