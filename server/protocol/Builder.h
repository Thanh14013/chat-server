#pragma once
#include "../../common/Protocol.h"
#include "../../common/ErrorCodes.h"
#include <string>

namespace Builder {
    Packet makeSystemNotify(const std::string& message);
    Packet makeConnectAccept(const std::string& token, const std::string& room, const std::string& nickname, bool isAdmin = false);
    Packet makeConnectReject(ErrorCode code, const std::string& reason);
    Packet makeReconnectRequest(const std::string& token);
    Packet makeChatBroadcast(const std::string& sender, const std::string& room, const std::string& message);
    Packet makeUserListResponse(const std::string& jsonList);
    Packet makeRoomListResponse(const std::string& jsonList);
    Packet makeAdminRoomInfoResponse(const std::string& jsonList);
    Packet makePing();
    Packet makePong();
    Packet makeError(ErrorCode code, const std::string& detail);
    Packet makeDisconnect(const std::string& reason);
}
