#include "Parser.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace Parser
{

    std::string payloadToString(const Packet &pkt)
    {
        return std::string(pkt.payload.begin(), pkt.payload.end());
    }

    ParsedConnect parseConnectRequest(const Packet &pkt)
    {
        ParsedConnect result;
        try
        {
            auto j = json::parse(payloadToString(pkt));
            result.nickname = j.value("nickname", "");
            result.password = j.value("password", "");
        }
        catch (...)
        {
        }
        return result;
    }

    std::string parseReconnectRequest(const Packet &pkt)
    {
        try
        {
            auto j = json::parse(payloadToString(pkt));
            return j.value("token", "");
        }
        catch (...)
        {
        }
        return "";
    }

    ParsedChat parseChatSend(const Packet &pkt)
    {
        ParsedChat result;
        try
        {
            auto j = json::parse(payloadToString(pkt));
            result.message = j.value("message", "");
            result.room = j.value("room", "general");
        }
        catch (...)
        {
        }
        return result;
    }

    ParsedPrivate parseChatPrivate(const Packet &pkt)
    {
        ParsedPrivate result;
        try
        {
            auto j = json::parse(payloadToString(pkt));
            result.to = j.value("to", "");
            result.message = j.value("message", "");
        }
        catch (...)
        {
        }
        return result;
    }

    ParsedRoomOp parseRoomJoin(const Packet &pkt)
    {
        ParsedRoomOp result;
        try
        {
            auto j = json::parse(payloadToString(pkt));
            result.room_name = j.value("room", "general");
        }
        catch (...)
        {
        }
        return result;
    }

    ParsedRoomOp parseRoomCreate(const Packet &pkt)
    {
        ParsedRoomOp result;
        try
        {
            auto j = json::parse(payloadToString(pkt));
            result.room_name = j.value("room", "");
        }
        catch (...)
        {
        }
        return result;
    }
}