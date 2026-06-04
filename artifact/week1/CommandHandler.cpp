#include "CommandHandler.h"
#include "../core/TcpClient.h"
#include "../../common/Protocol.h"
#include "../../common/MessageTypes.h"
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

static Packet makeJsonPacket(MessageType type, const json& j) {
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    return Packet(type, payload);
}

CommandHandler::CommandHandler(TcpClient* client) : m_client(client), m_currentRoom("general") {}

bool CommandHandler::handle(const Command& cmd) {
    switch (cmd.type) {
        case CommandType::CMD_QUIT:      cmdQuit();          return false;
        case CommandType::CMD_LIST:      cmdList();          break;
        case CommandType::CMD_LIST_ALL:  cmdListAll();       break;
        case CommandType::CMD_ROOMS:     cmdRooms();         break;
        case CommandType::CMD_JOIN:      cmdJoin(cmd);       break;
        case CommandType::CMD_LEAVE:     cmdLeave();         break;
        case CommandType::CMD_CREATE:    cmdCreate(cmd);     break;
        case CommandType::CMD_MSG:       cmdMsg(cmd);        break;
        case CommandType::CMD_WHOIS:     cmdWhois(cmd);      break;
        case CommandType::CMD_HELP:      cmdHelp(cmd);       break;
        case CommandType::CMD_KICK:      cmdKick(cmd);       break;
        case CommandType::CMD_MUTE:      cmdMute(cmd);       break;
        case CommandType::CMD_UNMUTE:    cmdUnmute(cmd);     break;
        case CommandType::CMD_BAN:       cmdBan(cmd);        break;
        case CommandType::CMD_UNBAN:     cmdUnban(cmd);      break;
        case CommandType::CMD_PROMOTE:   cmdPromote(cmd);    break;
        case CommandType::CMD_DEMOTE:    cmdDemote(cmd);     break;
        case CommandType::CMD_BROADCAST: cmdBroadcast(cmd);  break;
        case CommandType::CMD_SHUTDOWN:  cmdShutdown(cmd);   break;
        default:
            std::cout << "[!] Unknown command. Type /help for a list.\n";
            break;
    }
    return true;
}

void CommandHandler::cmdQuit() {
    json j; j["reason"] = "User quit";
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_DISCONNECT, j));
    m_client->disconnect();
}

void CommandHandler::cmdList() {
    m_client->sendPacket(Packet(MessageType::MSG_USER_LIST_REQUEST, {}));
}

void CommandHandler::cmdListAll() {
    m_client->sendPacket(Packet(MessageType::MSG_USER_LIST_REQUEST, {}));
}

void CommandHandler::cmdRooms() {
    m_client->sendPacket(Packet(MessageType::MSG_ROOM_LIST_REQUEST, {}));
}

void CommandHandler::cmdJoin(const Command& cmd) {
    if (cmd.args.empty()) { std::cout << "Usage: /join #room\n"; return; }
    std::string room = cmd.args[0];
    if (!room.empty() && room[0] == '#') room = room.substr(1);
    json j; j["room"] = room;
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_ROOM_JOIN, j));
}

void CommandHandler::cmdLeave() {
    m_client->sendPacket(Packet(MessageType::MSG_ROOM_LEAVE, {}));
}

void CommandHandler::cmdCreate(const Command& cmd) {
    if (cmd.args.empty()) { std::cout << "Usage: /create #room\n"; return; }
    std::string room = cmd.args[0];
    if (!room.empty() && room[0] == '#') room = room.substr(1);
    json j; j["room"] = room;
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_ROOM_CREATE, j));
}

void CommandHandler::cmdMsg(const Command& cmd) {
    if (cmd.args.size() < 2) { std::cout << "Usage: /msg <nickname> <message>\n"; return; }
    std::string to = cmd.args[0];
    std::ostringstream oss;
    for (size_t i = 1; i < cmd.args.size(); i++) {
        if (i > 1) oss << " ";
        oss << cmd.args[i];
    }
    json j; j["to"] = to; j["message"] = oss.str();
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_CHAT_PRIVATE, j));
}

void CommandHandler::cmdWhois(const Command& cmd) {
    if (cmd.args.empty()) { std::cout << "Usage: /whois <nickname>\n"; return; }
    std::cout << "[whois not yet implemented in week 1]\n";
}

void CommandHandler::cmdHelp(const Command&) {
    std::cout << "\n=== VCS SecureChat Commands ===\n";
    std::cout << "  /list              - List users in current room\n";
    std::cout << "  /listall           - List all users on server\n";
    std::cout << "  /rooms             - List all rooms\n";
    std::cout << "  /join #room        - Join a room\n";
    std::cout << "  /leave             - Leave current room\n";
    std::cout << "  /create #room      - Create a new room\n";
    std::cout << "  /msg <user> <text> - Send private message\n";
    std::cout << "  /whois <user>      - Show user info\n";
    std::cout << "  /quit              - Disconnect and exit\n";
    std::cout << "  [Admin] /kick /mute /ban /promote /broadcast /shutdown\n";
    std::cout << "================================\n\n";
}

void CommandHandler::cmdKick(const Command& cmd) {
    if (cmd.args.empty()) { std::cout << "Usage: /kick <nickname> [reason]\n"; return; }
    json j;
    j["target"] = cmd.args[0];
    j["reason"] = cmd.args.size() > 1 ? cmd.args[1] : "Kicked by admin";
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_ADMIN_KICK, j));
}

void CommandHandler::cmdMute(const Command& cmd) {
    if (cmd.args.empty()) { std::cout << "Usage: /mute <nickname> [seconds]\n"; return; }
    json j;
    j["target"]   = cmd.args[0];
    j["duration"] = cmd.args.size() > 1 ? std::stoi(cmd.args[1]) : 300;
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_ADMIN_MUTE, j));
}

void CommandHandler::cmdUnmute(const Command& cmd) {
    if (cmd.args.empty()) { std::cout << "Usage: /unmute <nickname>\n"; return; }
    json j; j["target"] = cmd.args[0]; j["duration"] = 0;
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_ADMIN_MUTE, j));
}

void CommandHandler::cmdBan(const Command& cmd) {
    if (cmd.args.empty()) { std::cout << "Usage: /ban <nickname> [reason]\n"; return; }
    json j;
    j["target"] = cmd.args[0];
    j["reason"] = cmd.args.size() > 1 ? cmd.args[1] : "Banned by admin";
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_ADMIN_BAN, j));
}

void CommandHandler::cmdUnban(const Command& cmd) {
    if (cmd.args.empty()) { std::cout << "Usage: /unban <nickname>\n"; return; }
    json j; j["target"] = cmd.args[0]; j["unban"] = true;
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_ADMIN_BAN, j));
}

void CommandHandler::cmdPromote(const Command& cmd) {
    if (cmd.args.empty()) { std::cout << "Usage: /promote <nickname>\n"; return; }
    json j; j["target"] = cmd.args[0];
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_ADMIN_PROMOTE, j));
}

void CommandHandler::cmdDemote(const Command& cmd) {
    if (cmd.args.empty()) { std::cout << "Usage: /demote <nickname>\n"; return; }
    json j; j["target"] = cmd.args[0]; j["demote"] = true;
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_ADMIN_PROMOTE, j));
}

void CommandHandler::cmdBroadcast(const Command& cmd) {
    if (cmd.args.empty()) { std::cout << "Usage: /broadcast <message>\n"; return; }
    std::ostringstream oss;
    for (size_t i = 0; i < cmd.args.size(); i++) {
        if (i > 0) oss << " ";
        oss << cmd.args[i];
    }
    json j; j["message"] = oss.str(); j["room"] = m_currentRoom;
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_CHAT_SEND, j));
}

void CommandHandler::cmdShutdown(const Command& cmd) {
    json j;
    j["delay"] = cmd.args.empty() ? 0 : std::stoi(cmd.args[0]);
    m_client->sendPacket(makeJsonPacket(MessageType::MSG_DISCONNECT, j));
}
