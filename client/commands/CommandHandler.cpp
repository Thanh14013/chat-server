#include "CommandHandler.h"
#include "../core/TcpClient.h"
#include "../security/ClientCrypto.h"
#include "../../common/MessageTypes.h"
#include "../../crypto/sha256.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

CommandHandler::CommandHandler(TcpClient *client) : m_client(client) {};
void CommandHandler::handleCommand(const Command &cmd)
{
    if (!m_client || !m_client->isReady())
    {
        std::cout << "[SYSTEM] Not connected to server!" << std::endl;
        return;
    }
    switch (cmd.type)
    {
    case CommandType::CMD_QUIT:
        handleQuit(cmd);
        break;
    case CommandType::CMD_LIST:
        handleList(cmd);
        break;
    case CommandType::CMD_LISTALL:
        handleListAll(cmd);
        break;
    case CommandType::CMD_ROOMS:
        handleRooms(cmd);
        break;
    case CommandType::CMD_JOIN:
        handleJoin(cmd);
        break;
    case CommandType::CMD_LEAVE:
        handleLeave(cmd);
        break;
    case CommandType::CMD_CREATE:
        handleCreate(cmd);
        break;
    case CommandType::CMD_MSG:
        handleMsg(cmd);
        break;
    case CommandType::CMD_SEND:
        handleSend(cmd);
        break;
    case CommandType::CMD_WHOIS:
        handleWhois(cmd);
        break;
    case CommandType::CMD_HELP:
        handleHelp(cmd);
        break;
    case CommandType::CMD_ACCEPT:
        handleAccept(cmd);
        break;
    case CommandType::CMD_REJECT:
        handleReject(cmd);
        break;
    case CommandType::CMD_KICK:
    case CommandType::CMD_MUTE:
    case CommandType::CMD_UNMUTE:
    case CommandType::CMD_BAN:
    case CommandType::CMD_UNBAN:
    case CommandType::CMD_PROMOTE:
    case CommandType::CMD_DEMOTE:
    case CommandType::CMD_BROADCAST:
    case CommandType::CMD_SHUTDOWN:
        handleAdminCommand(cmd);
        break;
    default:
        std::cout << "[SYSTEM] Unknown or invalid command." << std::endl;
        break;
    }
}

void CommandHandler::handleQuit(const Command &cmd)
{
    std::cout << "Disconnecting from server..." << std::endl;
    m_client->disconnect();
}

void CommandHandler::handleList(const Command &cmd)
{
    m_client->sendPacket(Packet(MessageType::MSG_USER_LIST_REQUEST, {}));
}

void CommandHandler::handleListAll(const Command &cmd)
{
    m_client->sendPacket(Packet(MessageType::MSG_ROOM_LIST_REQUEST, {}));
}

void CommandHandler::handleRooms(const Command &cmd)
{
    m_client->sendPacket(Packet(MessageType::MSG_ROOM_LIST_REQUEST, {}));
}

void CommandHandler::handleJoin(const Command &cmd)
{
    if (cmd.args.empty())
        return;
    json j;
    j["room"] = cmd.args[0];
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client->sendPacket(Packet(MessageType::MSG_ROOM_JOIN, payload));
}

void CommandHandler::handleLeave(const Command &cmd)
{
    m_client->sendPacket(Packet(MessageType::MSG_ROOM_LEAVE, {}));
}

void CommandHandler::handleCreate(const Command &cmd)
{
    if (cmd.args.empty())
        return;
    json j;
    j["room"] = cmd.args[0];
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client->sendPacket(Packet(MessageType::MSG_ROOM_CREATE, payload));
}

void CommandHandler::handleMsg(const Command &cmd)
{
    if (cmd.args.size() < 2)
        return;
    std::string target = cmd.args[0];
    std::string text = "";
    for (size_t i = 1; i < cmd.args.size(); i++)
    {
        text += cmd.args[i] + (i == cmd.args.size() - 1 ? "" : " ");
    }

    json j;
    j["to"] = target;
    j["message"] = text;
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client->sendPacket(Packet(MessageType::MSG_CHAT_PRIVATE, payload));
}

void CommandHandler::handleSend(const Command &cmd)
{
    if (cmd.args.size() < 2)
        return;
    std::string target = cmd.args[0];
    std::string filepath = cmd.args[1];

    std::ifstream ifs(filepath, std::ios::binary);
    if (!ifs.is_open())
    {
        std::cout << "[SYSTEM] Cannot open file: " << filepath << std::endl;
        return;
    }

    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    std::string filename = std::filesystem::path(filepath).filename().string();
    uint64_t fileSize = content.size();

    std::string hash = vcs::crypto::SHA256Hash::hash(content);
    json j;
    j["to"] = target;
    j["filename"] = filename;
    j["size"] = fileSize;
    j["sha256"] = hash;
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client->sendPacket(Packet(MessageType::MSG_FILE_REQUEST, payload));

    std::cout << "[SYSTEM] File transfer request sent to " << target << std::endl;
}

void CommandHandler::handleAccept(const Command& cmd) {
    if (cmd.args.empty()) return;
    json j;
    j["transfer_id"] = cmd.args[0];
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client->sendPacket(Packet(MessageType::MSG_FILE_ACCEPT, payload));
}

void CommandHandler::handleReject(const Command& cmd) {
    if (cmd.args.empty()) return;
    json j;
    j["transfer_id"] = cmd.args[0];
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client->sendPacket(Packet(MessageType::MSG_FILE_REJECT, payload));
}

void CommandHandler::handleWhois(const Command &cmd)
{
    if (cmd.args.empty())
        return;
    json j;
    j["target"] = cmd.args[0];
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client->sendPacket(Packet(MessageType::MSG_WHOIS_REQUEST, payload));
}

void CommandHandler::handleHelp(const Command &cmd)
{
    std::cout << "Available commands:\n"
              << " /quit, /list, /rooms, /join <room>, /msg <user> <text>, /send <user> <file>\n"
              << " /help [command] for more details." << std::endl;
}

void CommandHandler::handleAdminCommand(const Command &cmd)
{
    json j;
    MessageType type = MessageType::MSG_PING;

    if (cmd.type == CommandType::CMD_KICK)
    {
        if (cmd.args.empty())
            return;
        type = MessageType::MSG_ADMIN_KICK;
        j["target"] = cmd.args[0];
        if (cmd.args.size() > 1)
            j["reason"] = cmd.args[1];
    }
    else if (cmd.type == CommandType::CMD_MUTE)
    {
        if (cmd.args.empty())
            return;
        type = MessageType::MSG_ADMIN_MUTE;
        j["target"] = cmd.args[0];
        if (cmd.args.size() > 1)
            j["duration"] = std::stoi(cmd.args[1]);
    }
    else if (cmd.type == CommandType::CMD_UNMUTE)
    {
        if (cmd.args.empty())
            return;
        type = MessageType::MSG_ADMIN_MUTE;
        j["target"] = cmd.args[0];
        j["duration"] = 0;
    }
    else if (cmd.type == CommandType::CMD_BAN)
    {
        if (cmd.args.empty())
            return;
        type = MessageType::MSG_ADMIN_BAN;
        j["target"] = cmd.args[0];
        if (cmd.args.size() > 1)
            j["reason"] = cmd.args[1];
    }
    else if (cmd.type == CommandType::CMD_UNBAN)
    {
        if (cmd.args.empty())
            return;
        type = MessageType::MSG_ADMIN_BAN;
        j["target"] = cmd.args[0];
        j["unban"] = true;
    }
    else if (cmd.type == CommandType::CMD_PROMOTE)
    {
        if (cmd.args.empty())
            return;
        type = MessageType::MSG_ADMIN_PROMOTE;
        j["target"] = cmd.args[0];
    }
    else if (cmd.type == CommandType::CMD_DEMOTE)
    {
        if (cmd.args.empty())
            return;
        type = MessageType::MSG_ADMIN_PROMOTE;
        j["target"] = cmd.args[0];
        j["demote"] = true;
    }
    else
    {
        return;
    }

    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());

    m_client->sendPacket(Packet(type, payload));
}