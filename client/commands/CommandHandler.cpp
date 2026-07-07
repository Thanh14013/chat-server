#include "CommandHandler.h"
#include "../core/TcpClient.h"
#include "../core/ConnectionManager.h"
#include "../security/ClientCrypto.h"
#include "../../common/MessageTypes.h"
#include "../../crypto/sha256.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

extern ConnectionManager* g_mgr;

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
    case CommandType::CMD_DELETE_ROOM:
        handleDeleteRoom(cmd);
        break;
    case CommandType::CMD_ROOMS_ADMIN:
        handleRoomsAdmin(cmd);
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
    case CommandType::CMD_UNKICK:
    case CommandType::CMD_MUTE:
    case CommandType::CMD_UNMUTE:
    case CommandType::CMD_BAN:
    case CommandType::CMD_UNBAN:
    case CommandType::CMD_PROMOTE:
    case CommandType::CMD_DEMOTE:
    case CommandType::CMD_BROADCAST:
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


void CommandHandler::handleRooms(const Command &cmd)
{
    m_client->sendPacket(Packet(MessageType::MSG_ROOM_LIST_REQUEST, {}));
}

void CommandHandler::handleJoin(const Command &cmd)
{
    if (cmd.args.empty()) {
        std::cout << "[SYSTEM] Usage: /join <room_name> [password]" << std::endl;
        return;
    }
    json j;
    j["room"] = cmd.args[0];
    if (cmd.args.size() > 1) j["password"] = cmd.args[1];
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
    if (cmd.args.empty()) {
        std::cout << "[SYSTEM] Usage: /create <room_name> [password]" << std::endl;
        return;
    }
    json j;
    j["room"] = cmd.args[0];
    if (cmd.args.size() > 1) j["password"] = cmd.args[1];
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client->sendPacket(Packet(MessageType::MSG_ROOM_CREATE, payload));
}

void CommandHandler::handleDeleteRoom(const Command &cmd)
{
    if (cmd.args.empty()) {
        std::cout << "[SYSTEM] Usage: /delete <room_name>" << std::endl;
        return;
    }
    json j;
    j["room"] = cmd.args[0];
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client->sendPacket(Packet(MessageType::MSG_ROOM_DELETE, payload));
}

void CommandHandler::handleRoomsAdmin(const Command &cmd)
{
    m_client->sendPacket(Packet(MessageType::MSG_ADMIN_ROOM_INFO_REQUEST, {}));
}

void CommandHandler::handleMsg(const Command &cmd)
{
    if (cmd.args.size() < 2) {
        std::cout << "[SYSTEM] Usage: /msg <username> <message>" << std::endl;
        return;
    }
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
    if (cmd.args.size() < 2) {
        std::cout << "[SYSTEM] Usage: /send <username> <filepath>" << std::endl;
        return;
    }
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

    if (g_mgr) {
        g_mgr->registerUpload(filename, filepath);
    }

    std::cout << "[SYSTEM] File transfer request sent to " << target << std::endl;
}

void CommandHandler::handleAccept(const Command& cmd) {
    std::string tid;
    if (cmd.args.empty()) {
        tid = g_mgr ? g_mgr->getLastIncomingTransferId() : "";
        if (tid.empty()) {
            std::cout << "[SYSTEM] No pending transfer to accept." << std::endl;
            return;
        }
    } else {
        tid = cmd.args[0];
    }
    json j;
    j["transfer_id"] = tid;
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client->sendPacket(Packet(MessageType::MSG_FILE_ACCEPT, payload));
    std::string fname = g_mgr ? g_mgr->getIncomingFileName(tid) : "";
    if (!fname.empty()) {
        std::cout << "[SYSTEM] Accepted transfer for file " << fname << ". Waiting for file..." << std::endl;
    } else {
        std::cout << "[SYSTEM] Accepted transfer. Waiting for file..." << std::endl;
    }
}

void CommandHandler::handleReject(const Command& cmd) {
    std::string tid;
    if (cmd.args.empty()) {
        tid = g_mgr ? g_mgr->getLastIncomingTransferId() : "";
        if (tid.empty()) {
            std::cout << "[SYSTEM] No pending transfer to reject." << std::endl;
            return;
        }
    } else {
        tid = cmd.args[0];
    }
    json j;
    j["transfer_id"] = tid;
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client->sendPacket(Packet(MessageType::MSG_FILE_REJECT, payload));
    std::string fname = g_mgr ? g_mgr->getIncomingFileName(tid) : "";
    if (!fname.empty()) {
        std::cout << "[SYSTEM] Rejected transfer for file " << fname << "." << std::endl;
    } else {
        std::cout << "[SYSTEM] Rejected transfer." << std::endl;
    }
}

void CommandHandler::handleWhois(const Command &cmd)
{
    if (cmd.args.empty()) {
        std::cout << "[SYSTEM] Usage: /whois <username>" << std::endl;
        return;
    }
    json j;
    j["target"] = cmd.args[0];
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client->sendPacket(Packet(MessageType::MSG_WHOIS_REQUEST, payload));
}

void CommandHandler::handleHelp(const Command &cmd)
{
    std::cout << "\n--- VCS SecureChat Commands ---\n"
              << "[Client Commands]\n"
              << " /join <room_name> [password]  : Join a chat room\n"
              << " /leave                        : Leave the current chat room\n"
              << " /create <room_name> [pass]    : Create a new chat room\n"
              << " /delete <room_name>           : Delete a room (Creator/Admin/Owner)\n"
              << " /list                         : List all users in the current room\n"
              << " /rooms                        : List all active public rooms\n"
              << " /msg <username> <message>     : Send a private message\n"
              << " /send <username> <filepath>   : Send a file securely\n"
              << " /accept <filename>            : Accept an incoming file transfer\n"
              << " /reject <filename>            : Reject an incoming file transfer\n"
              << " /whois <username>             : Request public profile info\n"
              << " /help                         : Display this help menu\n"
              << " /quit                         : Disconnect and exit\n";

    if (m_client->isAdmin()) {
        std::cout << "\n[Admin Commands]\n"
                  << " /kick <username> [reason]     : Kick a user from current room\n"
                  << " /unkick <username> <room>     : Remove user from room's kick list\n"
                  << " /mute <username> [seconds]    : Prevent a user from sending messages\n"
                  << " /unmute <username>            : Remove a mute restriction\n"
                  << " /ban <username> [reason]      : Permanently ban a user\n"
                  << " /unban <username>             : Remove a ban from a user\n"
                  << " /broadcast <message>          : Send a global system message\n"
                  << " /rooms_admin                  : View detailed info of all rooms\n";
    }
    
    std::cout << "-------------------------------\n" << std::endl;
}

void CommandHandler::handleAdminCommand(const Command &cmd)
{
    json j;
    MessageType type = MessageType::MSG_PING;

    if (cmd.type == CommandType::CMD_KICK)
    {
        if (cmd.args.empty()) {
            std::cout << "[SYSTEM] Usage: /kick <username> [reason]" << std::endl;
            return;
        }
        type = MessageType::MSG_ADMIN_KICK;
        j["target"] = cmd.args[0];
        if (cmd.args.size() > 1)
            j["reason"] = cmd.args[1];
        else
            j["reason"] = "";
    }
    else if (cmd.type == CommandType::CMD_UNKICK)
    {
        if (cmd.args.size() < 2) {
            std::cout << "[SYSTEM] Usage: /unkick <user> <room>" << std::endl;
            return;
        }
        type = MessageType::MSG_ADMIN_UNKICK;
        j["target"] = cmd.args[0];
        j["room"] = cmd.args[1];
    }
    else if (cmd.type == CommandType::CMD_MUTE)
    {
        if (cmd.args.empty()) {
            std::cout << "[SYSTEM] Usage: /mute <username> [seconds]" << std::endl;
            return;
        }
        type = MessageType::MSG_ADMIN_MUTE;
        j["target"] = cmd.args[0];
        if (cmd.args.size() > 1)
            j["duration"] = std::stoi(cmd.args[1]);
        else
            j["duration"] = -1;
    }
    else if (cmd.type == CommandType::CMD_UNMUTE)
    {
        if (cmd.args.empty()) {
            std::cout << "[SYSTEM] Usage: /unmute <username>" << std::endl;
            return;
        }
        type = MessageType::MSG_ADMIN_MUTE;
        j["target"] = cmd.args[0];
        j["duration"] = 0;
    }
    else if (cmd.type == CommandType::CMD_BAN)
    {
        if (cmd.args.empty()) {
            std::cout << "[SYSTEM] Usage: /ban <username> [reason]" << std::endl;
            return;
        }
        type = MessageType::MSG_ADMIN_BAN;
        j["target"] = cmd.args[0];
        if (cmd.args.size() > 1)
            j["reason"] = cmd.args[1];
    }
    else if (cmd.type == CommandType::CMD_UNBAN)
    {
        if (cmd.args.empty()) {
            std::cout << "[SYSTEM] Usage: /unban <username>" << std::endl;
            return;
        }
        type = MessageType::MSG_ADMIN_BAN;
        j["target"] = cmd.args[0];
        j["unban"] = true;
    }
    else if (cmd.type == CommandType::CMD_PROMOTE)
    {
        if (cmd.args.empty()) {
            std::cout << "[SYSTEM] Usage: /promote <username>" << std::endl;
            return;
        }
        type = MessageType::MSG_ADMIN_PROMOTE;
        j["target"] = cmd.args[0];
    }
    else if (cmd.type == CommandType::CMD_DEMOTE)
    {
        if (cmd.args.empty()) {
            std::cout << "[SYSTEM] Usage: /demote <username>" << std::endl;
            return;
        }
        type = MessageType::MSG_ADMIN_PROMOTE;
        j["target"] = cmd.args[0];
        j["demote"] = true;
    }
    else if (cmd.type == CommandType::CMD_BROADCAST)
    {
        if (cmd.args.empty()) {
            std::cout << "[SYSTEM] Usage: /broadcast <message>" << std::endl;
            return;
        }
        type = MessageType::MSG_ADMIN_BROADCAST;
        std::string text = "";
        for (size_t i = 0; i < cmd.args.size(); i++)
        {
            text += cmd.args[i] + (i == cmd.args.size() - 1 ? "" : " ");
        }
        j["message"] = text;
    }
    else
    {
        return;
    }

    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());

    m_client->sendPacket(Packet(type, payload));
}