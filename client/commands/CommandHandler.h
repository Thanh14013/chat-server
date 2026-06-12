#pragma once
#include "CommandParser.h"
#include <string>
#include <memory>

class TcpClient;

class CommandHandler
{
public:
    explicit CommandHandler(TcpClient *client);
    ~CommandHandler() = default;

    void handleCommand(const Command &cmd);

private:
    TcpClient *m_client;

    void handleQuit(const Command &cmd);
    void handleList(const Command &cmd);
    void handleListAll(const Command &cmd);
    void handleRooms(const Command &cmd);
    void handleJoin(const Command &cmd);
    void handleLeave(const Command &cmd);
    void handleCreate(const Command &cmd);
    void handleMsg(const Command &cmd);
    void handleSend(const Command &cmd);
    void handleWhois(const Command &cmd);
    void handleHelp(const Command &cmd);
    void handleAccept(const Command& cmd);
    void handleReject(const Command& cmd);

    // Admin commands
    void handleAdminCommand(const Command &cmd);
};