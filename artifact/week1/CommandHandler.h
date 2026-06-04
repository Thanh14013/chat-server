#pragma once
#include "CommandParser.h"

class TcpClient;

class CommandHandler {
public:
    explicit CommandHandler(TcpClient* client);

    bool handle(const Command& cmd);
    void setCurrentRoom(const std::string& room) { m_currentRoom = room; }

private:
    void cmdQuit();
    void cmdList();
    void cmdListAll();
    void cmdRooms();
    void cmdJoin(const Command& cmd);
    void cmdLeave();
    void cmdCreate(const Command& cmd);
    void cmdMsg(const Command& cmd);
    void cmdWhois(const Command& cmd);
    void cmdHelp(const Command& cmd);
    void cmdKick(const Command& cmd);
    void cmdMute(const Command& cmd);
    void cmdUnmute(const Command& cmd);
    void cmdBan(const Command& cmd);
    void cmdUnban(const Command& cmd);
    void cmdPromote(const Command& cmd);
    void cmdDemote(const Command& cmd);
    void cmdBroadcast(const Command& cmd);
    void cmdShutdown(const Command& cmd);

    TcpClient*  m_client;
    std::string m_currentRoom;
};
