#pragma once
#include <string>

class TcpServer;

class AdminCommands
{
public:
    static AdminCommands &instance();

    void initialize(TcpServer *server);

    void kick(int adminFd, const std::string &targetNick, const std::string &reason);
    void mute(int adminFd, const std::string &targetNick, int durationSec);
    void unmute(int adminFd, const std::string &targetNick);
    void ban(int adminFd, const std::string &targetNick, const std::string &reason);
    void unban(int adminFd, const std::string &ipOrNick);
    void promote(int adminFd, const std::string &targetNick);
    void demote(int adminFd, const std::string &targetNick);
    void broadcast(int adminFd, const std::string &message);

private:
    AdminCommands() : m_server(nullptr) {};
    bool hasAdminRight(int adminFd, bool ownerOnly = false);
    std::string adminNick(int adminFd);
    void persistBan(const std::string &ip, const std::string &reason);
    void removeBan(const std::string &ipOrNick);

    TcpServer *m_server;
};