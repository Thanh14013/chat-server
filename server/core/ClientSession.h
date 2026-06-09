#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <ctime>
#include <cstdint>
#include "../../common/Protocol.h"
#include "../protocol/Packet.h"
#include <vector>

enum class UserRole
{
    USER,
    ADMIN,
    OWNER
};

class TcpServer;

class ClientSession
{
public:
    ClientSession(int fd, const std::string &ip, TcpServer *server);
    ~ClientSession();

    void start();
    void stop();

    void appendAndParseBytes(const uint8_t* data, size_t len);

    bool sendPacket(const Packet &pkt);
    void disconnect(const std::string &reason = "");

    bool isTimedOut() const;
    bool isAuthenticated() const { return m_authenticated; }
    bool isMuted() const;

    int fd() const { return m_fd; }
    const std::string &nickname() const { return m_nickname; }
    const std::string &ip() const { return m_ip; }
    const std::string &currentRoom() const { return m_room; }
    UserRole role() const { return m_role; }
    time_t connectTime() const { return m_connectTime; }
    time_t lastActive() const { return m_lastActive; }
    uint32_t msgCount() const { return m_msgCount; }

    void setNickname(const std::string& n)  { m_nickname = n; }
    void setRoom(const std::string& r)      { m_room = r; }
    void setAuthenticated(bool v)           { m_authenticated = v; }
    void setRole(UserRole r)                { m_role = r; }
    void setMuted(bool v, time_t until = 0) { m_muted = v; m_muteUntil = until; }
    void setLastActive(time_t t)            { m_lastActive = t; }
    void incrementMsgCount()               { m_msgCount++; }

    bool m_pongReceived { true };

private:
    std::vector<uint8_t> m_readBuffer;    

    int m_fd;
    std::string m_ip;
    std::string m_nickname;
    std::string m_room;
    bool m_authenticated;
    bool m_muted;
    time_t m_muteUntil;
    UserRole m_role;
    time_t m_connectTime;
    time_t m_lastActive;
    uint32_t m_msgCount;
    std::atomic<bool> m_running;

    std::mutex m_sendMutex;
    TcpServer *m_server;
};