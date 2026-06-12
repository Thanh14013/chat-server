#include "AdminCommands.h"
#include "../core/TcpServer.h"
#include "../core/ClientSession.h"
#include "../protocol/Builder.h"
#include "../security/AuditLogger.h"
#include "../utils/Logger.h"
#include "../../common/ErrorCodes.h"
#include <nlohmann/json.hpp>
#include <fstream>

using json = nlohmann::json;

AdminCommands &AdminCommands::instance()
{
    static AdminCommands inst;
    return inst;
}
void AdminCommands::initialize(TcpServer *server)
{
    m_server = server;
}

std::string AdminCommands::adminNick(int adminFd)
{
    if (!m_server)
        return "unknown";
    ClientSession *s = m_server->getSession(adminFd);
    return s ? s->nickname() : "unknown";
}

bool AdminCommands::hasAdminRight(int adminFd, bool ownerOnly)
{
    if (!m_server)
        return false;
    ClientSession *s = m_server->getSession(adminFd);
    if (!s)
        return false;
    if (ownerOnly)
        return s->role() == UserRole::OWNER;
    return s->role() == UserRole::ADMIN || s->role() == UserRole::OWNER;
}

void AdminCommands::kick(int adminFd, const std::string &targetNick, const std::string &reason)
{
    if (!hasAdminRight(adminFd))
    {
        ClientSession *admin = m_server->getSession(adminFd);
        if (admin)
            admin->sendPacket(Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "No admin rights"));
        return;
    }

    std::string anik = adminNick(adminFd);

    int targetFd = m_server->getFdByNickname(targetNick);
    ClientSession *target = m_server->getSession(targetFd);

    if (!target)
    {
        ClientSession *admin = m_server->getSession(adminFd);
        if (admin)
            admin->sendPacket(
                Builder::makeError(ErrorCode::ERR_ROOM_NOT_FOUND, "User not found"));
        return;
    }

    std::string room = target->currentRoom();
    m_server->broadcastToRoom(room,
                              Builder::makeSystemNotify(targetNick + " was kicked by " + anik + ": " + reason));

    AUDIT_D(AuditEventType::ADMIN, anik, targetNick, "KICK",
            AuditResult::SUCCESS, target->ip(), reason);

    target->disconnect("You were kicked: " + reason);
    LOG_INFO("KICK: admin=" + anik + " target=" + targetNick + " reason=" + reason);
}

void AdminCommands::mute(int adminFd, const std::string &targetNick, int durationSec)
{
    LOG_INFO("AdminCommands::mute called for target=" + targetNick + " by fd=" + std::to_string(adminFd));
    if (!hasAdminRight(adminFd))
    {
        LOG_INFO("Mute failed: fd=" + std::to_string(adminFd) + " has no admin rights");
        ClientSession *admin = m_server->getSession(adminFd);
        if (admin)
            admin->sendPacket(
                Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "No admin rights"));
        return;
    }
    std::string anik = adminNick(adminFd);
    int targetFd = m_server->getFdByNickname(targetNick);
    LOG_INFO("Mute: targetFd=" + std::to_string(targetFd) + " for " + targetNick);
    ClientSession *target = m_server->getSession(targetFd);
    if (!target) {
        LOG_INFO("Mute failed: target session is null");
        return;
    }

    time_t until = (durationSec > 0) ? std::time(nullptr) + durationSec : 0;
    target->setMuted(true, until);

    std::string msg = targetNick + " has been muted for " + std::to_string(durationSec) + " seconds by " + anik;

    m_server->broadcastToRoom(target->currentRoom(), Builder::makeSystemNotify(msg));
    AUDIT_D(AuditEventType::ADMIN, anik, targetNick, "MUTE",
            AuditResult::SUCCESS, target->ip(),
            "duration=" + std::to_string(durationSec));
    LOG_INFO("MUTE: admin=" + anik + " target=" + targetNick);
}

void AdminCommands::unmute(int adminFd, const std::string &targetNick)
{
    if (!hasAdminRight(adminFd))
        return;

    int targetFd = m_server->getFdByNickname(targetNick);
    ClientSession *s = m_server->getSession(targetFd);
    s->setMuted(false, 0);
    s->sendPacket(Builder::makeSystemNotify("You have been unmuted."));
    AUDIT(AuditEventType::ADMIN, adminNick(adminFd), targetNick,
          "UNMUTE", AuditResult::SUCCESS);
    return;
}

void AdminCommands::ban(int adminFd, const std::string &targetNick, const std::string &reason)
{
    if (!hasAdminRight(adminFd))
    {
        ClientSession *admin = m_server->getSession(adminFd);
        if (admin)
            admin->sendPacket(
                Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "No admin rights"));
        return;
    }

    std::string anik = adminNick(adminFd);
    int targetFd = m_server->getFdByNickname(targetNick);
    ClientSession *target = m_server->getSession(targetFd);
    if (!target)
        return;

    std::string ip = target->ip();
    persistBan(ip, reason);
    AUDIT_D(AuditEventType::ADMIN, anik, targetNick, "BAN", AuditResult::SUCCESS, ip, reason);
    m_server->broadcastToRoom(target->currentRoom(), Builder::makeSystemNotify(targetNick + " has been banned by " + anik));

    target->disconnect("You have been banned: " + reason);
    LOG_INFO("BAN: admin=" + anik + " target=" + targetNick + " ip=" + ip);
}

void AdminCommands::unban(int adminFd, const std::string &ipOrNick)
{
    if (!hasAdminRight(adminFd))
        return;
    removeBan(ipOrNick);
    AUDIT(AuditEventType::ADMIN, adminNick(adminFd), ipOrNick,
          "UNBAN", AuditResult::SUCCESS);
    LOG_INFO("UNBAN: " + ipOrNick);
}

void AdminCommands::promote(int adminFd, const std::string &targetNick)
{
    if (!hasAdminRight(adminFd, true))
    {
        ClientSession *admin = m_server->getSession(adminFd);
        if (admin)
            admin->sendPacket(
                Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "Only OWNER can promote"));
        return;
    }

    std::string anik = adminNick(adminFd);
    int targetFd = m_server->getFdByNickname(targetNick);
    ClientSession *target = m_server->getSession(targetFd);
    if (!target)
        return;

    target->setRole(UserRole::ADMIN);
    target->sendPacket(Builder::makeSystemNotify("You have been promoted to ADMIN."));
    AUDIT(AuditEventType::ADMIN, adminNick(adminFd), targetNick,
          "PROMOTE", AuditResult::SUCCESS);
    LOG_INFO("PROMOTE: " + targetNick + " -> ADMIN");
    return;
}

void AdminCommands::demote(int adminFd, const std::string &targetNick)
{
    if (!hasAdminRight(adminFd, true))
        return;
    std::string anik = adminNick(adminFd);
    int targetFd = m_server->getFdByNickname(targetNick);
    ClientSession *target = m_server->getSession(targetFd);
    if (!target)
        return;
    target->setRole(UserRole::USER);
    target->sendPacket(Builder::makeSystemNotify("Your admin role has been revoked."));
    AUDIT(AuditEventType::ADMIN, adminNick(adminFd), targetNick,
          "DEMOTE", AuditResult::SUCCESS);
    return;
}

void AdminCommands::broadcast(int adminFd, const std::string& message) {
    if (!hasAdminRight(adminFd)) {
        ClientSession* admin = m_server->getSession(adminFd);
        if (admin) admin->sendPacket(
            Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "No admin rights"));
        return;
    }

    std::string anik = adminNick(adminFd);
    std::string full = "[BROADCAST] " + message;
    m_server->broadcastToAll(Builder::makeSystemNotify(full));

    AUDIT_D(AuditEventType::ADMIN, anik, "", "BROADCAST",
            AuditResult::SUCCESS, "", message.substr(0, 128));
    LOG_INFO("BROADCAST by " + anik + ": " + message);
}

void AdminCommands::persistBan(const std::string& ip, const std::string& reason) {
    json banList = json::array();
    std::ifstream ifs("ban_list.json");
    if (ifs.is_open()) {
        try { ifs >> banList; } catch (...) {}
    }

    json entry;
    entry["ip"]     = ip;
    entry["reason"] = reason;
    entry["ts"]     = (long long)std::time(nullptr);
    banList.push_back(entry);

    std::ofstream ofs("ban_list.json");
    ofs << banList.dump(2);
}

void AdminCommands::removeBan(const std::string& ipOrNick) {
    std::ifstream ifs("ban_list.json");
    if (!ifs.is_open()) return;

    json banList;
    try { ifs >> banList; } catch (...) { return; }
    ifs.close();

    json updated = json::array();
    for (auto& entry : banList) {
        std::string ip = entry.value("ip", "");
        if (ip != ipOrNick) updated.push_back(entry);
    }

    std::ofstream ofs("ban_list.json");
    ofs << updated.dump(2);
}