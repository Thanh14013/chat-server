#include "AdminCommands.h"
#include "../core/TcpServer.h"
#include "../core/ClientSession.h"
#include "../protocol/Builder.h"
#include "../security/AuditLogger.h"
#include "../utils/Logger.h"
#include "../../common/ErrorCodes.h"
#include "../security/IntrusionDetector.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include "../utils/Config.h"

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
    auto s = m_server->getSession(adminFd);
    return s ? s->nickname() : "unknown";
}

bool AdminCommands::hasAdminRight(int adminFd, bool ownerOnly)
{
    if (!m_server)
        return false;
    auto s = m_server->getSession(adminFd);
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
        auto admin = m_server->getSession(adminFd);
        if (admin)
            admin->sendPacket(Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "You do not have admin privileges"));
        return;
    }

    std::string anik = adminNick(adminFd);

    int targetFd = m_server->getFdByNickname(targetNick);
    auto target = m_server->getSession(targetFd);

    if (!target)
    {
        auto admin = m_server->getSession(adminFd);
        if (admin)
            admin->sendPacket(
                Builder::makeError(ErrorCode::ERR_ROOM_NOT_FOUND, "Không tìm thấy user này trong hệ thống"));
        return;
    }

    std::string room = target->currentRoom();
    if (room == Config::instance().get().default_room) {
        // Do not kick if already in #general
        return;
    }

    std::string actualReason = reason.empty() ? "No reason provided" : reason;
    m_server->broadcastToRoom(room,
                              Builder::makeSystemNotify(targetNick + " was kicked by " + anik + (reason.empty() ? "" : ": " + reason)));

    AUDIT_D(AuditEventType::ADMIN, anik, targetNick, "KICK",
            AuditResult::SUCCESS, target->ip(), actualReason);

    m_server->kickFromRoom(targetFd, anik, actualReason);
    LOG_INFO("KICK: admin=" + anik + " target=" + targetNick + " reason=" + actualReason);
}

void AdminCommands::unkick(int adminFd, const std::string& targetNick, const std::string& room) {
    if (!hasAdminRight(adminFd)) {
        auto admin = m_server->getSession(adminFd);
        if (admin) admin->sendPacket(Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "You do not have admin privileges"));
        return;
    }

    std::string anik = adminNick(adminFd);
    m_server->unkickFromRoom(targetNick, anik, room);
    
    auto admin = m_server->getSession(adminFd);
    if (admin) admin->sendPacket(Builder::makeSystemNotify(targetNick + " was unkicked from #" + room));

    int targetFd = m_server->getFdByNickname(targetNick);
    auto target = m_server->getSession(targetFd);
    if (target) target->sendPacket(Builder::makeSystemNotify("You can now rejoin room #" + room));
    
    AUDIT(AuditEventType::ADMIN, anik, targetNick, "UNKICK", AuditResult::SUCCESS);
    LOG_INFO("UNKICK: admin=" + anik + " target=" + targetNick + " room=" + room);
}

void AdminCommands::mute(int adminFd, const std::string &targetNick, int durationSec)
{
    LOG_INFO("AdminCommands::mute called for target=" + targetNick + " by fd=" + std::to_string(adminFd));
    if (!hasAdminRight(adminFd))
    {
        LOG_INFO("Mute failed: fd=" + std::to_string(adminFd) + " has no admin rights");
        auto admin = m_server->getSession(adminFd);
        if (admin)
            admin->sendPacket(
                Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "You do not have admin privileges"));
        return;
    }
    std::string anik = adminNick(adminFd);
    int targetFd = m_server->getFdByNickname(targetNick);
    LOG_INFO("Mute: targetFd=" + std::to_string(targetFd) + " for " + targetNick);
    auto target = m_server->getSession(targetFd);
    time_t until = (durationSec > 0) ? std::time(nullptr) + durationSec : 0;
    
    // Save to DB (target may be offline)
    m_server->getAuthManager()->updateMuteStateDb(targetNick, true, until);

    if (target) {
        target->setMuted(true, until);
    }

    std::string msgForOthers = targetNick + " has been muted by " + anik + (durationSec > 0 ? " for " + std::to_string(durationSec) + "s" : " permanently");
    std::string msgForTarget = "You have been muted by " + anik + (durationSec > 0 ? " for " + std::to_string(durationSec) + "s" : " permanently");

    if (target) {
        target->sendPacket(Builder::makeSystemNotify(msgForTarget));
        m_server->broadcastToRoom(target->currentRoom(), Builder::makeSystemNotify(msgForOthers), targetFd);
    }
    
    auto admin = m_server->getSession(adminFd);
    if (admin) {
        admin->sendPacket(Builder::makeSystemNotify("You have muted " + targetNick + (durationSec > 0 ? " for " + std::to_string(durationSec) + "s" : " permanently")));
    }
    
    AUDIT_D(AuditEventType::ADMIN, anik, targetNick, "MUTE",
            AuditResult::SUCCESS, target ? target->ip() : "",
            "duration=" + std::to_string(durationSec));
    LOG_INFO("MUTE: admin=" + anik + " target=" + targetNick);
}

void AdminCommands::unmute(int adminFd, const std::string &targetNick)
{
    if (!hasAdminRight(adminFd))
        return;

    std::string anik = adminNick(adminFd);
    int targetFd = m_server->getFdByNickname(targetNick);
    auto s = m_server->getSession(targetFd);
    
    m_server->getAuthManager()->updateMuteStateDb(targetNick, false, 0);

    if (s) {
        s->setMuted(false, 0);
        s->sendPacket(Builder::makeSystemNotify("You have been unmuted."));
        m_server->broadcastToRoom(s->currentRoom(), Builder::makeSystemNotify(targetNick + " has been unmuted"), targetFd);
    }
    
    auto admin = m_server->getSession(adminFd);
    if (admin) {
        admin->sendPacket(Builder::makeSystemNotify("You have unmuted " + targetNick));
    }
    
    AUDIT_D(AuditEventType::ADMIN, anik, targetNick, "UNMUTE",
            AuditResult::SUCCESS, s ? s->ip() : "", "");
    LOG_INFO("UNMUTE: admin=" + anik + " target=" + targetNick);
}

void AdminCommands::ban(int adminFd, const std::string &targetNick, const std::string &reason)
{
    if (!hasAdminRight(adminFd))
    {
        auto admin = m_server->getSession(adminFd);
        if (admin)
            admin->sendPacket(
                Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "You do not have admin privileges"));
        return;
    }

    std::string anik = adminNick(adminFd);
    int targetFd = m_server->getFdByNickname(targetNick);
    auto target = m_server->getSession(targetFd);
    if (!target)
        return;

    std::string ip = target->ip();
    IntrusionDetector::instance().permBan(ip, reason);
    IntrusionDetector::instance().permBanNick(targetNick, reason);
    AUDIT_D(AuditEventType::ADMIN, anik, targetNick, "BAN", AuditResult::SUCCESS, ip, reason);
    m_server->broadcastToRoom(target->currentRoom(), Builder::makeSystemNotify(targetNick + " has been banned by " + anik));

    target->disconnect("You have been banned: " + reason);
    LOG_INFO("BAN: admin=" + anik + " target=" + targetNick + " ip=" + ip);
}

void AdminCommands::unban(int adminFd, const std::string &ipOrNick)
{
    if (!hasAdminRight(adminFd))
        return;
    IntrusionDetector::instance().unban(ipOrNick);
    IntrusionDetector::instance().unbanNick(ipOrNick);
    AUDIT(AuditEventType::ADMIN, adminNick(adminFd), ipOrNick,
          "UNBAN", AuditResult::SUCCESS);
    LOG_INFO("UNBAN: " + ipOrNick);
}

void AdminCommands::promote(int adminFd, const std::string &targetNick)
{
    if (!hasAdminRight(adminFd, true))
    {
        auto admin = m_server->getSession(adminFd);
        if (admin)
            admin->sendPacket(
                Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "Chỉ OWNER mới có quyền thăng cấp (promote)"));
        return;
    }

    std::string anik = adminNick(adminFd);
    int targetFd = m_server->getFdByNickname(targetNick);
    auto target = m_server->getSession(targetFd);
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
    auto target = m_server->getSession(targetFd);
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
        auto admin = m_server->getSession(adminFd);
        if (admin) admin->sendPacket(
            Builder::makeError(ErrorCode::ERR_PERMISSION_DENIED, "You do not have admin privileges"));
        return;
    }

    std::string anik = adminNick(adminFd);
    std::string full = "[BROADCAST] " + message;
    m_server->broadcastToAll(Builder::makeSystemNotify(full));

    AUDIT_D(AuditEventType::ADMIN, anik, "", "BROADCAST",
            AuditResult::SUCCESS, "", message.substr(0, 128));
    LOG_INFO("BROADCAST by " + anik + ": " + message);
}
