#pragma once
#include <string>
#include <vector>

enum class CommandType {
    CMD_UNKNOWN,
    CMD_QUIT,
    CMD_LIST,
    CMD_LIST_ALL,
    CMD_ROOMS,
    CMD_JOIN,
    CMD_LEAVE,
    CMD_CREATE,
    CMD_MSG,
    CMD_SEND,
    CMD_WHOIS,
    CMD_HELP,
    CMD_KICK,
    CMD_MUTE,
    CMD_UNMUTE,
    CMD_BAN,
    CMD_UNBAN,
    CMD_PROMOTE,
    CMD_DEMOTE,
    CMD_BROADCAST,
    CMD_SHUTDOWN
};

struct Command {
    CommandType          type;
    std::vector<std::string> args;
    std::string          raw;
};

namespace CommandParser {
    bool    isCommand(const std::string& input);
    Command parse(const std::string& input);
}
