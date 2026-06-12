#pragma once
#include <string>
#include <vector>

enum class CommandType{
    // General
    CMD_QUIT,
    CMD_LIST,
    CMD_LISTALL,
    CMD_ROOMS,
    CMD_JOIN,
    CMD_LEAVE,
    CMD_CREATE,
    CMD_MSG,
    CMD_SEND,
    CMD_WHOIS,
    CMD_HELP,
    CMD_ACCEPT,
    CMD_REJECT,
    // Admin
    CMD_KICK,
    CMD_MUTE,
    CMD_UNMUTE,
    CMD_BAN,
    CMD_UNBAN,
    CMD_PROMOTE,
    CMD_DEMOTE,
    CMD_BROADCAST,
    CMD_SHUTDOWN,

    // Unknown or regular text
    CMD_UNKNOWN,
    CMD_TEXT
};

enum class CommandValidationResult {
    VALID,
    INVALID,
    REQUIRES_ADMIN
};

struct Command {
    CommandType type;
    std::vector<std::string> args;
    std::string raw;
};

class CommandParser{
    public:
        CommandParser() = default;
        ~CommandParser() = default;

        bool isCommand(const std::string& input) const;
        Command parse(const std::string& input) const;
        CommandValidationResult validate(const Command& cmd) const;
    
    private:
        CommandType stringToCommandType(const std::string& cmdStr) const;
};