#include "CommandParser.h"
#include <sstream>
#include <algorithm>

bool CommandParser::isCommand(const std::string& input) const {
    return !input.empty() && input[0] == '/';
}

CommandType CommandParser::stringToCommandType(const std::string& cmdStr) const {
    if (cmdStr == "/quit") return CommandType::CMD_QUIT;
    if (cmdStr == "/list") return CommandType::CMD_LIST;
    if (cmdStr == "/listall") return CommandType::CMD_LISTALL;
    if (cmdStr == "/rooms") return CommandType::CMD_ROOMS;
    if (cmdStr == "/join") return CommandType::CMD_JOIN;
    if (cmdStr == "/leave") return CommandType::CMD_LEAVE;
    if (cmdStr == "/create") return CommandType::CMD_CREATE;
    if (cmdStr == "/msg") return CommandType::CMD_MSG;
    if (cmdStr == "/send") return CommandType::CMD_SEND;
    if (cmdStr == "/whois") return CommandType::CMD_WHOIS;
    if (cmdStr == "/accept") return CommandType::CMD_ACCEPT;
    if (cmdStr == "/reject") return CommandType::CMD_REJECT;
    if (cmdStr == "/help") return CommandType::CMD_HELP;
    if (cmdStr == "/kick") return CommandType::CMD_KICK;
    if (cmdStr == "/unkick") return CommandType::CMD_UNKICK;
    if (cmdStr == "/mute") return CommandType::CMD_MUTE;
    if (cmdStr == "/unmute") return CommandType::CMD_UNMUTE;
    if (cmdStr == "/ban") return CommandType::CMD_BAN;
    if (cmdStr == "/unban") return CommandType::CMD_UNBAN;
    if (cmdStr == "/promote") return CommandType::CMD_PROMOTE;
    if (cmdStr == "/demote") return CommandType::CMD_DEMOTE;
    if (cmdStr == "/broadcast") return CommandType::CMD_BROADCAST;
    if (cmdStr == "/shutdown") return CommandType::CMD_SHUTDOWN;
    if (cmdStr == "/delete") return CommandType::CMD_DELETE_ROOM;
    if (cmdStr == "/rooms_admin") return CommandType::CMD_ROOMS_ADMIN;
    
    return CommandType::CMD_UNKNOWN;
}

Command CommandParser::parse(const std::string& input) const {
    Command cmd;
    cmd.raw = input;
    if (!isCommand(input)){
        cmd.type = CommandType::CMD_TEXT;
        return cmd;
    }

    std::istringstream iss(input);
    std::string token;

    if (iss>>token){
        cmd.type = stringToCommandType(token);
    } else{
        cmd.type = CommandType::CMD_UNKNOWN;
        return cmd;
    }

    while (iss >> token){
        cmd.args.push_back(token);
    }

    return cmd;
}

CommandValidationResult CommandParser::validate(const Command& cmd) const {
    if (cmd.type == CommandType::CMD_TEXT) {
        return CommandValidationResult::VALID;
    }

    if (cmd.type == CommandType::CMD_UNKNOWN) {
        return CommandValidationResult::INVALID;
    }

    // Check commands that require admin privileges
    if (cmd.type == CommandType::CMD_KICK || 
        cmd.type == CommandType::CMD_UNKICK || 
        cmd.type == CommandType::CMD_MUTE ||
        cmd.type == CommandType::CMD_UNMUTE ||
        cmd.type == CommandType::CMD_BAN ||
        cmd.type == CommandType::CMD_UNBAN ||
        cmd.type == CommandType::CMD_PROMOTE ||
        cmd.type == CommandType::CMD_DEMOTE ||
        cmd.type == CommandType::CMD_BROADCAST ||
        cmd.type == CommandType::CMD_SHUTDOWN ||
        cmd.type == CommandType::CMD_DELETE_ROOM ||
        cmd.type == CommandType::CMD_ROOMS_ADMIN) {
        return CommandValidationResult::REQUIRES_ADMIN;
    }
    // Check required arguments
    switch (cmd.type) {
        case CommandType::CMD_UNKICK:
            if (cmd.args.size() < 2) return CommandValidationResult::INVALID;
            break;
        case CommandType::CMD_JOIN:
        case CommandType::CMD_CREATE:
        case CommandType::CMD_WHOIS:
        case CommandType::CMD_ACCEPT:
        case CommandType::CMD_REJECT:
        case CommandType::CMD_DELETE_ROOM:
            if (cmd.args.size() < 1) return CommandValidationResult::INVALID;
            break;
        case CommandType::CMD_MSG:
        case CommandType::CMD_SEND:
            if (cmd.args.size() < 2) return CommandValidationResult::INVALID;
            break;
        default:
            break;
    }

    return CommandValidationResult::VALID;
}