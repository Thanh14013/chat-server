#include "CommandParser.h"
#include <sstream>
#include <algorithm>

namespace CommandParser {

bool isCommand(const std::string& input) {
    return !input.empty() && input[0] == '/';
}

Command parse(const std::string& input) {
    Command cmd;
    cmd.raw  = input;
    cmd.type = CommandType::CMD_UNKNOWN;

    if (!isCommand(input)) return cmd;

    std::istringstream iss(input);
    std::string token;
    std::vector<std::string> tokens;
    while (iss >> token) tokens.push_back(token);

    if (tokens.empty()) return cmd;

    std::string name = tokens[0];
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);

    for (size_t i = 1; i < tokens.size(); i++) cmd.args.push_back(tokens[i]);

    if (name == "/quit")      cmd.type = CommandType::CMD_QUIT;
    else if (name == "/list")      cmd.type = CommandType::CMD_LIST;
    else if (name == "/listall")   cmd.type = CommandType::CMD_LIST_ALL;
    else if (name == "/rooms")     cmd.type = CommandType::CMD_ROOMS;
    else if (name == "/join")      cmd.type = CommandType::CMD_JOIN;
    else if (name == "/leave")     cmd.type = CommandType::CMD_LEAVE;
    else if (name == "/create")    cmd.type = CommandType::CMD_CREATE;
    else if (name == "/msg")       cmd.type = CommandType::CMD_MSG;
    else if (name == "/send")      cmd.type = CommandType::CMD_SEND;
    else if (name == "/whois")     cmd.type = CommandType::CMD_WHOIS;
    else if (name == "/help")      cmd.type = CommandType::CMD_HELP;
    else if (name == "/kick")      cmd.type = CommandType::CMD_KICK;
    else if (name == "/mute")      cmd.type = CommandType::CMD_MUTE;
    else if (name == "/unmute")    cmd.type = CommandType::CMD_UNMUTE;
    else if (name == "/ban")       cmd.type = CommandType::CMD_BAN;
    else if (name == "/unban")     cmd.type = CommandType::CMD_UNBAN;
    else if (name == "/promote")   cmd.type = CommandType::CMD_PROMOTE;
    else if (name == "/demote")    cmd.type = CommandType::CMD_DEMOTE;
    else if (name == "/broadcast") cmd.type = CommandType::CMD_BROADCAST;
    else if (name == "/shutdown")  cmd.type = CommandType::CMD_SHUTDOWN;

    return cmd;
}

}
