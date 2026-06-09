#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <nlohmann/json.hpp>

#include "../common/Protocol.h"
#include "../common/MessageTypes.h"
#include "../common/Constants.h"
#include "../server/protocol/Packet.h"

using json = nlohmann::json;

static int g_fd = -1;
static std::atomic<bool> g_running {false};
static std::string g_nick;
static std::string g_room = "general";

static bool sendPacket(const Packet& pkt){
    auto bytes = packetToBytes(pkt);
    ssize_t total = 0;
    ssize_t len = static_cast<ssize_t>(bytes.size());
    while (total < len){
        ssize_t n =::send(g_fd, bytes.data() + total, len-total, MSG_NOSIGNAL);
        if (n <= 0) return false;
        total+=n;
    }
    return true;
}

static Packet makeJsonPacket(MessageType type, const json& j){
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    return Packet(type, payload);
}

static std::string timestamp() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << "[" << std::put_time(std::localtime(&tt), "%H:%M:%S") << "] ";
    return oss.str();
}

static void receiveThread(){
    while (g_running){
        Packet pkt;
        if (!readPacketFromFd(g_fd, pkt)){
            if (g_running) {
                std::cout << "\n[!] Disconnected from server.\n";
                g_running = false;
            }
            break;
        }

        auto type = static_cast<MessageType>(pkt.header.msg_type);
        std::string body(pkt.payload.begin(), pkt.payload.end());

        switch (type){
            case MessageType::MSG_CHAT_BROADCAST: {
                try{
                    auto j = json::parse(body);
                    std::string sender = j.value("sender", "?");
                    std::string room    = j.value("room",    "?");
                    std::string message = j.value("message", "");
                    std::cout << timestamp() << "[#" << room << "] " << sender << ": " << message << "\n";
                } catch(...){}
                break;
            }
            case MessageType::MSG_CHAT_PRIVATE: {
                try {
                    auto j      = json::parse(body);
                    std::string from    = j.value("from",    "?");
                    std::string message = j.value("message", "");
                    std::cout << timestamp()
                              << "[PM from " << from << "]: " << message << "\n";
                } catch (...) {}
                break;
            }
            case MessageType::MSG_SYSTEM_NOTIFY: {
                try {
                    auto j   = json::parse(body);
                    std::string msg = j.value("message", body);
                    std::cout << timestamp() << "*** " << msg << " ***\n";
                } catch (...) {
                    std::cout << timestamp() << "*** " << body << " ***\n";
                }
                break;
            }
            case MessageType::MSG_USER_LIST_RESPONSE: {
                try {
                    auto j = json::parse(body);
                    std::cout << "\n--- Online users in #" << g_room << " ---\n";
                    for (auto& name : j)
                        std::cout << "  - " << name.get<std::string>() << "\n";
                    std::cout << "-----------------------------\n\n";
                } catch (...) {}
                break;
            }
            case MessageType::MSG_ROOM_LIST_RESPONSE: {
                try {
                    auto j = json::parse(body);
                    std::cout << "\n--- Rooms ---\n";
                    for (auto& r : j)
                        std::cout << "  # " << r.get<std::string>() << "\n";
                    std::cout << "-------------\n\n";
                } catch (...) {}
                break;
            }
            case MessageType::MSG_ERROR: {
                try {
                    auto j = json::parse(body);
                    std::cout << "[ERROR] " << j.value("detail", body) << "\n";
                } catch (...) {
                    std::cout << "[ERROR] " << body << "\n";
                }
                break;
            }
            case MessageType::MSG_DISCONNECT: {
                try {
                    auto j = json::parse(body);
                    std::cout << "\n[!] Server: " << j.value("reason", "") << "\n";
                } catch (...) {}
                g_running = false;
                break;
            }
            case MessageType::MSG_PING: {
                sendPacket(Packet(MessageType::MSG_PONG, {}));
                break;
            }
            default:
                break;
        }
    }
}

static void inputThread(){
    while (g_running){
        std::string line;
        if (std::getline(std::cin, line)){
            g_running = false;
            break;
        }
        if (line.empty()) continue;

        if (line == "/quit") {
            json j; j["reason"] = "User quit";
            sendPacket(makeJsonPacket(MessageType::MSG_DISCONNECT, j));
            g_running = false;
            break;
        }

        if (line == "/list") {
            sendPacket(Packet(MessageType::MSG_USER_LIST_REQUEST, {}));
            continue;
        }

        if (line == "/rooms") {
            sendPacket(Packet(MessageType::MSG_ROOM_LIST_REQUEST, {}));
            continue;
        }

        if (line.rfind("/join", 0) == 0){
            std::string room = line.substr(6);
            if (!room.empty() && room[0] == '#') room = room.substr(1);
            json j; j["room"] = room;
            sendPacket(makeJsonPacket(MessageType::MSG_ROOM_JOIN, j));
            g_room = room;
            continue;
        }

        if (line.rfind("/msg", 0) == 0){
            std::istringstream iss (line.substr(5));
            std::string to, msg;
            iss >> to;
            std::getline(iss >> std::ws, msg);
            if (!to.empty() && !msg.empty()){
                json j; j["to"] = to, j["message"] = msg;
                sendPacket(makeJsonPacket(MessageType::MSG_CHAT_PRIVATE, j));
            }else {
                std::cout << "Usage: /msg <nickname> <message>\n";
            }
            continue;
        }

        if (line == "/help") {
            std::cout << "\n=== Commands ===\n"
                      << "  /list           - show online users in current room\n"
                      << "  /rooms          - show all rooms\n"
                      << "  /join #room     - join a room\n"
                      << "  /msg <user> <text> - private message\n"
                      << "  /quit           - disconnect and exit\n"
                      << "  /help           - show this help\n"
                      << "================\n\n";
            continue;
        }

        if (!line.empty() && line[0] == '/') {
            std::cout << "[!] Unknown command. Type /help for a list.\n";
            continue;
        }

        json j;
        j["message"] = line;
        j["room"]    = g_room;
        if (!sendPacket(makeJsonPacket(MessageType::MSG_CHAT_SEND, j))) {
            std::cout << "[!] Failed to send. Connection lost.\n";
            g_running = false;
            break;
        }
    }
}

static void signalHandler(int){
    std::cout<<"\n[!] Interrupt. Disconnecting...\n";
    g_running = false;
    if (g_fd>=0) ::shutdown(g_fd, SHUT_RDWR);
    std::exit(0);
}

static void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " [--host IP] [--port PORT]\n"
              << "  --host  IP    Server IP  (default: 127.0.0.1)\n"
              << "  --port  PORT  Server port (default: 9000)\n";
}

int main(int argc, char* argv[]){
    std::string host ="127.0.0.1";
    uint16_t port = 9000;

    for (int i=1; i< argc;i++){
        std::string arg = argv[i];
        if ((arg == "--host") && i+1 < argc) {host = argv[++i]; continue;}
        if ((arg == "--port") && i+1 < argc) {
            try{
                int p = std::stoi(argv[++i]);
                if ( p<1 || p > 65535) throw std::out_of_range("port");
                port = static_cast<uint16_t>(p);
            } catch(...){
                std::cerr<< "[!] Invalid port: " << argv[i] << "\n";
                return 1;
            }
        }
        if (arg == "--help") { printUsage(argv[0]); return 0;}
        std::cerr << "[!] Unknown argument: " << arg << "\n";
        printUsage(argv[0]);
        return 1;
    }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    std::signal(SIGPIPE, SIG_IGN);

    std::cout << "=== ChatGroup Client ===\n\n";

    g_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (g_fd < 0) {std::cerr << "[!] socket() failed.\n"; return 1; }
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0){
        std::cerr << "[!] Invalid host: " << host << "\n";
        ::close(g_fd);
        return 1;
    }

    std::cout << "Connecting to " << host << ":" << port << "...\n";
    int attempts = 0;
    int delays[] = {0,2,4,8};
    bool connected = false;
    while (attempts < 4) {
        if (delays[attempts] > 0){
            std::cout << "Retrying in " << delays[attempts] << "s...\n";
            std::this_thread::sleep_for(std::chrono::seconds(delays[attempts]));
        }
        if (::connect(g_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            connected = true;
            break;
        }
        std::cout << "Attempt " << (attempts + 1) << " failed.\n";
        attempts++;
    }

    if (!connected) {
        std::cerr << "[!] Could not connect to " << host << ":" << port << "\n";
        ::close(g_fd);
        return 1;
    }
    std::cout << "[+] Connected.\n\n";

    std::cout << "Enter nickname: ";
    std::getline(std::cin, g_nick);
    if (g_nick.empty()) g_nick = "guest";

    {
        json j;
        j["nickname"] = g_nick;
        j["password"] = "";
        if (!sendPacket(makeJsonPacket(MessageType::MSG_CONNECT_REQUEST, j))) {
            std::cerr << "[!] Failed to send connect request.\n";
            ::close(g_fd);
            return 1;
        }
    }

    {
        Packet resp;
        if (!readPacketFromFd(g_fd, resp)){
            std::cerr << "[!] No response from server.\n";
            ::close(g_fd);
            return 1;
        }

        auto type = static_cast<MessageType>(resp.header.msg_type);
        std::string body(resp.payload.begin(), resp.payload.end());

        if (type == MessageType::MSG_CONNECT_REJECT){
            try{
                auto j = json::parse(body);
                std::cerr << "[!] Rejected: " << j.value("reason", "unknown") << "\n";
            }catch(...){
                std::cerr << "[!] Connection rejected.\n";
            }
            ::close(g_fd);
            return 1;
        }

        if (type == MessageType::MSG_CONNECT_ACCEPT){
            try{
                auto j = json::parse(body);
                g_room = j.value("room", "general");
            }catch(...){
                std::cout << "[+] Welcome, " << g_nick << "! You are in #" << g_room << "\n";
                std::cout << "[*] Type /help for commands.\n\n";
            }
        }
    }

    g_running = true;

    std::thread recvTHr(receiveThread);
    std::thread inpThr(inputThread);

    recvTHr.join();
    inpThr.join();

    ::close(g_fd);
    g_fd = -1;
    std::cout << "\n[*] End.\n";
    return 0;
}