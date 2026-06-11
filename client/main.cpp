#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>
#include <termios.h>
#include <unistd.h>

#include "core/TcpClient.h"
#include "../common/MessageTypes.h"
#include "../server/protocol/Packet.h"

using json = nlohmann::json;

static std::atomic<bool> g_running {false};
static std::string g_nick;
static std::string g_room = "general";
static TcpClient client;
static std::atomic<bool> g_handshakeDone{false};
static std::atomic<bool> g_handshakeSuccess{false};
static std::string g_jwtToken;
static std::string g_host = "127.0.0.1";
static uint16_t g_port = 9000;

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

static void onPacketReceived(const Packet& pkt) {
    auto type = static_cast<MessageType>(pkt.header.msg_type);
    std::string body(pkt.payload.begin(), pkt.payload.end());

    switch (type) {
        case MessageType::MSG_CONNECT_REJECT: {
            try {
                auto j = json::parse(body);
                std::cerr << "[!] Rejected: " << j.value("reason", "unknown") << "\n";
            } catch(...) {
                std::cerr << "[!] Connection rejected.\n";
            }
            g_running = false;
            client.disconnect();
            break;
        }
        case MessageType::MSG_CONNECT_ACCEPT: {
            try {
                auto j = json::parse(body);
                g_room = j.value("room", "general");
                std::string token = j.value("token", "");
                if (!token.empty()) g_jwtToken = token;
            } catch(...) {}
            if (g_jwtToken.empty()) {
                std::cout << "[+] Reconnected successfully to #" << g_room << "\n";
            } else {
                std::cout << "[+] Welcome, " << g_nick << "! You are in #" << g_room << "\n";
                std::cout << "[*] Type /help for commands.\n\n";
            }
            break;
        }
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
                std::cout << timestamp() << "[PM from " << from << "]: " << message << "\n";
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
            client.disconnect();
            break;
        }
        case MessageType::MSG_PING: {
            client.sendPacket(Packet(MessageType::MSG_PONG, {}));
            break;
        }
        default:
            break;
    }
}

static void onDisconnected() {
    g_handshakeDone = true; // In case it disconnects during handshake
    if (g_running) {
        if (!g_jwtToken.empty()) {
            std::cout << "\n[!] Connection lost. Attempting auto-reconnect in background...\n";
            std::thread([]() {
                int attempt = 1;
                while (g_running) {
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                    std::cout << "[*] Auto-reconnecting (Attempt " << attempt++ << ")...\n";
                    g_handshakeDone = false;
                    g_handshakeSuccess = false;
                    if (client.connectToServer(g_host, g_port)) {
                        while (!g_handshakeDone && g_running) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        }
                        if (g_handshakeSuccess) {
                            json j; j["token"] = g_jwtToken;
                            client.sendPacket(makeJsonPacket(MessageType::MSG_RECONNECT_REQUEST, j));
                            break;
                        }
                    }
                }
            }).detach();
        } else {
            std::cout << "\n[!] Disconnected from server.\n";
            g_running = false;
        }
    }
}

static void inputThread() {
    while (g_running) {
        std::string line;
        if (!std::getline(std::cin, line)) {
            g_running = false;
            break;
        }
        if (line.empty()) continue;

        if (line == "/quit") {
            json j; j["reason"] = "User quit";
            client.sendPacket(makeJsonPacket(MessageType::MSG_DISCONNECT, j));
            g_running = false;
            client.disconnect();
            break;
        }

        if (line == "/list") {
            client.sendPacket(Packet(MessageType::MSG_USER_LIST_REQUEST, {}));
            continue;
        }

        if (line == "/rooms") {
            client.sendPacket(Packet(MessageType::MSG_ROOM_LIST_REQUEST, {}));
            continue;
        }

        if (line.rfind("/join", 0) == 0) {
            std::string room = line.substr(6);
            if (!room.empty() && room[0] == '#') room = room.substr(1);
            json j; j["room"] = room;
            client.sendPacket(makeJsonPacket(MessageType::MSG_ROOM_JOIN, j));
            g_room = room;
            continue;
        }

        if (line.rfind("/msg", 0) == 0) {
            std::istringstream iss (line.substr(5));
            std::string to, msg;
            iss >> to;
            std::getline(iss >> std::ws, msg);
            if (!to.empty() && !msg.empty()){
                json j; j["to"] = to, j["message"] = msg;
                client.sendPacket(makeJsonPacket(MessageType::MSG_CHAT_PRIVATE, j));
            } else {
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
        if (!client.sendPacket(makeJsonPacket(MessageType::MSG_CHAT_SEND, j))) {
            if (g_jwtToken.empty()) {
                std::cout << "[!] Failed to send. Connection lost.\n";
                g_running = false;
                client.disconnect();
                break;
            } else {
                std::cout << "[!] Failed to send message. System is reconnecting...\n";
            }
        }
    }
}

static void signalHandler(int){
    std::cout<<"\n[!] Interrupt. Disconnecting...\n";
    g_running = false;
    client.disconnect();
    std::exit(0);
}

static void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " [--host IP] [--port PORT]\n"
              << "  --host  IP    Server IP  (default: 127.0.0.1)\n"
              << "  --port  PORT  Server port (default: 9000)\n";
}

void setEcho(bool enable) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable ) tty.c_lflag &= ~ECHO;
    else tty.c_lflag |= ECHO;
    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

int main(int argc, char* argv[]){
    for (int i=1; i< argc;i++){
        std::string arg = argv[i];
        if ((arg == "--host") && i+1 < argc) {g_host = argv[++i]; continue;}
        if ((arg == "--port") && i+1 < argc) {
            try {
                int p = std::stoi(argv[++i]);
                if ( p<1 || p > 65535) throw std::out_of_range("port");
                g_port = static_cast<uint16_t>(p);
            } catch(...) {
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

    client.setOnPacketReceived(onPacketReceived);
    client.setOnDisconnected(onDisconnected);

    client.setOnHandshakeDone([&](bool success) {
        g_handshakeSuccess = success;
        g_handshakeDone = true;
    });

    std::cout << "Connecting to " << g_host << ":" << g_port << "...\n";
    if (!client.connectToServer(g_host, g_port)) {
        std::cerr << "[!] Could not connect to " << g_host << ":" << g_port << "\n";
        return 1;
    }

    std::cout << "[+] Connected. Performing secure handshake...\n";
    
    auto start_wait = std::chrono::steady_clock::now();
    while(!g_handshakeDone) {
        if(std::chrono::steady_clock::now() - start_wait > std::chrono::seconds(10)) {
            std::cerr << "[!] Handshake timeout.\n";
            client.disconnect();
            return 1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (!g_handshakeSuccess) {
        std::cerr << "[!] Secure handshake failed.\n";
        client.disconnect();
        return 1;
    }

    std::cout << "[+] Secure handshake complete.\n\n";

    std::cout << "Enter nickname: ";
    std::getline(std::cin, g_nick);
    if (g_nick.empty()) g_nick = "guest";

    std::string password;
    std::cout << "Enter password (will be hidden): ";
    setEcho(false);
    std::getline(std::cin, password);
    setEcho(true);
    std::cout << "\n";

    json j;
    j["nickname"] = g_nick;
    j["password"] = password;
    if (!client.sendPacket(makeJsonPacket(MessageType::MSG_CONNECT_REQUEST, j))) {
        std::cerr << "[!] Failed to send connect request.\n";
        client.disconnect();
        return 1;
    }

    g_running = true;

    std::thread inpThr(inputThread);
    inpThr.join();

    client.disconnect();
    std::cout << "\n[*] End.\n";
    return 0;
}