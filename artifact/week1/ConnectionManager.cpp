#include "ConnectionManager.h"
#include "../../common/MessageTypes.h"
#include "../../common/ErrorCodes.h"
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

ConnectionManager::ConnectionManager()
    : m_cmdHandler(&m_client), m_running(false), m_currentRoom("general") {}

ConnectionManager::~ConnectionManager() {
    stop();
}

bool ConnectionManager::start(const std::string& host, uint16_t port) {
    m_client.setOnPacketReceived([this](const Packet& pkt) {
        m_queue.push(pkt);
    });

    m_client.setOnDisconnected([this]() {
        std::cout << "\n[!] Disconnected from server.\n";
        m_running = false;
    });

    std::cout << "Connecting to " << host << ":" << port << "...\n";
    if (!m_client.connectToServer(host, port)) {
        std::cout << "[!] Failed to connect after retries.\n";
        return false;
    }
    std::cout << "[+] Connected.\n";

    std::cout << "Enter nickname: ";
    std::getline(std::cin, m_nickname);
    if (m_nickname.empty()) m_nickname = "guest";

    json j;
    j["nickname"] = m_nickname;
    j["password"] = "";
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    m_client.sendPacket(Packet(MessageType::MSG_CONNECT_REQUEST, payload));

    auto resp = m_queue.popWithTimeout(5000);
    if (!resp) {
        std::cout << "[!] Server did not respond.\n";
        return false;
    }

    auto type = static_cast<MessageType>(resp->header.msg_type);
    if (type == MessageType::MSG_CONNECT_REJECT) {
        std::string body(resp->payload.begin(), resp->payload.end());
        try {
            auto jj = json::parse(body);
            std::cout << "[!] Rejected: " << jj.value("reason", "unknown") << "\n";
        } catch (...) {
            std::cout << "[!] Connection rejected.\n";
        }
        return false;
    }

    if (type == MessageType::MSG_CONNECT_ACCEPT) {
        std::string body(resp->payload.begin(), resp->payload.end());
        try {
            auto jj = json::parse(body);
            m_currentRoom = jj.value("room", "general");
            m_cmdHandler.setCurrentRoom(m_currentRoom);
        } catch (...) {}
        std::cout << "[+] Joined #" << m_currentRoom << "\n";
        std::cout << "[*] Type /help for commands.\n\n";
    }

    m_running = true;
    m_inputThread = std::thread(&ConnectionManager::inputThread, this);

    while (m_running) {
        auto pkt = m_queue.popWithTimeout(200);
        if (pkt) displayPacket(*pkt);
    }

    if (m_inputThread.joinable()) m_inputThread.join();
    return true;
}

void ConnectionManager::stop() {
    m_running = false;
    m_client.disconnect();
    if (m_inputThread.joinable()) m_inputThread.join();
}

void ConnectionManager::inputThread() {
    while (m_running) {
        std::string line;
        if (!std::getline(std::cin, line)) {
            m_running = false;
            break;
        }
        if (line.empty()) continue;

        if (CommandParser::isCommand(line)) {
            Command cmd = CommandParser::parse(line);
            bool cont = m_cmdHandler.handle(cmd);
            if (!cont) {
                m_running = false;
                break;
            }
        } else {
            if (!sendChatMessage(line)) {
                m_running = false;
                break;
            }
        }
    }
}

bool ConnectionManager::sendChatMessage(const std::string& msg) {
    json j;
    j["message"] = msg;
    j["room"]    = m_currentRoom;
    std::string s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    return m_client.sendPacket(Packet(MessageType::MSG_CHAT_SEND, payload));
}

void ConnectionManager::printTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto tt  = std::chrono::system_clock::to_time_t(now);
    std::cout << "[" << std::put_time(std::localtime(&tt), "%H:%M:%S") << "] ";
}

void ConnectionManager::displayPacket(const Packet& pkt) {
    auto type = static_cast<MessageType>(pkt.header.msg_type);
    std::string body(pkt.payload.begin(), pkt.payload.end());

    switch (type) {
        case MessageType::MSG_CHAT_BROADCAST: {
            try {
                auto j = json::parse(body);
                std::string sender  = j.value("sender", "?");
                std::string room    = j.value("room", "?");
                std::string message = j.value("message", "");
                printTimestamp();
                std::cout << "[#" << room << "] " << sender << ": " << message << "\n";
            } catch (...) {}
            break;
        }
        case MessageType::MSG_CHAT_PRIVATE: {
            try {
                auto j = json::parse(body);
                std::string from    = j.value("from", "?");
                std::string message = j.value("message", "");
                printTimestamp();
                std::cout << "[PM from " << from << "]: " << message << "\n";
            } catch (...) {}
            break;
        }
        case MessageType::MSG_SYSTEM_NOTIFY: {
            try {
                auto j = json::parse(body);
                std::string msg = j.value("message", body);
                printTimestamp();
                std::cout << "*** " << msg << " ***\n";
            } catch (...) {
                printTimestamp();
                std::cout << "*** " << body << " ***\n";
            }
            break;
        }
        case MessageType::MSG_USER_LIST_RESPONSE: {
            try {
                auto j = json::parse(body);
                std::cout << "\n=== Online Users ===\n";
                for (auto& name : j) std::cout << "  - " << name.get<std::string>() << "\n";
                std::cout << "===================\n\n";
            } catch (...) {}
            break;
        }
        case MessageType::MSG_ROOM_LIST_RESPONSE: {
            try {
                auto j = json::parse(body);
                std::cout << "\n=== Rooms ===\n";
                for (auto& r : j) std::cout << "  # " << r.get<std::string>() << "\n";
                std::cout << "=============\n\n";
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
                std::cout << "\n[!] Disconnected: " << j.value("reason", "") << "\n";
            } catch (...) {}
            m_running = false;
            break;
        }
        case MessageType::MSG_PING: {
            m_client.sendPacket(Packet(MessageType::MSG_PONG, {}));
            break;
        }
        default:
            break;
    }
}
