#include "ConnectionManager.h"
#include "../core/TcpClient.h"
#include "../../common/MessageTypes.h"
#include <iostream>
#include <filesystem>
#include <iomanip>
#include <ctime>
#include <nlohmann/json.hpp>
#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
using json = nlohmann::json;

ConnectionManager::ConnectionManager(TcpClient *client)
    : m_client(client), m_cmdHandler(client), m_running(false)
{
    if (m_client)
    {
        m_client->setOnPacketReceived([this](const Packet &pkt)
                                      { this->onPacketReceived(pkt); });
        m_client->setOnHandshakeDone([this](bool success)
                                     { this->onHandshakeDone(success); });
        m_client->setOnDisconnected([this]() {
            std::cout << "\n[SYSTEM] Disconnected from server.\n";
            stop();
        });
    }
}

void ConnectionManager::onHandshakeDone(bool success) {
    std::lock_guard<std::mutex> lock(m_authMutex);
    if (!success) {
        m_authState = AuthState::HANDSHAKE_FAILED;
    } else {
        m_authState = AuthState::PENDING_AUTH;
    }
    m_authCv.notify_all();
}

ConnectionManager::~ConnectionManager()
{
    stop();
}
void ConnectionManager::stop()
{
    m_running = false;
    m_authCv.notify_all();
}

void ConnectionManager::registerUpload(const std::string &filename, const std::string &filepath)
{
    std::lock_guard<std::mutex> lock(m_fileMutex);
    m_pendingUploads[filename] = filepath;
}
void ConnectionManager::run()
{
    if (m_running)
        return;
    m_running = true;

    // 1. Wait for handshake
    {
        std::unique_lock<std::mutex> lock(m_authMutex);
        m_authCv.wait(lock, [this]() { 
            return m_authState != AuthState::PENDING_HANDSHAKE || !m_running.load(); 
        });
    }

    if (!m_running) return;
    if (m_authState == AuthState::HANDSHAKE_FAILED) {
        std::cout << "[SYSTEM] Crypto handshake failed.\n";
        stop();
        return;
    }

    // 2. Try Reconnect if token exists
    std::string token;
    if (std::filesystem::exists("token.txt")) {
        std::ifstream ifs("token.txt");
        if (ifs.is_open()) {
            std::getline(ifs, token);
            ifs.close();
        }
    }

    if (!token.empty()) {
        json j;
        j["token"] = token;
        std::string payload = j.dump();
        std::vector<uint8_t> body(payload.begin(), payload.end());
        m_client->sendPacket(Packet(MessageType::MSG_RECONNECT_REQUEST, body));

        std::unique_lock<std::mutex> lock(m_authMutex);
        m_authCv.wait(lock, [this]() { 
            return m_authState == AuthState::AUTHENTICATED || 
                   m_authState == AuthState::REJECTED || 
                   !m_running.load(); 
        });
    }

    // 3. Fallback / Login Loop
    while (m_running && m_authState != AuthState::AUTHENTICATED) {
        std::cout << "Enter nickname: ";
        std::cout.flush();
        std::string nick;
        if (!std::getline(std::cin, nick)) {
            stop();
            return;
        }

        std::cout << "Enter password: ";
        std::cout.flush();
        std::string pass;
#ifdef _WIN32
        char ch;
        while ((ch = _getch()) != '\r') {
            if (ch == '\b') {
                if (!pass.empty()) {
                    pass.pop_back();
                    std::cout << "\b \b";
                }
            } else if (ch == 3) {
                std::exit(1);
            } else {
                pass += ch;
                std::cout << '*';
            }
        }
        std::cout << std::endl;
#else
        termios oldt;
        tcgetattr(STDIN_FILENO, &oldt);
        termios newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        if (!std::getline(std::cin, pass)) {
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            stop();
            return;
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << std::endl;
#endif

        json j;
        j["nickname"] = nick;
        j["password"] = pass;
        std::string payload = j.dump();
        std::vector<uint8_t> body(payload.begin(), payload.end());
        
        m_authState = AuthState::PENDING_AUTH;
        m_client->sendPacket(Packet(MessageType::MSG_CONNECT_REQUEST, body));

        std::unique_lock<std::mutex> lock(m_authMutex);
        m_authCv.wait(lock, [this]() { 
            return m_authState == AuthState::AUTHENTICATED || 
                   m_authState == AuthState::REJECTED || 
                   !m_running.load(); 
        });
    }

    if (!m_running) return;

    std::cout << "Type /help for a list of commands." << std::endl;

    std::string input;
    while (m_running)
    {
        if (std::getline(std::cin, input))
        {
            if (input.empty())
                continue;

            if (m_cmdParser.isCommand(input))
            {
                Command cmd = m_cmdParser.parse(input);
                CommandValidationResult res = m_cmdParser.validate(cmd);

                if (res == CommandValidationResult::INVALID)
                {
                    std::cout << "[SYSTEM] Invalid command syntax." << std::endl;
                    continue;
                }

                if (cmd.type == CommandType::CMD_SEND && cmd.args.size() >= 2)
                {
                    std::string filepath = cmd.args[1];
                    std::string filename = std::filesystem::path(filepath).filename().string();
                    registerUpload(filename, filepath);
                }

                m_cmdHandler.handleCommand(cmd);
                if (cmd.type == CommandType::CMD_QUIT)
                {
                    stop();
                    break;
                }
            }
            else
            {
                json j;
                j["message"] = input;
                std::string s = j.dump();
                std::vector<uint8_t> payload(s.begin(), s.end());
                std::cout << "\x1b[1A\x1b[2K\r" << std::flush; // Erase the line the user just typed to avoid double printing
                m_client->sendPacket(Packet(MessageType::MSG_CHAT_SEND, payload));
            }
        }
    }
}

void ConnectionManager::onPacketReceived(const Packet &pkt)
{
    auto type = static_cast<MessageType>(pkt.header.msg_type);
    std::string payload(pkt.payload.begin(), pkt.payload.end());

    switch (type)
    {
    case MessageType::MSG_CONNECT_ACCEPT:
    {
        auto j = json::parse(payload, nullptr, false);
        if (!j.is_discarded()) {
            std::string token = j.value("token", "");
            if (!token.empty()) {
                std::ofstream ofs("token.txt");
                ofs << token;
                ofs.close();
            }
            std::string room = j.value("room", "general");
            m_nickname = j.value("nickname", "");
            std::cout << "[+] Connected successfully! You are in #" << room << "\n";
        }
        std::lock_guard<std::mutex> lock(m_authMutex);
        m_authState = AuthState::AUTHENTICATED;
        m_authCv.notify_all();
        break;
    }
    case MessageType::MSG_CONNECT_REJECT:
    {
        auto j = json::parse(payload, nullptr, false);
        if (!j.is_discarded()) {
            std::string reason = j.value("reason", "Unknown");
            if (reason.find("token") == std::string::npos) {
                std::cout << "[-] Connection rejected: " << reason << "\n";
            }
        }
        if (std::filesystem::exists("token.txt")) {
            std::filesystem::remove("token.txt"); // Remove invalid token
        }
        std::lock_guard<std::mutex> lock(m_authMutex);
        m_authState = AuthState::REJECTED;
        m_authCv.notify_all();
        break;
    }
    case MessageType::MSG_CHAT_BROADCAST:
    {
        auto j = json::parse(payload, nullptr, false);
        if (!j.is_discarded())
        {
            try {
                if (j.is_array()) {
                    for (const auto& item : j) {
                        time_t ts = item.value("ts", 0LL);
                        std::string sender = item.value("sender", "");
                        std::string r = item.value("room", "");
                        if (!r.empty() && r[0] == '#') r = r.substr(1);
                        
                        std::cout << "\r[" << std::put_time(std::localtime(&ts), "%H:%M:%S") << "] ["
                                  << r << "] ";
                        if (sender == m_nickname) {
                            std::cout << item.value("message", "") << std::endl;
                        } else {
                            std::cout << sender << ": " << item.value("message", "") << std::endl;
                        }
                    }
                } else if (j.is_object()) {
                    time_t ts = j.value("ts", 0LL);
                    std::string sender = j.value("sender", "");
                    std::string r = j.value("room", "");
                    if (!r.empty() && r[0] == '#') r = r.substr(1);

                    std::cout << "\r[" << std::put_time(std::localtime(&ts), "%H:%M:%S") << "] ["
                              << r << "] ";
                    if (sender == m_nickname) {
                        std::cout << j.value("message", "") << std::endl;
                    } else {
                        std::cout << sender << ": " << j.value("message", "") << std::endl;
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "[!] Error parsing chat broadcast: " << e.what() << std::endl;
            }
        }
        break;
    }
    case MessageType::MSG_SYSTEM_NOTIFY:
    {
        auto j = json::parse(payload, nullptr, false);
        if (!j.is_discarded())
        {
            std::cout << "[SYSTEM] " << j.value("message", "") << std::endl;
        }
        break;
    }
    case MessageType::MSG_CHAT_PRIVATE:
    {
        auto j = json::parse(payload, nullptr, false);
        if (!j.is_discarded())
        {
            std::cout << "[PRIVATE] " << j.value("from", "") << " -> "
                      << j.value("to", "") << ": "
                      << j.value("message", "") << std::endl;
        }
        break;
    }
    case MessageType::MSG_ERROR:
    {
        auto j = json::parse(payload, nullptr, false);
        if (!j.is_discarded())
        {
            std::cout << "[ERROR] " << j.value("reason", "") << std::endl;
        }
        break;
    }
    case MessageType::MSG_PING:
    {
        m_client->sendPacket(Packet(MessageType::MSG_PONG, std::vector<uint8_t>()));
        break;
    }
    case MessageType::MSG_USER_LIST_RESPONSE:
    case MessageType::MSG_USER_LISTALL_RESPONSE:
    case MessageType::MSG_ROOM_LIST_RESPONSE:
    case MessageType::MSG_ADMIN_ROOM_INFO_RESPONSE:
    {
        auto j = json::parse(payload, nullptr, false);
        if (!j.is_discarded())
        {
            std::cout << "[INFO] " << j.dump(2) << std::endl;
        }
        break;
    }
    case MessageType::MSG_WHOIS_RESPONSE:
    {
        auto j = json::parse(payload, nullptr, false);
        if (!j.is_discarded())
        {
            if (j.contains("error"))
            {
                std::cout << "[SYSTEM] " << j["error"].get<std::string>() << std::endl;
            }
            else
            {
                std::cout << "=== WHOIS INFO ===\n"
                          << " Nickname: " << j.value("nickname", "") << "\n"
                          << " IP: " << j.value("ip", "") << "\n"
                          << " Room: " << j.value("room", "") << "\n"
                          << " Muted: " << (j.value("is_muted", false) ? "Yes" : "No") << "\n"
                          << "==================\n";
            }
        }
        break;
    }
    case MessageType::MSG_FILE_REQUEST:
        handleFileRequest(json::parse(payload, nullptr, false));
        break;
    case MessageType::MSG_FILE_ACCEPT:
        handleFileAccept(json::parse(payload, nullptr, false));
        break;
    case MessageType::MSG_FILE_REJECT:
    {
        auto j = json::parse(payload, nullptr, false);
        if (!j.is_discarded())
        {
            std::cout << "[SYSTEM] Transfer " << j.value("transfer_id", "") << " was rejected." << std::endl;
        }
        break;
    }
    case MessageType::MSG_FILE_DATA:
        handleFileData(json::parse(payload, nullptr, false));
        break;
    case MessageType::MSG_FILE_COMPLETE:
        handleFileComplete(json::parse(payload, nullptr, false));
        break;
    default:
        break;
    }
}

void ConnectionManager::handleFileRequest(const nlohmann::json &j)
{
    if (j.is_discarded())
        return;
    std::cout << "[FILE] User " << j.value("from", "")
              << " wants to send file: " << j.value("filename", "")
              << " (" << j.value("size", 0) << " bytes). "
              << "Type /accept " << j.value("transfer_id", "") << " or /reject " << j.value("transfer_id", "") << std::endl;

    std::lock_guard<std::mutex> lock(m_fileMutex);
    DownloadState state;
    state.filename = j.value("filename", "");
    state.expectedSize = j.value("size", 0);
    state.receivedSize = 0;
    state.expectedHash = j.value("sha256", "");
    m_activeDownloads[j.value("transfer_id", "")] = state;
}

void ConnectionManager::handleFileAccept(const nlohmann::json &j)
{
    if (j.is_discarded())
        return;
    std::string tid = j.value("transfer_id", "");
    std::string filename = j.value("filename", "");
    std::string filepath;

    {
        std::lock_guard<std::mutex> lock(m_fileMutex);
        if (m_pendingUploads.find(filename) != m_pendingUploads.end())
        {
            filepath = m_pendingUploads[filename];
        }
    }

    if (filepath.empty())
    {
        std::cout << "[SYSTEM] Accepted transfer " << tid << " but cannot find local file mapping." << std::endl;
        return;
    }

    std::cout << "[SYSTEM] Transfer " << tid << " accepted. Starting upload..." << std::endl;
    std::thread(&ConnectionManager::uploadWorker, this, tid, filepath).detach();
}

void ConnectionManager::uploadWorker(std::string transferId, std::string filepath)
{
    std::ifstream ifs(filepath, std::ios::binary);
    if (!ifs.is_open())
    {
        std::cout << "[SYSTEM] Cannot read file for upload: " << filepath << std::endl;
        return;
    }

    std::vector<uint8_t> buffer(4096);
    while (ifs)
    {
        ifs.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
        size_t bytesRead = ifs.gcount();
        if (bytesRead > 0)
        {
            std::vector<uint8_t> chunk(buffer.begin(), buffer.begin() + bytesRead);
            json j;
            j["transfer_id"] = transferId;
            j["data"] = chunk;
            std::string s = j.dump();
            m_client->sendPacket(Packet(MessageType::MSG_FILE_DATA, std::vector<uint8_t>(s.begin(), s.end())));
            std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Prevent flooding
        }
    }
    ifs.close();

    json endj;
    endj["transfer_id"] = transferId;
    std::string s = endj.dump();
    m_client->sendPacket(Packet(MessageType::MSG_FILE_COMPLETE, std::vector<uint8_t>(s.begin(), s.end())));
    std::cout << "[SYSTEM] Finished sending file " << filepath << " (tid: " << transferId << ")" << std::endl;
}

void ConnectionManager::handleFileData(const nlohmann::json &j)
{
    if (j.is_discarded())
        return;
    std::string tid = j.value("transfer_id", "");
    std::vector<uint8_t> chunk = j.value("data", std::vector<uint8_t>());

    std::lock_guard<std::mutex> lock(m_fileMutex);
    auto it = m_activeDownloads.find(tid);
    if (it == m_activeDownloads.end())
        return;

    std::string outPath = "Downloads_" + it->second.filename;
    std::ofstream ofs(outPath, std::ios::binary | std::ios::app);
    if (ofs.is_open() && !chunk.empty())
    {
        ofs.write(reinterpret_cast<const char *>(chunk.data()), chunk.size());
        it->second.receivedSize += chunk.size();
    }
}

void ConnectionManager::handleFileComplete(const nlohmann::json &j)
{
    if (j.is_discarded())
        return;
    std::string tid = j.value("transfer_id", "");

    std::lock_guard<std::mutex> lock(m_fileMutex);
    auto it = m_activeDownloads.find(tid);
    if (it != m_activeDownloads.end())
    {
        std::cout << "[SYSTEM] File download complete: " << it->second.filename
                  << " (" << it->second.receivedSize << " bytes)." << std::endl;
        m_activeDownloads.erase(it);
    }
}
