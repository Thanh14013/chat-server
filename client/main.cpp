#include "core/TcpClient.h"
#include "core/ConnectionManager.h"
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdint>
#include <csignal>
#include <unistd.h>

ConnectionManager* g_mgr = nullptr;

void signalHandler(int signum) {
    if (g_mgr) {
        g_mgr->stop();
    }
    // Force std::getline to unblock by closing stdin
    ::close(STDIN_FILENO);
}

int main(int argc, char* argv[]){
    std::string host = "127.0.0.1";
    uint16_t port = 9000;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--host" && i + 1 < argc) host = argv[++i];
        if (arg == "--port" && i + 1 < argc) port = (uint16_t)std::stoi(argv[++i]);
    }

    TcpClient client;
    if (!client.connectToServer(host,port)){
        std::cerr << "Failed to connect to " << host << ":" << port << std::endl;
        return 1;
    }

    std::cout << "Connected to server! Starting Connection Manager..." << std::endl;

    ConnectionManager mgr(&client);
    g_mgr = &mgr;
    std::signal(SIGINT, signalHandler);

    mgr.run();

    mgr.stop();
    client.disconnect();
    return 0;
}