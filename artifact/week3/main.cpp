#include "core/ConnectionManager.h"
#include <iostream>
#include <string>
#include <cstdlib>

int main(int argc, char* argv[]) {
    std::string host = "127.0.0.1";
    uint16_t    port = 9000;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--host" && i + 1 < argc) host = argv[++i];
        if (arg == "--port" && i + 1 < argc) port = (uint16_t)std::stoi(argv[++i]);
    }

    ConnectionManager mgr;
    mgr.start(host, port);
    return 0;
}
