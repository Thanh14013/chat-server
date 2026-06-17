#include "core/TcpServer.h"
#include "core/EventLoop.h"
#include "utils/Logger.h"
#include "utils/Config.h"
#include "utils/Database.h"
#include "security/CryptoEngine.h"
#include "security/AuditLogger.h"
#include "security/IntrusionDetector.h"
#include <csignal>
#include <cstdlib>
#include <string>
#include <sys/stat.h>
#include <iostream>

static TcpServer* g_server = nullptr;
static EventLoop* g_eventLoop = nullptr;

static void signalHandler(int sig){
    if (sig == SIGINT || sig == SIGTERM) {
        LOG_INFO("Shutdown signal received.");
        if (g_eventLoop) g_eventLoop->stop();
        if (g_server)    g_server->stop();
    }
}

int main(int argc, char* argv[]){
    std::string configPath = "server_config.json";
    int portOverride = 0;
    bool verifyAudit = false;

    for (int i = 1; i < argc; i++){
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) configPath = argv[++i];
        if (arg == "--port" && i + 1 < argc) portOverride = std::stoi(argv[++i]);
        if (arg == "--verify-audit-log") verifyAudit = true;
    }

    mkdir("logs", 0755);
    Logger::instance().setLogDir("logs");
    Logger::instance().setLevel(LogLevel::INFO);

    if (verifyAudit) {
        Database::instance().open("vcs_chat.db");
        bool ok = AuditLogger::instance().verifyChain();
        std::cout << (ok ? "[PASS] Audit chain intact.\n" : "[FAIL] Audit chain TAMPERED!\n");
        Database::instance().close();
        return ok ? 0 : 1;
    }

    Config::instance().load(configPath);
    const auto& cfg = Config::instance().get();

    Database::instance().open("vcs_chat.db");

    std::signal(SIGINT,  signalHandler);
    std::signal(SIGTERM, signalHandler);
    std::signal(SIGPIPE, SIG_IGN);

    uint16_t port     = portOverride > 0 ? static_cast<uint16_t>(portOverride) : cfg.port;
    int      maxCli   = cfg.max_clients;
    int      poolSize = cfg.thread_pool_size;

    TcpServer server;
    EventLoop eventLoop(&server);

    g_server = &server;
    g_eventLoop = &eventLoop;

    LOG_INFO("Initializing Crypto Engine...");
    vcs::security::CryptoEngine::getInstance().initialize();

    eventLoop.start();
    server.start(port, maxCli, poolSize);

    eventLoop.stop();
    Database::instance().close();

    LOG_INFO("End.");
    return 0;
}