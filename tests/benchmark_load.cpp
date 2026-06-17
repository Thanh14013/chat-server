#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <numeric>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../common/Protocol.h"
#include "../common/MessageTypes.h"
#include "../server/protocol/Packet.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std::chrono;

struct BenchStats {
    int    client_id;
    long   msgs_sent;
    long   msgs_received;
    double latency_avg_ms;
    double latency_p99_ms;
    double latency_p999_ms;
    bool   connected;
};

static bool send_all(int fd, const std::vector<uint8_t>& data) {
    size_t total = 0;
    while (total < data.size()) {
        ssize_t n = ::send(fd, data.data() + total, data.size() - total, MSG_NOSIGNAL);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

static bool read_packet(int fd, Packet& out) {
    return readPacketFromFd(fd, out);
}

static Packet make_json_packet(MessageType type, const json& j) {
    std::string s = j.dump();
    std::vector<uint8_t> p(s.begin(), s.end());
    return Packet(type, p);
}

struct BenchmarkClient {
    int    fd = -1;
    int    id;
    bool   connected = false;

    bool connect_to(const std::string& host, uint16_t port, int cid) {
        id = cid;
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        ::inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

        if (::connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
            ::close(fd); fd = -1; return false;
        }

        json j;
        j["nickname"] = "bench_" + std::to_string(id);
        j["password"] = "";
        send_all(fd, packetToBytes(make_json_packet(MessageType::MSG_CONNECT_REQUEST, j)));

        Packet resp;
        if (!read_packet(fd, resp)) { ::close(fd); fd = -1; return false; }
        if (static_cast<MessageType>(resp.header.msg_type) != MessageType::MSG_CONNECT_ACCEPT) {
            ::close(fd); fd = -1; return false;
        }

        connected = true;
        return true;
    }

    BenchStats run(int duration_sec) {
        BenchStats stats{};
        stats.client_id  = id;
        stats.connected  = connected;

        if (!connected) return stats;

        std::vector<double> latencies;
        latencies.reserve(10000);

        auto start  = steady_clock::now();
        auto end_at = start + seconds(duration_sec);

        std::atomic<long> recv_count{0};

        std::thread recv_thread([&]() {
            while (steady_clock::now() < end_at + milliseconds(500)) {
                Packet pkt;
                if (!read_packet(fd, pkt)) break;
                if (static_cast<MessageType>(pkt.header.msg_type) ==
                    MessageType::MSG_CHAT_BROADCAST)
                    recv_count++;
            }
        });

        while (steady_clock::now() < end_at) {
            auto t0 = steady_clock::now();

            json msg;
            msg["message"] = "bench_ping_" + std::to_string(stats.msgs_sent);
            msg["room"]    = "general";
            if (!send_all(fd, packetToBytes(
                    make_json_packet(MessageType::MSG_CHAT_SEND, msg)))) break;

            stats.msgs_sent++;

            double elapsed = duration_cast<microseconds>(
                steady_clock::now() - t0).count() / 1000.0;
            latencies.push_back(elapsed);

            std::this_thread::sleep_for(milliseconds(10));
        }

        std::this_thread::sleep_for(milliseconds(300));
        ::shutdown(fd, SHUT_RDWR);
        recv_thread.join();

        stats.msgs_received = recv_count.load();

        if (!latencies.empty()) {
            double sum = std::accumulate(latencies.begin(), latencies.end(), 0.0);
            stats.latency_avg_ms = sum / latencies.size();

            std::sort(latencies.begin(), latencies.end());
            stats.latency_p99_ms  = latencies[(int)(latencies.size() * 0.99)];
            stats.latency_p999_ms = latencies[(int)(latencies.size() * 0.999)];
        }

        return stats;
    }
};

struct BenchmarkRunner {
    std::string host;
    uint16_t    port;
    int         num_clients;
    int         duration_sec;

    void run(const std::string& scenario_name) {
        std::cout << "\nRunning: " << scenario_name
                  << " (" << num_clients << " clients, "
                  << duration_sec << "s)\n";

        std::vector<std::thread>  threads;
        std::vector<BenchStats>   results(num_clients);

        for (int i = 0; i < num_clients; i++) {
            threads.emplace_back([&, i]() {
                BenchmarkClient client;
                if (client.connect_to(host, port, i)) {
                    results[i] = client.run(duration_sec);
                }
            });
            std::this_thread::sleep_for(milliseconds(20));
        }

        for (auto& t : threads) t.join();

        long   total_sent = 0, total_recv = 0;
        double avg_lat = 0, p99_lat = 0, p999_lat = 0;
        int    connected = 0;

        for (auto& s : results) {
            if (!s.connected) continue;
            connected++;
            total_sent += s.msgs_sent;
            total_recv += s.msgs_received;
            avg_lat  += s.latency_avg_ms;
            p99_lat  = std::max(p99_lat,  s.latency_p99_ms);
            p999_lat = std::max(p999_lat, s.latency_p999_ms);
        }

        if (connected > 0) avg_lat /= connected;

        double throughput = total_sent / (double)duration_sec;
        double delivery   = total_sent > 0
            ? (100.0 * total_recv / (total_sent * std::max(1, connected - 1))) : 0;

        std::cout
            << "╔══════════════════════════════════════════════════════╗\n"
            << "║        VCS SecureChat — Load Test Results            ║\n"
            << "╠══════════════════════════════════════════════════════╣\n"
            << "║  Scenario : " << scenario_name
                 << std::string(42 - scenario_name.size(), ' ') << "║\n"
            << "║  Clients  : " << connected << "/" << num_clients
                 << std::string(48 - std::to_string(connected).size()
                    - std::to_string(num_clients).size() - 1, ' ') << "║\n"
            << "║  Duration : " << duration_sec << "s"
                 << std::string(49 - std::to_string(duration_sec).size(), ' ') << "║\n"
            << "╠══════════════════════════════════════════════════════╣\n"
            << "║  Messages sent    : " << total_sent
                 << std::string(33 - std::to_string(total_sent).size(), ' ') << "║\n"
            << "║  Throughput avg   : " << (int)throughput << " msg/s"
                 << std::string(28 - std::to_string((int)throughput).size(), ' ') << "║\n"
            << "║  Latency avg      : " << avg_lat  << " ms"
                 << std::string(30, ' ') << "║\n"
            << "║  Latency P99      : " << p99_lat  << " ms"
                 << std::string(30, ' ') << "║\n"
            << "║  Latency P99.9    : " << p999_lat << " ms"
                 << std::string(30, ' ') << "║\n"
            << "╚══════════════════════════════════════════════════════╝\n";
    }
};

int main(int argc, char* argv[]) {
    std::string host = "127.0.0.1";
    uint16_t    port = 9000;
    int scenario = 0;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--host"     && i+1 < argc) host     = argv[++i];
        if (arg == "--port"     && i+1 < argc) port     = std::stoi(argv[++i]);
        if (arg == "--scenario" && i+1 < argc) scenario = std::stoi(argv[++i]);
    }

    std::cout << "VCS SecureChat Benchmark — target: " << host << ":" << port << "\n";

    if (scenario == 0 || scenario == 1) {
        BenchmarkRunner r1{host, port, 10, 30};
        r1.run("Baseline (10 clients)");
    }
    if (scenario == 0 || scenario == 2) {
        BenchmarkRunner r2{host, port, 50, 60};
        r2.run("Load Test (50 clients)");
    }
    if (scenario == 0 || scenario == 3) {
        BenchmarkRunner r3{host, port, 100, 60};
        r3.run("Stress Test (100 clients)");
    }

    return 0;
}
