#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <chrono>
#include "../../common/Protocol.h"

class MessageQueue
{
public:
    void push(const Packet &pkt);
    Packet pop();
    std::optional<Packet> tryPop();
    std::optional<Packet> popWithTimeout(int ms);
    size_t size();

private:
    std::queue<Packet> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    static constexpr size_t MAX_SIZE = 1000;
};