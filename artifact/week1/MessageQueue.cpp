#include "MessageQueue.h"

void MessageQueue::push(const Packet& pkt) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_queue.size() >= MAX_SIZE) m_queue.pop();
    m_queue.push(pkt);
    m_cv.notify_one();
}

Packet MessageQueue::pop() {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_cv.wait(lock, [this] { return !m_queue.empty(); });
    Packet p = m_queue.front();
    m_queue.pop();
    return p;
}

std::optional<Packet> MessageQueue::tryPop() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_queue.empty()) return std::nullopt;
    Packet p = m_queue.front();
    m_queue.pop();
    return p;
}

std::optional<Packet> MessageQueue::popWithTimeout(int ms) {
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_cv.wait_for(lock, std::chrono::milliseconds(ms), [this] { return !m_queue.empty(); })) {
        Packet p = m_queue.front();
        m_queue.pop();
        return p;
    }
    return std::nullopt;
}

size_t MessageQueue::size() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_queue.size();
}
