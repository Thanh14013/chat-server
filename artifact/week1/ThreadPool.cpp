#include "ThreadPool.h"
#include "../utils/Logger.h"

ThreadPool::ThreadPool(int numThreads) : m_stopping(false) {
    for (int i = 0; i < numThreads; i++) {
        m_workers.emplace_back(&ThreadPool::workerLoop, this);
    }
    LOG_INFO("ThreadPool initialized with " + std::to_string(numThreads) + " workers.");
}

ThreadPool::~ThreadPool() {
    shutdown();
}

void ThreadPool::submit(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_stopping) return;
        m_tasks.push(std::move(task));
    }
    m_cv.notify_one();
}

size_t ThreadPool::pendingTasks() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_tasks.size();
}

void ThreadPool::shutdown() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stopping = true;
    }
    m_cv.notify_all();
    for (auto& t : m_workers) {
        if (t.joinable()) t.join();
    }
    m_workers.clear();
}

void ThreadPool::workerLoop() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this] {
                return m_stopping || !m_tasks.empty();
            });
            if (m_stopping && m_tasks.empty()) return;
            task = std::move(m_tasks.front());
            m_tasks.pop();
        }
        try {
            task();
        } catch (const std::exception& e) {
            LOG_ERROR("ThreadPool task exception: " + std::string(e.what()));
        } catch (...) {
            LOG_ERROR("ThreadPool task: unknown exception");
        }
    }
}
