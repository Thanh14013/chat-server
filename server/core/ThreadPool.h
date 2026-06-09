#pragma once
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>

class ThreadPool {
    public:
        explicit ThreadPool(int numThreads);
        ~ThreadPool();

        void submit(std::function<void()> task);
        size_t pendingTasks();
        void shutdown();

    private:
        void workerLoop();

        std::vector<std::thread> m_workers;
        std::queue<std::function<void()>> m_tasks;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::atomic<bool> m_stopping;
};