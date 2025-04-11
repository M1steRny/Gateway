#pragma once

#include "types.hpp"
#include "constants.hpp"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <future>
#include <atomic>

namespace finaldefi {
namespace sdk {

/**
 * @brief Thread pool with priority queue for task execution
 */
class ThreadPool {
public:
    enum class Priority {
        LOW,
        NORMAL,
        HIGH,
        CRITICAL
    };
    
    struct Task {
        std::function<void()> function;
        Priority priority;
        std::chrono::steady_clock::time_point created_at;
        
        // Comparison for priority queue
        bool operator<(const Task& other) const {
            if (priority != other.priority) {
                return priority < other.priority;
            }
            return created_at > other.created_at; // Older tasks first
        }
    };
    
    // Constructor
    ThreadPool(size_t thread_count = constants::DEFAULT_THREAD_POOL_SIZE);
    
    // Destructor
    ~ThreadPool();
    
    // Enqueue a task with priority
    template<typename F, typename... Args>
    auto enqueue(Priority priority, F&& f, Args&&... args) 
        -> std::future<decltype(f(args...))> {
        using return_type = decltype(f(args...));
        
        auto task_promise = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );
        
        std::future<return_type> result = task_promise->get_future();
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            if (!running_) {
                throw std::runtime_error("Cannot enqueue on stopped ThreadPool");
            }
            
            tasks_.push({
                [task_promise]() { (*task_promise)(); },
                priority,
                std::chrono::steady_clock::now()
            });
        }
        
        condition_.notify_one();
        return result;
    }
    
    // Convenience methods for different priority levels
    template<typename F, typename... Args>
    auto enqueue_low(F&& f, Args&&... args) -> std::future<decltype(f(args...))> {
        return enqueue(Priority::LOW, std::forward<F>(f), std::forward<Args>(args)...);
    }
    
    template<typename F, typename... Args>
    auto enqueue_normal(F&& f, Args&&... args) -> std::future<decltype(f(args...))> {
        return enqueue(Priority::NORMAL, std::forward<F>(f), std::forward<Args>(args)...);
    }
    
    template<typename F, typename... Args>
    auto enqueue_high(F&& f, Args&&... args) -> std::future<decltype(f(args...))> {
        return enqueue(Priority::HIGH, std::forward<F>(f), std::forward<Args>(args)...);
    }
    
    template<typename F, typename... Args>
    auto enqueue_critical(F&& f, Args&&... args) -> std::future<decltype(f(args...))> {
        return enqueue(Priority::CRITICAL, std::forward<F>(f), std::forward<Args>(args)...);
    }
    
    // Get thread pool stats
    size_t get_queued_tasks() const;
    size_t get_active_tasks() const;
    size_t get_completed_tasks() const;
    size_t get_thread_count() const;
    
private:
    std::vector<std::thread> workers_;
    std::thread metrics_thread_;
    std::priority_queue<Task> tasks_;
    
    mutable std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::atomic<bool> running_{false};
    std::atomic<size_t> active_tasks_{0};
    std::atomic<size_t> completed_tasks_{0};
};

} // namespace sdk
} // namespace finaldefi