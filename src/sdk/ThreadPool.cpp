#include "finaldefi/sdk/ThreadPool.hpp"
#include "finaldefi/sdk/SecureLogger.hpp"
#include <sstream>
#include <thread>
#include <chrono>

namespace finaldefi {
namespace sdk {

ThreadPool::ThreadPool(size_t thread_count) {
    try {
        SecureLogger::instance().info("Initializing thread pool with " + std::to_string(thread_count) + " threads");
        running_ = true;
        
        // Initialize worker threads
        for (size_t i = 0; i < thread_count; ++i) {
            workers_.emplace_back([this, i] {
                thread_local std::string thread_name = "worker-" + std::to_string(i);
                
                while (running_) {
                    Task task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex_);
                        
                        // Wait for task or stop signal
                        condition_.wait(lock, [this] {
                            return !tasks_.empty() || !running_;
                        });
                        
                        if (!running_ && tasks_.empty()) {
                            return;
                        }
                        
                        if (tasks_.empty()) {
                            continue;
                        }
                        
                        // Get highest priority task
                        task = std::move(tasks_.top());
                        tasks_.pop();
                        
                        // Update stats
                        ++active_tasks_;
                    }
                    
                    // Execute task
                    try {
                        task.function();
                    } catch (const std::exception& e) {
                        SecureLogger::instance().error("Thread pool task exception: " + std::string(e.what()));
                    } catch (...) {
                        SecureLogger::instance().error("Thread pool task unknown exception");
                    }
                    
                    // Update stats
                    {
                        std::lock_guard<std::mutex> lock(queue_mutex_);
                        --active_tasks_;
                        ++completed_tasks_;
                    }
                }
            });
        }
        
        // Start metrics thread
        metrics_thread_ = std::thread([this] {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::seconds(60));
                
                if (!running_) break;
                
                std::lock_guard<std::mutex> lock(queue_mutex_);
                SecureLogger::instance().debug("Thread pool metrics - Queued: " + 
                                         std::to_string(tasks_.size()) + 
                                         ", Active: " + std::to_string(active_tasks_) + 
                                         ", Completed: " + std::to_string(completed_tasks_));
            }
        });
        
    } catch (const std::exception& e) {
        SecureLogger::instance().critical("Failed to initialize thread pool: " + std::string(e.what()));
        throw;
    }
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        running_ = false;
    }
    
    condition_.notify_all();
    
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    if (metrics_thread_.joinable()) {
        metrics_thread_.join();
    }
    
    SecureLogger::instance().info("Thread pool shutdown complete");
}

size_t ThreadPool::get_queued_tasks() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return tasks_.size();
}

size_t ThreadPool::get_active_tasks() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return active_tasks_;
}

size_t ThreadPool::get_completed_tasks() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return completed_tasks_;
}

size_t ThreadPool::get_thread_count() const {
    return workers_.size();
}

} // namespace sdk
} // namespace finaldefi