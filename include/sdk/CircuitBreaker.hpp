#pragma once

#include "types.hpp"
#include "constants.hpp"
#include <chrono>
#include <mutex>
#include <string>

namespace finaldefi {
namespace sdk {

/**
 * @brief Circuit breaker pattern implementation for fault tolerance
 */
class CircuitBreaker {
public:
    enum class State {
        CLOSED,    // Normal operation
        OPEN,      // No operation allowed, failing fast
        HALF_OPEN  // Testing if service is healthy again
    };
    
    CircuitBreaker(
        size_t failure_threshold = constants::CIRCUIT_BREAKER_THRESHOLD,
        std::chrono::seconds reset_timeout = constants::CIRCUIT_BREAKER_RESET_TIMEOUT);
    
    // Execute a function with circuit breaker protection
    template<typename T, typename F, typename... Args>
    Result<T> execute(F&& func, Args&&... args) {
        using return_type = T;
        
        if (state_ == State::OPEN) {
            // Check if it's time to try again
            auto now = std::chrono::steady_clock::now();
            if (now - last_failure_time_ >= reset_timeout_) {
                SecureLogger::instance().info("Circuit half-open, testing service");
                state_ = State::HALF_OPEN;
            } else {
                SecureLogger::instance().warning("Circuit open, failing fast");
                return ErrorCode::CIRCUIT_OPEN;
            }
        }
        
        try {
            auto result = func(std::forward<Args>(args)...);
            
            // If successful in HALF_OPEN state, reset the circuit
            if (state_ == State::HALF_OPEN) {
                SecureLogger::instance().info("Service recovered, circuit closed");
                reset();
            }
            
            return result;
        } catch (const std::exception& e) {
            record_failure(e.what());
            
            if constexpr (std::is_same_v<return_type, void>) {
                return ErrorCode::TASK_EXECUTION_FAILED;
            } else {
                return ErrorCode::TASK_EXECUTION_FAILED;
            }
        }
    }
    
    // Special case for void return type
    template<typename F, typename... Args>
    Result<void> execute(F&& func, Args&&... args) {
        if (state_ == State::OPEN) {
            // Check if it's time to try again
            auto now = std::chrono::steady_clock::now();
            if (now - last_failure_time_ >= reset_timeout_) {
                SecureLogger::instance().info("Circuit half-open, testing service");
                state_ = State::HALF_OPEN;
            } else {
                SecureLogger::instance().warning("Circuit open, failing fast");
                return ErrorCode::CIRCUIT_OPEN;
            }
        }
        
        try {
            func(std::forward<Args>(args)...);
            
            // If successful in HALF_OPEN state, reset the circuit
            if (state_ == State::HALF_OPEN) {
                SecureLogger::instance().info("Service recovered, circuit closed");
                reset();
            }
            
            return ErrorCode::SUCCESS;
        } catch (const std::exception& e) {
            record_failure(e.what());
            return ErrorCode::TASK_EXECUTION_FAILED;
        }
    }
    
    // Record a success
    void record_success();
    
    // Record a failure
    void record_failure(const std::string& error_message = "Unknown error");
    
    // Reset the circuit
    void reset();
    
    // Get current state
    State get_state() const;
    
    // Get failure count
    size_t get_failure_count() const;
    
private:
    size_t failure_threshold_;
    std::chrono::seconds reset_timeout_;
    State state_;
    size_t failure_count_;
    std::chrono::steady_clock::time_point last_failure_time_;
    mutable std::mutex mutex_;
};

} // namespace sdk
} // namespace finaldefi