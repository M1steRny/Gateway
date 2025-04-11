#include "finaldefi/sdk/CircuitBreaker.hpp"
#include "finaldefi/sdk/SecureLogger.hpp"
#include <chrono>
#include <mutex>

namespace finaldefi {
namespace sdk {

CircuitBreaker::CircuitBreaker(
    size_t failure_threshold,
    std::chrono::seconds reset_timeout)
    : failure_threshold_(failure_threshold),
      reset_timeout_(reset_timeout),
      state_(State::CLOSED),
      failure_count_(0) {
}

void CircuitBreaker::record_success() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (state_ == State::HALF_OPEN) {
        SecureLogger::instance().info("Service recovered, circuit closed");
        reset();
    }
}

void CircuitBreaker::record_failure(const std::string& error_message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    last_failure_time_ = std::chrono::steady_clock::now();
    
    if (state_ == State::CLOSED) {
        ++failure_count_;
        
        if (failure_count_ >= failure_threshold_) {
            SecureLogger::instance().warning("Failure threshold reached, circuit opened due to: " + error_message);
            state_ = State::OPEN;
        }
    } else if (state_ == State::HALF_OPEN) {
        SecureLogger::instance().warning("Service still failing in half-open state, circuit opened again");
        state_ = State::OPEN;
    }
}

void CircuitBreaker::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    state_ = State::CLOSED;
    failure_count_ = 0;
}

CircuitBreaker::State CircuitBreaker::get_state() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

size_t CircuitBreaker::get_failure_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return failure_count_;
}

} // namespace sdk
} // namespace finaldefi