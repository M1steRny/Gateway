/**
 * @file types.hpp
 * @brief Common type definitions for the Final DeFi SDK
 */

 #pragma once

 #include "finaldefi/sdk/errors.hpp"
 #include "finaldefi/sdk/constants.hpp"
 #include <vector>
 #include <array>
 #include <string>
 #include <optional>
 #include <chrono>
 #include <atomic>
 #include <mutex>
 #include <memory>
 #include <functional>
 #include <unordered_map>
 #include <stdexcept>
 #include <sodium.h>
 #include <oqs/oqs.h>
 #include <openssl/ssl.h>
 
 namespace finaldefi {
 namespace sdk {
 
 /**
  * @brief Result type for operations that can fail
  */
 template<typename T>
 class Result {
 public:
     Result(T value) : value_(std::move(value)), error_(ErrorCode::SUCCESS) {}
     Result(ErrorCode error) : error_(error) {}
     
     bool is_ok() const { return error_ == ErrorCode::SUCCESS; }
     bool is_err() const { return !is_ok(); }
     
     const T& value() const { 
         if (is_err()) {
             throw std::runtime_error("Attempted to access value of an error result");
         }
         return value_; 
     }
     
     ErrorCode error() const { return error_; }
     
     std::string error_message() const {
         return ErrorCodeToString(error_);
     }
     
 private:
     T value_{};
     ErrorCode error_;
 };
 
 // Specialization for void result
 template<>
 class Result<void> {
 public:
     Result() : error_(ErrorCode::SUCCESS) {}
     Result(ErrorCode error) : error_(error) {}
     
     bool is_ok() const { return error_ == ErrorCode::SUCCESS; }
     bool is_err() const { return !is_ok(); }
     
     ErrorCode error() const { return error_; }
     
     std::string error_message() const {
         return ErrorCodeToString(error_);
     }
     
 private:
     ErrorCode error_;
 };
 
 // Common type aliases
 using ByteVector = std::vector<uint8_t>;
 using NodeId = std::array<uint8_t, constants::NODE_ID_SIZE>;
 using TimePoint = std::chrono::system_clock::time_point;
 
 /**
  * @brief Secure container for sensitive data with automatic zeroing
  */
 template<typename T>
 class SecureContainer {
 public:
     SecureContainer() : data_(nullptr), size_(0) {}
     
     explicit SecureContainer(size_t size) : size_(size) {
         data_ = static_cast<T*>(sodium_malloc(sizeof(T) * size));
         if (!data_) {
             throw std::bad_alloc();
         }
         sodium_mlock(data_, sizeof(T) * size);
     }
     
     ~SecureContainer() {
         if (data_) {
             sodium_memzero(data_, sizeof(T) * size_);
             sodium_munlock(data_, sizeof(T) * size_);
             sodium_free(data_);
         }
     }
     
     // Prevent copying
     SecureContainer(const SecureContainer&) = delete;
     SecureContainer& operator=(const SecureContainer&) = delete;
     
     // Allow moving
     SecureContainer(SecureContainer&& other) noexcept : data_(other.data_), size_(other.size_) {
         other.data_ = nullptr;
         other.size_ = 0;
     }
     
     SecureContainer& operator=(SecureContainer&& other) noexcept {
         if (this != &other) {
             if (data_) {
                 sodium_memzero(data_, sizeof(T) * size_);
                 sodium_munlock(data_, sizeof(T) * size_);
                 sodium_free(data_);
             }
             
             data_ = other.data_;
             size_ = other.size_;
             
             other.data_ = nullptr;
             other.size_ = 0;
         }
         return *this;
     }
     
     T* data() { return data_; }
     const T* data() const { return data_; }
     size_t size() const { return size_; }
     
     T& operator[](size_t idx) {
         if (idx >= size_) {
             throw std::out_of_range("SecureContainer index out of range");
         }
         return data_[idx];
     }
     
     const T& operator[](size_t idx) const {
         if (idx >= size_) {
             throw std::out_of_range("SecureContainer index out of range");
         }
         return data_[idx];
     }
     
     // Convert to ByteVector (for interoperability)
     ByteVector to_byte_vector() const {
         return ByteVector(data_, data_ + size_);
     }
     
 private:
     T* data_;
     size_t size_;
 };
 
 // Specialized type aliases
 using SecureBytes = SecureContainer<uint8_t>;
 using SecureString = SecureContainer<char>;
 
 /**
  * @brief Base class for all cryptographic operations
  */
 class CryptoOperation {
 public:
     virtual ~CryptoOperation() = default;
     
     // Get performance metrics
     struct Metrics {
         size_t operations_performed = 0;
         std::chrono::microseconds total_execution_time{0};
         std::chrono::microseconds min_execution_time{std::chrono::microseconds::max()};
         std::chrono::microseconds max_execution_time{0};
         double average_execution_time_us = 0.0;
     };
     
     virtual Metrics get_metrics() const = 0;
     
 protected:
     // Measure execution time
     template<typename F, typename... Args>
     auto measure_execution(F&& func, Args&&... args) -> decltype(func(std::forward<Args>(args)...)) {
         auto start_time = std::chrono::high_resolution_clock::now();
         
         auto result = func(std::forward<Args>(args)...);
         
         auto end_time = std::chrono::high_resolution_clock::now();
         auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
         
         update_metrics(duration);
         
         return result;
     }
     
     // Update metrics
     void update_metrics(std::chrono::microseconds duration) {
         std::lock_guard<std::mutex> lock(metrics_mutex_);
         
         metrics_.operations_performed++;
         metrics_.total_execution_time += duration;
         
         if (duration < metrics_.min_execution_time) {
             metrics_.min_execution_time = duration;
         }
         
         if (duration > metrics_.max_execution_time) {
             metrics_.max_execution_time = duration;
         }
         
         metrics_.average_execution_time_us = 
             static_cast<double>(metrics_.total_execution_time.count()) / 
             metrics_.operations_performed;
     }
     
     Metrics metrics_;
     mutable std::mutex metrics_mutex_;
 };
 
 } // namespace sdk
 } // namespace finaldefi