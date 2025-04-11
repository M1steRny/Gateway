/**
 * @file SecureLogger.hpp
 * @brief Secure logging facility with different log levels and rotation
 */

 #pragma once

 #include "finaldefi/sdk/constants.hpp"
 #include <string>
 #include <mutex>
 #include <fstream>
 #include <chrono>
 #include <filesystem>
 
 namespace finaldefi {
 namespace sdk {
 
 /**
  * @brief Secure logging facility with different log levels and rotation
  */
 class SecureLogger {
 public:
     enum class LogLevel {
         TRACE,
         DEBUG,
         INFO,
         WARNING,
         ERROR,
         CRITICAL
     };
     
     /**
      * @brief Get the singleton instance of the logger
      * @return Reference to the singleton instance
      */
     static SecureLogger& instance();
     
     /**
      * @brief Initialize the logger
      * @param log_path Path to store log files
      * @param min_level Minimum log level to record
      */
     void initialize(const std::string& log_path = constants::LOG_PATH, 
                    LogLevel min_level = LogLevel::INFO);
     
     /**
      * @brief Log a message with a specific level
      * @param level Log level
      * @param message Message to log
      */
     void log(LogLevel level, const std::string& message);
     
     /**
      * @brief Format and log a message with a specific level
      * @param level Log level
      * @param format Format string
      * @param args Format arguments
      */
     template <typename... Args>
     void logf(LogLevel level, const char* format, Args... args);
     
     // Convenience methods for different log levels
     void trace(const std::string& message);
     void debug(const std::string& message);
     void info(const std::string& message);
     void warning(const std::string& message);
     void error(const std::string& message);
     void critical(const std::string& message);
     
     /**
      * @brief Destructor
      */
     ~SecureLogger();
     
     /**
      * @brief Get the current log level
      * @return Current log level
      */
     LogLevel get_log_level() const { return min_level_; }
     
     /**
      * @brief Set the log level
      * @param level New log level
      */
     void set_log_level(LogLevel level) { min_level_ = level; }
     
     /**
      * @brief Check if a log level is enabled
      * @param level Log level to check
      * @return True if the log level is enabled, false otherwise
      */
     bool is_level_enabled(LogLevel level) const { return level >= min_level_; }
     
     /**
      * @brief Get the current log path
      * @return Current log path
      */
     std::string get_log_path() const { return log_path_; }
     
     /**
      * @brief Flush log buffers
      */
     void flush();
     
 private:
     // Private constructor for singleton
     SecureLogger();
     
     // Delete copy constructor and assignment operator
     SecureLogger(const SecureLogger&) = delete;
     SecureLogger& operator=(const SecureLogger&) = delete;
     
     // Internal log implementation
     void log_internal(LogLevel level, const std::string& message);
     
     // Check and rotate log files if needed
     void check_and_rotate_log();
     
     // Convert log level to string
     static std::string level_to_string(LogLevel level);
     
     // Get current timestamp
     static std::string get_current_timestamp(const char* format = "%Y-%m-%d %H:%M:%S");
     
     // Singleton instance
     static std::mutex instance_mutex_;
     static SecureLogger* instance_;
     
     // Logger state
     std::mutex log_mutex_;
     std::ofstream log_file_;
     std::string log_path_;
     LogLevel min_level_ = LogLevel::INFO;
     bool initialized_ = false;
     uint64_t log_count_ = 0;
     std::chrono::system_clock::time_point last_rotation_time_;
     size_t max_log_file_size_ = 10 * 1024 * 1024; // 10 MB
     uint32_t max_log_files_ = 10;
 };
 
 } // namespace sdk
 } // namespace finaldefi