#include "finaldefi/sdk/SecureLogger.hpp"
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <mutex>

namespace finaldefi {
namespace sdk {

// Initialize static variables
std::mutex SecureLogger::instance_mutex_;
SecureLogger* SecureLogger::instance_ = nullptr;

// Get singleton instance
SecureLogger& SecureLogger::instance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = new SecureLogger();
    }
    return *instance_;
}

// Constructor
SecureLogger::SecureLogger() 
    : min_level_(LogLevel::INFO), 
      log_path_(constants::LOG_PATH),
      initialized_(false) {
}

// Destructor
SecureLogger::~SecureLogger() {
    std::lock_guard<std::mutex> lock(log_mutex_);
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

// Initialize the logger
void SecureLogger::initialize(const std::string& log_path, LogLevel min_level) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    if (initialized_) {
        log_internal(LogLevel::INFO, "Logger already initialized, reinitializing with new parameters");
    }
    
    log_path_ = log_path;
    min_level_ = min_level;
    
    // Create log directory if it doesn't exist
    std::filesystem::create_directories(log_path_);
    
    // Open log file
    std::string filename = log_path_ + "/secure_gateway_" + 
                          get_current_timestamp("%Y%m%d_%H%M%S") + ".log";
    
    if (log_file_.is_open()) {
        log_file_.close();
    }
    
    log_file_.open(filename, std::ios::out | std::ios::app);
    
    if (!log_file_.is_open()) {
        // If we can't open the log file, try to create a fallback in the current directory
        log_file_.open("secure_gateway.log", std::ios::out | std::ios::app);
    }
    
    initialized_ = true;
    log_internal(LogLevel::INFO, "SecureLogger initialized");
}

// Log a message with specific level
void SecureLogger::log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_internal(level, message);
}

// Format a log message
template <typename... Args>
void SecureLogger::logf(LogLevel level, const char* format, Args... args) {
    char buffer[2048];
    snprintf(buffer, sizeof(buffer), format, args...);
    log(level, std::string(buffer));
}

// Trace level log
void SecureLogger::trace(const std::string& message) {
    log(LogLevel::TRACE, message);
}

// Debug level log
void SecureLogger::debug(const std::string& message) {
    log(LogLevel::DEBUG, message);
}

// Info level log
void SecureLogger::info(const std::string& message) {
    log(LogLevel::INFO, message);
}

// Warning level log
void SecureLogger::warning(const std::string& message) {
    log(LogLevel::WARNING, message);
}

// Error level log
void SecureLogger::error(const std::string& message) {
    log(LogLevel::ERROR, message);
}

// Critical level log
void SecureLogger::critical(const std::string& message) {
    log(LogLevel::CRITICAL, message);
}

// Internal log implementation
void SecureLogger::log_internal(LogLevel level, const std::string& message) {
    if (level < min_level_ || !log_file_.is_open()) {
        return;
    }
    
    // Check if we need to rotate the log file
    check_and_rotate_log();
    
    // Write log entry
    log_file_ << "[" << get_current_timestamp() << "] [" << level_to_string(level) << "] " 
             << message << std::endl;
    log_file_.flush();
    
    // Also output to stderr for critical and error messages
    if (level >= LogLevel::ERROR) {
        std::cerr << "[" << get_current_timestamp() << "] [" << level_to_string(level) << "] " 
                 << message << std::endl;
    }
}

// Check and rotate log files if needed
void SecureLogger::check_and_rotate_log() {
    // Rotate logs based on file size (10MB)
    if (log_file_.tellp() >= 10 * 1024 * 1024) {
        log_file_.close();
        
        std::string filename = log_path_ + "/secure_gateway_" + 
                               get_current_timestamp("%Y%m%d_%H%M%S") + ".log";
        log_file_.open(filename, std::ios::out | std::ios::app);
        
        if (!log_file_.is_open()) {
            // Fallback
            log_file_.open("secure_gateway.log", std::ios::out | std::ios::app);
        }
    }
}

// Convert log level to string
std::string SecureLogger::level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

// Get current timestamp
std::string SecureLogger::get_current_timestamp(const char* format) {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    
    std::tm tm_now;
    localtime_r(&time_t_now, &tm_now);
    
    char buffer[128];
    strftime(buffer, sizeof(buffer), format, &tm_now);
    
    return std::string(buffer);
}

} // namespace sdk
} // namespace finaldefi