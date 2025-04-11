#include "finaldefi/sdk/FinalDefiSDK.hpp"
#include "finaldefi/sdk/SecureLogger.hpp"
#include "finaldefi/sdk/KyberEncryption.hpp"
#include "finaldefi/sdk/DilithiumSignature.hpp"
#include "finaldefi/sdk/ThresholdCrypto.hpp"
#include "finaldefi/sdk/MessageCompression.hpp"
#include "finaldefi/sdk/PQNetworking.hpp"
#include <iostream>
#include <fstream>
#include <mutex>
#include <chrono>
#include <thread>
#include <atomic>
#include <random>
#include <sodium.h>
#include <oqs/oqs.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

namespace finaldefi {
namespace sdk {

// Static members
std::unique_ptr<KyberEncryption> FinalDefiSDK::kyber_instance_ = nullptr;
std::unique_ptr<DilithiumSignature> FinalDefiSDK::dilithium_instance_ = nullptr;
std::unique_ptr<ThresholdCrypto> FinalDefiSDK::threshold_instance_ = nullptr;
std::unique_ptr<PQNetworking> FinalDefiSDK::networking_instance_ = nullptr;
std::shared_ptr<ThreadPool> FinalDefiSDK::thread_pool_ = nullptr;
std::mutex FinalDefiSDK::init_mutex_;
std::atomic<bool> FinalDefiSDK::initialized_(false);
boost::uuids::random_generator FinalDefiSDK::uuid_generator_;

// Initialize the SDK
Result<void> FinalDefiSDK::initialize() {
    std::lock_guard<std::mutex> lock(init_mutex_);
    
    if (initialized_) {
        SecureLogger::instance().debug("FinalDefiSDK already initialized");
        return ErrorCode::SUCCESS;
    }

    try {
        // Initialize SecureLogger
        SecureLogger::instance().initialize(constants::LOG_PATH, SecureLogger::LogLevel::INFO);
        SecureLogger::instance().info("Initializing FinalDefiSDK...");

        // Initialize libsodium
        if (sodium_init() == -1) {
            SecureLogger::instance().critical("Failed to initialize libsodium");
            return ErrorCode::INTERNAL_ERROR;
        }
        
        // Lock memory to prevent sensitive data from being swapped
        SecureLogger::instance().info("Locking memory pages to prevent swapping");
        if (mlock(nullptr, 0) == -1) {
            SecureLogger::instance().warning("Failed to lock memory pages: " + std::string(strerror(errno)));
        } else {
            SecureLogger::instance().info("Memory pages locked successfully");
        }

        // Initialize OQS
        OQS_init();
        
        // Initialize components
        kyber_instance_ = std::make_unique<KyberEncryption>();
        auto kyber_result = kyber_instance_->initialize();
        if (kyber_result.is_err()) {
            SecureLogger::instance().critical("Failed to initialize Kyber: " + kyber_result.error_message());
            return kyber_result;
        }
        
        dilithium_instance_ = std::make_unique<DilithiumSignature>();
        auto dilithium_result = dilithium_instance_->initialize();
        if (dilithium_result.is_err()) {
            SecureLogger::instance().critical("Failed to initialize Dilithium: " + dilithium_result.error_message());
            return dilithium_result;
        }
        
        threshold_instance_ = std::make_unique<ThresholdCrypto>();
        
        networking_instance_ = std::make_unique<PQNetworking>();
        auto networking_result = networking_instance_->initialize_ssl();
        if (networking_result.is_err()) {
            SecureLogger::instance().critical("Failed to initialize PQNetworking: " + networking_result.error_message());
            return networking_result;
        }
        
        // Initialize thread pool
        thread_pool_ = std::make_shared<ThreadPool>(constants::DEFAULT_THREAD_POOL_SIZE);
        
        // Set memory protection for the process
        set_memory_protection();
        
        initialized_ = true;
        SecureLogger::instance().info("FinalDefiSDK initialized successfully");
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().critical("Exception during FinalDefiSDK initialization: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Shut down the SDK
Result<void> FinalDefiSDK::shutdown() {
    std::lock_guard<std::mutex> lock(init_mutex_);
    
    if (!initialized_) {
        SecureLogger::instance().debug("FinalDefiSDK not initialized or already shut down");
        return ErrorCode::SUCCESS;
    }
    
    try {
        SecureLogger::instance().info("Shutting down FinalDefiSDK...");
        
        // Release thread pool
        thread_pool_.reset();
        
        // Release networking
        networking_instance_.reset();
        
        // Release threshold crypto
        threshold_instance_.reset();
        
        // Release Dilithium
        dilithium_instance_.reset();
        
        // Release Kyber
        kyber_instance_.reset();
        
        // Clean up OQS
        OQS_cleanup();
        
        initialized_ = false;
        SecureLogger::instance().info("FinalDefiSDK shut down successfully");
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during FinalDefiSDK shutdown: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Generate a Kyber key pair
Result<std::pair<ByteVector, ByteVector>> FinalDefiSDK::generate_kyber_keypair() {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return kyber_instance_->generate_keypair();
}

// Double encapsulate a shared secret for enhanced security
Result<std::pair<std::pair<ByteVector, ByteVector>, ByteVector>> FinalDefiSDK::double_encapsulate(const ByteVector& public_key) {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return kyber_instance_->double_encapsulate(public_key);
}

// Double decapsulate a shared secret
Result<ByteVector> FinalDefiSDK::double_decapsulate(
    const ByteVector& ciphertext1, 
    const ByteVector& ciphertext2, 
    const ByteVector& secret_key) {
    
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return kyber_instance_->double_decapsulate(ciphertext1, ciphertext2, secret_key);
}

// Encrypt data using Kyber-derived key
Result<ByteVector> FinalDefiSDK::encrypt_data(const ByteVector& data, const ByteVector& shared_secret) {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return kyber_instance_->encrypt_data(data, shared_secret);
}

// Decrypt data using Kyber-derived key
Result<ByteVector> FinalDefiSDK::decrypt_data(const ByteVector& ciphertext, const ByteVector& shared_secret) {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return kyber_instance_->decrypt_data(ciphertext, shared_secret);
}

// Generate a Dilithium signature key pair
Result<std::pair<ByteVector, ByteVector>> FinalDefiSDK::generate_dilithium_keypair() {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return dilithium_instance_->generate_keypair();
}

// Sign data using Dilithium
Result<ByteVector> FinalDefiSDK::sign_data(const ByteVector& data, const ByteVector& secret_key) {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return dilithium_instance_->sign(data, secret_key);
}

// Verify a Dilithium signature
Result<bool> FinalDefiSDK::verify_signature(const ByteVector& data, const ByteVector& signature, const ByteVector& public_key) {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return dilithium_instance_->verify(data, signature, public_key);
}

// Generate threshold keys
Result<std::pair<ByteVector, std::vector<ByteVector>>> FinalDefiSDK::generate_threshold_keys(size_t threshold, size_t total) {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return threshold_instance_->generate_threshold_keys(threshold, total);
}

// Combine threshold shares
Result<ByteVector> FinalDefiSDK::combine_threshold_shares(const std::vector<ByteVector>& shares, size_t threshold, size_t total) {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return threshold_instance_->combine_threshold_shares(shares, threshold, total);
}

// Compress data
Result<ByteVector> FinalDefiSDK::compress_data(const ByteVector& data) {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return MessageCompression::compress(data);
}

// Decompress data
Result<ByteVector> FinalDefiSDK::decompress_data(const ByteVector& compressed_data) {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return MessageCompression::decompress(compressed_data);
}

// Create a secure connection
Result<SSL*> FinalDefiSDK::create_secure_connection(const std::string& host, uint16_t port) {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return networking_instance_->create_connection(host, port);
}

// Send data over a secure connection
Result<void> FinalDefiSDK::send_secure_data(SSL* ssl, const ByteVector& data) {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return networking_instance_->send_data(ssl, data);
}

// Receive data over a secure connection
Result<ByteVector> FinalDefiSDK::receive_secure_data(SSL* ssl) {
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    return networking_instance_->receive_data(ssl);
}

// Close a secure connection
void FinalDefiSDK::close_secure_connection(SSL* ssl) {
    if (!initialized_) {
        SecureLogger::instance().warning("FinalDefiSDK not initialized when closing connection");
        return;
    }
    
    networking_instance_->close_connection(ssl);
}

// Enqueue a task in the thread pool
Result<void> FinalDefiSDK::enqueue_task(
    ThreadPool::Priority priority, 
    std::function<void()> task) {
    
    if (!initialized_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    try {
        thread_pool_->enqueue(priority, std::move(task));
        return ErrorCode::SUCCESS;
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception enqueueing task: " + std::string(e.what()));
        return ErrorCode::THREAD_POOL_ERROR;
    }
}

// Generate a random secure UUID
std::string FinalDefiSDK::generate_uuid() {
    if (!initialized_) {
        initialize();
    }
    
    boost::uuids::uuid uuid = uuid_generator_();
    return boost::uuids::to_string(uuid);
}

// Set memory protection for sensitive data
void FinalDefiSDK::set_memory_protection() {
    // Set resource limits to prevent core dumps
    struct rlimit limit;
    limit.rlim_cur = 0;
    limit.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &limit) != 0) {
        SecureLogger::instance().warning("Failed to disable core dumps: " + std::string(strerror(errno)));
    }
    
    // Lock future memory allocations
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        SecureLogger::instance().warning("Failed to lock memory pages: " + std::string(strerror(errno)));
    }
    
    // Set secure permissions on /dev/shm (shared memory)
    chmod("/dev/shm", 0700);
}

// Zero out sensitive memory buffers
void FinalDefiSDK::secure_zero_memory(void* ptr, size_t size) {
    if (ptr) {
        sodium_memzero(ptr, size);
    }
}

// Get thread pool statistics
ThreadPoolStats FinalDefiSDK::get_thread_pool_stats() {
    if (!initialized_) {
        initialize();
    }
    
    ThreadPoolStats stats;
    stats.queued_tasks = thread_pool_->get_queued_tasks();
    stats.active_tasks = thread_pool_->get_active_tasks();
    stats.completed_tasks = thread_pool_->get_completed_tasks();
    stats.thread_count = thread_pool_->get_thread_count();
    
    return stats;
}

} // namespace sdk
} // namespace finaldefi