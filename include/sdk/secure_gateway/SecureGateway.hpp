#pragma once

#include "FinalDefiSDK.hpp"
#include <memory>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

namespace finaldefi {
namespace secure_gateway {

using namespace finaldefi::sdk;

/**
 * @brief Gateway configuration structure
 */
struct GatewayConfig {
    // HTTP server configuration
    std::string http_bind_address;
    uint16_t http_bind_port;
    
    // WebSocket server configuration
    std::string ws_bind_address;
    uint16_t ws_bind_port;
    
    // Node manager configuration
    std::string node_manager_address;
    uint16_t node_manager_port;
    
    // FinalChain configuration
    std::string finalchain_url;
    
    // Gateway identification
    std::string node_name;
    std::array<uint8_t, constants::NODE_ID_SIZE> node_id;
    
    // Quorum parameters
    uint32_t quorum_threshold;
    uint32_t quorum_total;
    
    // Thread pool configuration
    uint32_t thread_pool_size;
    
    // Transaction processing configuration
    uint32_t max_concurrent_tx;
    uint32_t transaction_buffer_size;
    
    // Epoch configuration
    std::chrono::seconds epoch_interval;
    
    // Storage paths
    std::string transaction_store_path;
    std::string attestation_store_path;
    std::string log_path;
    
    // Key rotation interval
    std::chrono::seconds key_rotation_interval;
};

/**
 * @brief Smart queue with high/low water mark support
 */
template<typename T>
class SmartQueue {
public:
    SmartQueue(size_t capacity = std::numeric_limits<size_t>::max())
        : capacity_(capacity), high_water_mark_(capacity * 0.9), low_water_mark_(capacity * 0.7),
          above_high_water_mark_(false) {}
    
    // Set high water mark
    void set_high_water_mark(size_t mark) {
        high_water_mark_ = mark;
    }
    
    // Set low water mark
    void set_low_water_mark(size_t mark) {
        low_water_mark_ = mark;
    }
    
    // Push an item to the queue
    void push(const T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Don't push if we're already at capacity
        if (queue_.size() >= capacity_) {
            return;
        }
        
        queue_.push(item);
        
        // Check if we've crossed the high water mark
        if (!above_high_water_mark_ && queue_.size() >= high_water_mark_) {
            above_high_water_mark_ = true;
        }
        
        // Notify waiters
        cv_.notify_one();
    }
    
    // Push an item to the queue (move version)
    void push(T&& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Don't push if we're already at capacity
        if (queue_.size() >= capacity_) {
            return;
        }
        
        queue_.push(std::move(item));
        
        // Check if we've crossed the high water mark
        if (!above_high_water_mark_ && queue_.size() >= high_water_mark_) {
            above_high_water_mark_ = true;
        }
        
        // Notify waiters
        cv_.notify_one();
    }
    
    // Pop an item from the queue
    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        
        // Wait for an item
        cv_.wait(lock, [this] { return !queue_.empty(); });
        
        T item = std::move(queue_.front());
        queue_.pop();
        
        // Check if we've crossed the low water mark
        if (above_high_water_mark_ && queue_.size() <= low_water_mark_) {
            above_high_water_mark_ = false;
        }
        
        return item;
    }
    
    // Try to pop an item from the queue
    bool try_pop(T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (queue_.empty()) {
            return false;
        }
        
        item = std::move(queue_.front());
        queue_.pop();
        
        // Check if we've crossed the low water mark
        if (above_high_water_mark_ && queue_.size() <= low_water_mark_) {
            above_high_water_mark_ = false;
        }
        
        return true;
    }
    
    // Wait for the queue to be non-empty
    template<typename Rep, typename Period, typename Predicate>
    bool wait_for_non_empty(std::unique_lock<std::mutex>& lock, 
                           const std::chrono::duration<Rep, Period>& timeout,
                           Predicate pred) {
        return cv_.wait_for(lock, timeout, [this, &pred] { 
            return !queue_.empty() || pred(); 
        });
    }
    
    // Check if the queue is above the high water mark
    bool is_above_high_water_mark() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return above_high_water_mark_;
    }
    
    // Get the current size of the queue
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    // Check if the queue is empty
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }
    
    // Notify all waiters
    void notify_all() {
        cv_.notify_all();
    }
    
private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    size_t capacity_;
    size_t high_water_mark_;
    size_t low_water_mark_;
    bool above_high_water_mark_;
};

/**
 * @brief Gateway metrics structure
 */
struct GatewayMetrics {
    // Transaction metrics
    size_t pending_transactions = 0;
    size_t processing_transactions = 0;
    size_t completed_transactions = 0;
    size_t failed_transactions = 0;
    size_t total_submissions = 0;
    
    // Attestation metrics
    size_t total_attestations = 0;
    size_t attestation_queue_size = 0;
    size_t finalchain_submissions = 0;
    
    // Node metrics
    size_t active_nodes = 0;
    size_t total_nodes = 0;
    
    // Epoch metrics
    std::chrono::system_clock::time_point last_epoch_time;
    ByteVector last_batch_root;
    size_t total_epochs = 0;
    
    // Performance metrics
    double average_processing_time_ms = 0.0;
    uint64_t total_processing_time_ms = 0;
    size_t transactions_processed = 0;
    
    // System metrics
    double load_factor = 0.0;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_updated;
};

/**
 * @brief Transaction submission result
 */
struct SubmissionResult {
    bool success;
    std::string message;
    ByteVector transaction_id;
    std::optional<ByteVector> attestation_id;
    std::optional<ByteVector> finalchain_tx_hash;
};

/**
 * @brief Transaction validation result enum
 */
enum class ValidationResult {
    VALID,
    INVALID_SIGNATURE,
    INVALID_FORMAT,
    INVALID_CHAIN,
    INVALID_SENDER,
    REJECTED_BY_QUORUM,
    INTERNAL_ERROR
};

/**
 * @brief Transaction validation info
 */
struct ValidationInfo {
    ValidationResult result;
    std::string message;
    ByteVector transaction_id;
    std::optional<ByteVector> attestation_id;
};

/**
 * @brief Secure Gateway implementation
 */
class SecureGateway {
public:
    // Constructor
    SecureGateway(const GatewayConfig& config);
    
    // Destructor
    ~SecureGateway();
    
    // Initialize the Secure Gateway
    Result<void> initialize();
    
    // Start the Secure Gateway
    Result<void> start();
    
    // Stop the Secure Gateway
    Result<void> stop();
    
    // Submit a transaction
    Result<SubmissionResult> submit_transaction(const Transaction& transaction);
    
    // Verify transaction intent
    Result<ValidationInfo> verify_transaction_intent(
        const Transaction& transaction, 
        const ByteVector& signature);
    
    // Get the status of a transaction
    Result<Transaction> get_transaction_status(const ByteVector& transaction_id);
    
    // Get all transactions
    Result<std::vector<Transaction>> get_all_transactions();
    
    // Get transactions by status
    Result<std::vector<Transaction>> get_transactions_by_status(Transaction::Status status);
    
    // Get an attestation by ID
    Result<Attestation> get_attestation(const ByteVector& attestation_id);
    
    // Get all attestations
    Result<std::vector<Attestation>> get_all_attestations();
    
    // Generate a UI keypair
    Result<std::pair<ByteVector, ByteVector>> generate_ui_keypair();
    
    // Get gateway metrics
    GatewayMetrics get_metrics() const;
    
private:
    // Gateway state
    enum class State {
        UNINITIALIZED,
        INITIALIZED,
        RUNNING,
        STOPPED
    };
    
    // Constants
    static constexpr size_t MAX_ATTESTATIONS_PER_EPOCH = 1000;
    static constexpr size_t MAX_CONNECTION_HOSTS = 16;
    static constexpr size_t MAX_CONNECTIONS_PER_HOST = 8;
    static constexpr std::chrono::seconds CONNECTION_STALE_THRESHOLD = std::chrono::seconds(300);
    
    // Configuration
    GatewayConfig config_;
    
    // State
    State state_;
    std::mutex state_mutex_;
    std::atomic<bool> running_{false};
    
    // Cryptographic keys
    std::pair<ByteVector, ByteVector> gateway_keys_; // Kyber public/secret key pair
    std::pair<ByteVector, ByteVector> signature_keys_; // Dilithium public/secret key pair
    std::chrono::steady_clock::time_point key_creation_time_;
    
    // Transaction queue
    SmartQueue<Transaction> pending_transactions_queue_;
    std::mutex pending_queue_mutex_;
    
    // Attestation buffer
    SmartQueue<Attestation> attestation_buffer_;
    
    // Shared components
    std::shared_ptr<TransactionStore> transaction_store_;
    std::shared_ptr<AttestationStore> attestation_store_;
    std::shared_ptr<NodeRegistry> node_registry_;
    std::shared_ptr<ThreadPool> thread_pool_;
    
    // Worker threads
    std::vector<std::thread> worker_threads_;
    std::thread key_rotation_thread_;
    std::thread node_manager_sync_thread_;
    std::thread epoch_processing_thread_;
    std::thread node_heartbeat_thread_;
    std::thread connection_pool_maintenance_thread_;
    std::thread metrics_thread_;
    
    // Metrics
    mutable std::mutex metrics_mutex_;
    GatewayMetrics metrics_;
    std::chrono::steady_clock::time_point last_metrics_update_;
    
    // Connection pool
    std::unordered_map<std::string, std::queue<std::pair<SSL*, std::chrono::steady_clock::time_point>>> connection_pool_;
    std::vector<std::unique_ptr<std::mutex>> connection_pool_mutexes_;
    
    // Circuit breakers
    CircuitBreaker transaction_circuit_breaker_;
    CircuitBreaker validation_circuit_breaker_;
    CircuitBreaker attestation_circuit_breaker_;
    CircuitBreaker network_circuit_breaker_;
    
    // Process a transaction submission
    SubmissionResult process_transaction_submission(const Transaction& transaction);
    
    // Process a transaction verification request
    ValidationInfo process_transaction_verification(
        const Transaction& transaction, 
        const ByteVector& signature);
    
    // Process a transaction
    void process_transaction(Transaction& tx);
    
    // Submit a transaction to a light agent
    Result<std::optional<ByteVector>> submit_to_light_agent(const Transaction& tx);
    
    // Submit a transaction to a specific light agent
    Result<std::optional<ByteVector>> submit_to_specific_light_agent(
        const Transaction& tx, 
        const NodeInfo& node);
    
    // Get the best nodes for a specific chain
    Result<std::vector<NodeInfo>> get_best_nodes_for_chain(uint32_t chain_id);
    
    // Generate a transaction attestation
    Result<Attestation> generate_transaction_attestation(const Transaction& tx);
    
    // Generate an intent attestation
    Result<Attestation> generate_intent_attestation(
        const Transaction& tx, 
        const ByteVector& signature);
    
    // Generate a completion attestation
    Result<Attestation> generate_completion_attestation(const Transaction& tx);
    
    // Process an epoch of transactions
    void process_epoch();
    
    // Process a batch of transaction attestations
    void process_transaction_batch(const std::vector<Attestation>& attestations);
    
    // Create an epoch attestation
    Result<Attestation> create_epoch_attestation(const std::vector<Attestation>& attestations);
    
    // Submit an attestation to FinalChain
    void submit_attestation_to_finalchain(const Attestation& attestation);
    
    // Get quorum signatures from other nodes
    Result<std::vector<std::pair<NodeId, ByteVector>>> get_quorum_signatures(const ByteVector& data);
    
    // Request a signature from a specific node
    Result<ByteVector> request_signature_from_node(
        const ByteVector& data, 
        const NodeInfo& node);
    
    // Verify a transaction with quorum
    Result<void> verify_transaction_quorum(const Transaction& transaction);
    
    // Get quorum verification from nodes
    Result<void> get_quorum_verification(
        const ByteVector& tx_hash, 
        const ByteVector& tx_id,
        uint32_t chain_id);
    
    // Request verification from a specific node
    Result<void> request_verification_from_node(
        const ByteVector& tx_hash, 
        const ByteVector& tx_id,
        const NodeInfo& node);
    
    // Initialize cryptographic keys
    Result<void> initialize_cryptographic_keys();
    
    // Register with node manager
    Result<void> register_with_node_manager();
    
    // Initialize connection pool
    void initialize_connection_pool();
    
    // Start worker threads
    void start_worker_threads();
    
    // Start key rotation timer
    void start_key_rotation_timer();
    
    // Start node manager synchronization
    void start_node_manager_sync();
    
    // Start epoch processing
    void start_epoch_processing();
    
    // Start node heartbeat
    void start_node_heartbeat();
    
    // Start connection pool maintenance
    void start_connection_pool_maintenance();
    
    // Start metrics collection
    void start_metrics_collection();
    
    // Transaction processing thread
    void process_transactions_thread();
    
    // Update metrics
    void update_metrics();
    
    // Verify chain ID is supported
    Result<void> verify_chain_id(uint32_t chain_id);
    
    // Send heartbeat to node manager
    void send_heartbeat();
    
    // Update node load with node manager
    void update_node_load(double load_factor);
    
    // Sync with node manager
    void sync_with_node_manager();
    
    // Rotate cryptographic keys
    void rotate_keys();
    
    // Generate key rotation attestation
    Result<Attestation> generate_key_rotation_attestation();
    
    // Update node keys with node manager
    Result<void> update_node_keys();
    
    // Register a node with the node manager
    Result<void> register_node_with_manager(const NodeInfo& node);
    
    // Save keys to disk
    Result<void> save_keys();
    
    // Encrypt keys for storage
    Result<ByteVector> encrypt_keys(const ByteVector& data);
    
    // Decrypt keys from storage
    Result<std::pair<std::pair<ByteVector, ByteVector>, std::pair<ByteVector, ByteVector>>> 
    decrypt_keys(const ByteVector& encrypted_data);
    
    // Get or create a connection from the connection pool
    Result<SSL*> get_or_create_connection(const std::string& host, uint16_t port);
    
    // Return a connection to the pool
    void return_connection_to_pool(const std::string& host, uint16_t port, SSL* ssl);
    
    // Clean up stale connections in the pool
    void cleanup_stale_connections();
    
    // Close all connections in the pool
    void close_all_connections();
    
    // Initialize the metrics
    void initialize_metrics();
    
    // Get the local machine's address
    std::string get_local_address() const;
    
    // Helper functions for byte conversion
    std::string bytes_to_hex(const ByteVector& bytes) const;
    ByteVector hex_to_bytes(const std::string& hex) const;
};

} // namespace secure_gateway
} // namespace finaldefi