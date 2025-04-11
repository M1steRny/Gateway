#include "SecureGateway.hpp"
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <thread>
#include <random>
#include <cstring>
#include <sys/mman.h>
#include <sys/resource.h>

namespace finaldefi {
namespace secure_gateway {

using namespace std::chrono_literals;

// Constructor
SecureGateway::SecureGateway(const GatewayConfig& config)
    : config_(config), 
      state_(State::UNINITIALIZED),
      attestation_buffer_(config.transaction_buffer_size),
      transaction_circuit_breaker_(constants::CIRCUIT_BREAKER_THRESHOLD, constants::CIRCUIT_BREAKER_RESET_TIMEOUT),
      validation_circuit_breaker_(constants::CIRCUIT_BREAKER_THRESHOLD, constants::CIRCUIT_BREAKER_RESET_TIMEOUT),
      attestation_circuit_breaker_(constants::CIRCUIT_BREAKER_THRESHOLD, constants::CIRCUIT_BREAKER_RESET_TIMEOUT),
      network_circuit_breaker_(constants::CIRCUIT_BREAKER_THRESHOLD, constants::CIRCUIT_BREAKER_RESET_TIMEOUT) {
    
    // Set priority for the process
    setpriority(PRIO_PROCESS, 0, -10);
    
    // Lock memory to prevent sensitive data from being swapped
    SecureLogger::instance().info("Attempting to lock memory pages to prevent swapping");
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        SecureLogger::instance().warning("Failed to lock memory pages: " + std::string(strerror(errno)));
    } else {
        SecureLogger::instance().info("Successfully locked memory pages");
    }
    
    // Initialize the async processing queues with high/low water marks
    pending_transactions_queue_.set_high_water_mark(config.transaction_buffer_size * 0.9);
    pending_transactions_queue_.set_low_water_mark(config.transaction_buffer_size * 0.7);
    
    // Set up metrics collection
    last_metrics_update_ = std::chrono::steady_clock::now();
}

// Destructor
SecureGateway::~SecureGateway() {
    stop();
}

// Initialize the Secure Gateway
Result<void> SecureGateway::initialize() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    if (state_ != State::UNINITIALIZED) {
        SecureLogger::instance().error("Secure Gateway already initialized");
        return ErrorCode::INTERNAL_ERROR;
    }
    
    SecureLogger::instance().info("Initializing Secure Gateway...");
    
    try {
        // Initialize the FinalDeFi SDK
        auto sdk_result = FinalDefiSDK::instance().initialize();
        if (sdk_result.is_err()) {
            SecureLogger::instance().error("Failed to initialize FinalDeFi SDK: " + sdk_result.error_message());
            return sdk_result.error();
        }
        
        // Initialize transaction store
        transaction_store_ = std::make_shared<TransactionStore>(config_.transaction_store_path);
        
        // Initialize attestation store
        attestation_store_ = std::make_shared<AttestationStore>(config_.attestation_store_path);
        
        // Initialize node registry
        node_registry_ = std::make_shared<NodeRegistry>();
        
        // Initialize thread pool
        thread_pool_ = std::make_shared<ThreadPool>(config_.thread_pool_size);
        
        // Generate or load cryptographic keys
        auto keys_result = initialize_cryptographic_keys();
        if (keys_result.is_err()) {
            SecureLogger::instance().error("Failed to initialize cryptographic keys: " + keys_result.error_message());
            return keys_result.error();
        }
        
        // Register with node manager if configured
        if (!config_.node_manager_address.empty()) {
            auto reg_result = register_with_node_manager();
            if (reg_result.is_err()) {
                SecureLogger::instance().error("Failed to register with node manager: " + reg_result.error_message());
                return reg_result.error();
            }
        } else {
            SecureLogger::instance().info("No node manager configured, operating in standalone mode");
        }
        
        // Initialize connection pool for communications
        initialize_connection_pool();
        
        // Initialize metrics collection
        initialize_metrics();
        
        // Set state to initialized
        state_ = State::INITIALIZED;
        
        SecureLogger::instance().info("Secure Gateway initialized successfully");
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during initialization: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Start the Secure Gateway
Result<void> SecureGateway::start() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    if (state_ == State::UNINITIALIZED) {
        SecureLogger::instance().error("Secure Gateway not initialized");
        return ErrorCode::INTERNAL_ERROR;
    }
    
    if (state_ == State::RUNNING) {
        SecureLogger::instance().warning("Secure Gateway already running");
        return ErrorCode::SUCCESS;
    }
    
    SecureLogger::instance().info("Starting Secure Gateway...");
    
    try {
        // Set running flag
        running_ = true;
        
        // Start worker threads
        start_worker_threads();
        
        // Start key rotation timer
        start_key_rotation_timer();
        
        // Start node manager synchronization
        if (!config_.node_manager_address.empty()) {
            start_node_manager_sync();
        }
        
        // Start epoch processing
        start_epoch_processing();
        
        // Start node heartbeat
        start_node_heartbeat();
        
        // Start connection pool maintenance
        start_connection_pool_maintenance();
        
        // Start metrics collection
        start_metrics_collection();
        
        // Set state to running
        state_ = State::RUNNING;
        
        SecureLogger::instance().info("Secure Gateway started successfully");
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during startup: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Stop the Secure Gateway
Result<void> SecureGateway::stop() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    if (state_ == State::STOPPED || state_ == State::UNINITIALIZED) {
        return ErrorCode::SUCCESS;
    }
    
    SecureLogger::instance().info("Stopping Secure Gateway...");
    
    try {
        // Set running flag to false
        running_ = false;
        
        // Notify all condition variables
        pending_transactions_queue_.notify_all();
        
        // Stop worker threads
        for (auto& thread : worker_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        worker_threads_.clear();
        
        // Stop key rotation timer
        if (key_rotation_thread_.joinable()) {
            key_rotation_thread_.join();
        }
        
        // Stop node manager sync
        if (node_manager_sync_thread_.joinable()) {
            node_manager_sync_thread_.join();
        }
        
        // Stop epoch processing
        if (epoch_processing_thread_.joinable()) {
            epoch_processing_thread_.join();
        }
        
        // Stop node heartbeat
        if (node_heartbeat_thread_.joinable()) {
            node_heartbeat_thread_.join();
        }
        
        // Stop connection pool maintenance
        if (connection_pool_maintenance_thread_.joinable()) {
            connection_pool_maintenance_thread_.join();
        }
        
        // Stop metrics collection
        if (metrics_thread_.joinable()) {
            metrics_thread_.join();
        }
        
        // Close all connections in the pool
        close_all_connections();
        
        // Set state to stopped
        state_ = State::STOPPED;
        
        SecureLogger::instance().info("Secure Gateway stopped successfully");
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during shutdown: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Submit a transaction
Result<SubmissionResult> SecureGateway::submit_transaction(const Transaction& transaction) {
    if (state_ != State::RUNNING) {
        SecureLogger::instance().error("Secure Gateway not running");
        return ErrorCode::INTERNAL_ERROR;
    }
    
    // Check if queue is full
    if (pending_transactions_queue_.size() >= config_.transaction_buffer_size) {
        SecureLogger::instance().error("Transaction buffer full, rejecting transaction");
        return ErrorCode::INTERNAL_ERROR;
    }
    
    try {
        // Return value with circuit breaker protection
        return transaction_circuit_breaker_.execute<SubmissionResult>([&]() {
            return process_transaction_submission(transaction);
        });
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during transaction submission: " + std::string(e.what()));
        transaction_circuit_breaker_.record_failure(e.what());
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Verify transaction intent
Result<ValidationInfo> SecureGateway::verify_transaction_intent(
    const Transaction& transaction, 
    const ByteVector& signature) {
    
    if (state_ != State::RUNNING) {
        SecureLogger::instance().error("Secure Gateway not running");
        return ErrorCode::INTERNAL_ERROR;
    }
    
    try {
        // Return value with circuit breaker protection
        return validation_circuit_breaker_.execute<ValidationInfo>([&]() {
            return process_transaction_verification(transaction, signature);
        });
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during transaction verification: " + std::string(e.what()));
        validation_circuit_breaker_.record_failure(e.what());
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Get the status of a transaction
Result<Transaction> SecureGateway::get_transaction_status(const ByteVector& transaction_id) {
    if (state_ != State::RUNNING) {
        SecureLogger::instance().error("Secure Gateway not running");
        return ErrorCode::INTERNAL_ERROR;
    }
    
    try {
        return transaction_store_->load_transaction(transaction_id);
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during transaction status retrieval: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Get all transactions
Result<std::vector<Transaction>> SecureGateway::get_all_transactions() {
    if (state_ != State::RUNNING) {
        SecureLogger::instance().error("Secure Gateway not running");
        return ErrorCode::INTERNAL_ERROR;
    }
    
    try {
        return transaction_store_->get_all_transactions();
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during transaction retrieval: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Get transactions by status
Result<std::vector<Transaction>> SecureGateway::get_transactions_by_status(Transaction::Status status) {
    if (state_ != State::RUNNING) {
        SecureLogger::instance().error("Secure Gateway not running");
        return ErrorCode::INTERNAL_ERROR;
    }
    
    try {
        return transaction_store_->get_transactions_by_status(status);
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during transaction retrieval: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Get an attestation by ID
Result<Attestation> SecureGateway::get_attestation(const ByteVector& attestation_id) {
    if (state_ != State::RUNNING) {
        SecureLogger::instance().error("Secure Gateway not running");
        return ErrorCode::INTERNAL_ERROR;
    }
    
    try {
        return attestation_store_->load_attestation(attestation_id);
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during attestation retrieval: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Get all attestations
Result<std::vector<Attestation>> SecureGateway::get_all_attestations() {
    if (state_ != State::RUNNING) {
        SecureLogger::instance().error("Secure Gateway not running");
        return ErrorCode::INTERNAL_ERROR;
    }
    
    try {
        return attestation_store_->get_all_attestations();
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during attestation retrieval: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Generate a UI keypair
Result<std::pair<ByteVector, ByteVector>> SecureGateway::generate_ui_keypair() {
    if (state_ != State::RUNNING) {
        SecureLogger::instance().error("Secure Gateway not running");
        return ErrorCode::INTERNAL_ERROR;
    }
    
    try {
        return FinalDefiSDK::instance().generate_dilithium_keypair();
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during UI keypair generation: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Get gateway metrics
GatewayMetrics SecureGateway::get_metrics() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    return metrics_;
}

// Process a transaction submission
SubmissionResult SecureGateway::process_transaction_submission(const Transaction& transaction) {
    // Create a mutable copy of the transaction
    Transaction tx = transaction;
    
    // Generate a transaction ID if not provided
    if (tx.id.empty()) {
        tx.id = Transaction::generate_id();
    }
    
    // Set timestamp if not provided
    if (tx.timestamp == 0) {
        tx.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }
    
    // Calculate transaction hash
    ByteVector tx_hash = tx.calculate_hash();
    
    // Verify user signature
    auto verify_result = FinalDefiSDK::instance().verify_signature(
        tx_hash, tx.user_signature, tx.sender_public_key);
    
    if (verify_result.is_err() || !verify_result.value()) {
        SecureLogger::instance().error("Invalid user signature for transaction");
        
        SubmissionResult result;
        result.success = false;
        result.message = "Invalid user signature";
        result.transaction_id = tx.id;
        
        return result;
    }
    
    // Sign with gateway key
    auto sign_result = FinalDefiSDK::instance().sign_data(tx_hash, gateway_keys_.second);
    if (sign_result.is_err()) {
        SecureLogger::instance().error("Failed to sign transaction: " + sign_result.error_message());
        
        SubmissionResult result;
        result.success = false;
        result.message = "Failed to sign transaction";
        result.transaction_id = tx.id;
        
        return result;
    }
    
    tx.gateway_signature = sign_result.value();
    
    // Set transaction status
    tx.status = Transaction::Status::PENDING;
    
    // Store transaction
    auto store_result = transaction_store_->store_transaction(tx);
    if (store_result.is_err()) {
        SecureLogger::instance().error("Failed to store transaction: " + store_result.error_message());
        
        SubmissionResult result;
        result.success = false;
        result.message = "Failed to store transaction";
        result.transaction_id = tx.id;
        
        return result;
    }
    
    // Generate attestation
    auto attestation_result = generate_transaction_attestation(tx);
    if (attestation_result.is_err()) {
        SecureLogger::instance().error("Failed to generate attestation: " + attestation_result.error_message());
        
        SubmissionResult result;
        result.success = false;
        result.message = "Failed to generate attestation";
        result.transaction_id = tx.id;
        
        return result;
    }
    
    Attestation attestation = attestation_result.value();
    
    // Store attestation
    auto att_store_result = attestation_store_->store_attestation(attestation);
    if (att_store_result.is_err()) {
        SecureLogger::instance().error("Failed to store attestation: " + att_store_result.error_message());
        
        SubmissionResult result;
        result.success = false;
        result.message = "Failed to store attestation";
        result.transaction_id = tx.id;
        
        return result;
    }
    
    // Add attestation to the buffer for eventual FinalChain submission
    attestation_buffer_.push(attestation);
    
    // Submit the transaction for processing
    std::lock_guard<std::mutex> lock(pending_queue_mutex_);
    pending_transactions_queue_.push(tx);
    
    // Update metrics
    {
        std::lock_guard<std::mutex> metrics_lock(metrics_mutex_);
        metrics_.pending_transactions++;
        metrics_.total_submissions++;
    }
    
    // Prepare result
    SubmissionResult result;
    result.success = true;
    result.message = "Transaction submitted successfully";
    result.transaction_id = tx.id;
    result.attestation_id = attestation.id;
    
    // If already received a FinalChain hash from a similar attestation, include it
    auto tx_attestations = attestation_store_->get_attestations_by_entity_id(tx.id);
    if (tx_attestations.is_ok()) {
        for (const auto& att : tx_attestations.value()) {
            auto it = att.metadata.find("finalchain_tx_hash");
            if (it != att.metadata.end()) {
                result.finalchain_tx_hash = hex_to_bytes(it->second);
                break;
            }
        }
    }
    
    SecureLogger::instance().info("Transaction submitted successfully: " + bytes_to_hex(tx.id));
    
    return result;
}

// Process a transaction verification request
ValidationInfo SecureGateway::process_transaction_verification(
    const Transaction& transaction, 
    const ByteVector& signature) {
    
    ValidationInfo info;
    info.transaction_id = transaction.id;
    
    // Calculate transaction hash
    ByteVector tx_hash = transaction.calculate_hash();
    
    // Verify user signature
    auto verify_result = FinalDefiSDK::instance().verify_signature(
        tx_hash, signature, transaction.sender_public_key);
    
    if (verify_result.is_err()) {
        info.result = ValidationResult::INTERNAL_ERROR;
        info.message = "Error verifying signature: " + verify_result.error_message();
        return info;
    }
    
    if (!verify_result.value()) {
        info.result = ValidationResult::INVALID_SIGNATURE;
        info.message = "Invalid signature";
        return info;
    }
    
    // Verify chain ID
    auto chain_id_verify_result = verify_chain_id(transaction.chain_id);
    if (chain_id_verify_result.is_err()) {
        info.result = ValidationResult::INVALID_CHAIN;
        info.message = "Invalid chain ID: " + chain_id_verify_result.error_message();
        return info;
    }
    
    // Get quorum verification for this transaction
    auto quorum_result = verify_transaction_quorum(transaction);
    if (quorum_result.is_err()) {
        info.result = ValidationResult::REJECTED_BY_QUORUM;
        info.message = "Rejected by quorum: " + quorum_result.error_message();
        return info;
    }
    
    // Generate attestation for intent verification
    auto attestation_result = generate_intent_attestation(transaction, signature);
    if (attestation_result.is_err()) {
        info.result = ValidationResult::INTERNAL_ERROR;
        info.message = "Failed to generate attestation: " + attestation_result.error_message();
        return info;
    }
    
    Attestation attestation = attestation_result.value();
    
    // Store attestation
    auto att_store_result = attestation_store_->store_attestation(attestation);
    if (att_store_result.is_err()) {
        info.result = ValidationResult::INTERNAL_ERROR;
        info.message = "Failed to store attestation: " + att_store_result.error_message();
        return info;
    }
    
    // Add to attestation buffer
    attestation_buffer_.push(attestation);
    
    // Fill result info
    info.result = ValidationResult::VALID;
    info.message = "Transaction intent verified";
    info.attestation_id = attestation.id;
    
    SecureLogger::instance().info("Transaction intent verified: " + bytes_to_hex(transaction.id));
    
    return info;
}

// Initialize cryptographic keys
Result<void> SecureGateway::initialize_cryptographic_keys() {
    try {
        std::string secret_file = constants::SECRET_FILE_PATH;
        bool has_existing_keys = std::filesystem::exists(secret_file);
        
        if (has_existing_keys) {
            SecureLogger::instance().info("Loading existing keys from " + secret_file);
            
            // Read the encrypted keys
            std::ifstream file(secret_file, std::ios::binary | std::ios::ate);
            if (!file) {
                SecureLogger::instance().error("Failed to open secret file: " + secret_file);
                return ErrorCode::FILE_IO_ERROR;
            }
            
            // Get file size
            size_t size = file.tellg();
            file.seekg(0, std::ios::beg);
            
            // Read encrypted data
            ByteVector encrypted_data(size);
            if (!file.read(reinterpret_cast<char*>(encrypted_data.data()), size)) {
                SecureLogger::instance().error("Failed to read secret file: " + secret_file);
                return ErrorCode::FILE_IO_ERROR;
            }
            
            file.close();
            
            // Decrypt the keys
            auto keys_result = decrypt_keys(encrypted_data);
            if (keys_result.is_err()) {
                SecureLogger::instance().error("Failed to decrypt keys: " + keys_result.error_message());
                return keys_result.error();
            }
            
            auto [kyber_keys, dilithium_keys] = keys_result.value();
            
            // Set the keys
            gateway_keys_ = kyber_keys;
            signature_keys_ = dilithium_keys;
            
            SecureLogger::instance().info("Keys loaded successfully");
            
        } else {
            SecureLogger::instance().info("Generating new keys");
            
            // Generate Kyber keypair for gateway
            auto kyber_result = FinalDefiSDK::instance().generate_kyber_keypair();
            if (kyber_result.is_err()) {
                SecureLogger::instance().error("Failed to generate Kyber keypair: " + kyber_result.error_message());
                return kyber_result.error();
            }
            
            gateway_keys_ = kyber_result.value();
            
            // Generate Dilithium keypair for signatures
            auto dilithium_result = FinalDefiSDK::instance().generate_dilithium_keypair();
            if (dilithium_result.is_err()) {
                SecureLogger::instance().error("Failed to generate Dilithium keypair: " + dilithium_result.error_message());
                return dilithium_result.error();
            }
            
            signature_keys_ = dilithium_result.value();
            
            // Save the keys
            auto save_result = save_keys();
            if (save_result.is_err()) {
                SecureLogger::instance().error("Failed to save keys: " + save_result.error_message());
                return save_result.error();
            }
            
            SecureLogger::instance().info("New keys generated and saved successfully");
        }
        
        // Set key creation time
        key_creation_time_ = std::chrono::steady_clock::now();
        
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during key initialization: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Register with node manager
Result<void> SecureGateway::register_with_node_manager() {
    try {
        SecureLogger::instance().info("Registering with node manager at " + 
                               config_.node_manager_address + ":" + 
                               std::to_string(config_.node_manager_port));
        
        // Create NodeInfo structure
        NodeInfo node;
        node.id = config_.node_id;
        node.hostname = get_local_address();
        node.port = config_.http_bind_port;
        node.kyber_public_key = gateway_keys_.first;
        node.dilithium_public_key = signature_keys_.first;
        node.version = "0.2.0";
        node.last_heartbeat = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        node.is_active = true;
        node.load_factor = 0.0;
        node.key_generation_time = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        
        // Add capabilities
        node.capabilities["secure_gateway"] = "true";
        node.capabilities["post_quantum"] = "true";
        node.capabilities["max_concurrent_tx"] = std::to_string(config_.max_concurrent_tx);
        node.capabilities["epoch_interval"] = std::to_string(config_.epoch_interval.count());
        node.capabilities["protocol_version"] = "2";
        
        // Calculate and set fingerprint
        node.fingerprint = NodeInfo::calculate_fingerprint(node);
        
        // Create a network connection to the node manager
        auto networking = std::make_unique<PQNetworking>();
        auto init_result = networking->initialize_ssl();
        if (init_result.is_err()) {
            SecureLogger::instance().error("Failed to initialize networking: " + init_result.error_message());
            return init_result.error();
        }
        
        auto conn_result = networking->create_connection(config_.node_manager_address, config_.node_manager_port);
        if (conn_result.is_err()) {
            SecureLogger::instance().error("Failed to connect to node manager: " + conn_result.error_message());
            return conn_result.error();
        }
        
        SSL* ssl = conn_result.value();
        
        // Serialize the node info
        ByteVector node_data = node.serialize();
        
        // Prepare registration request
        ByteVector request;
        request.push_back(0x01); // 0x01 for node registration
        
        // Add node data size
        uint32_t node_size = static_cast<uint32_t>(node_data.size());
        request.push_back((node_size >> 24) & 0xFF);
        request.push_back((node_size >> 16) & 0xFF);
        request.push_back((node_size >> 8) & 0xFF);
        request.push_back(node_size & 0xFF);
        
        // Add node data
        request.insert(request.end(), node_data.begin(), node_data.end());
        
        // Send request
        auto send_result = networking->send_data(ssl, request);
        if (send_result.is_err()) {
            networking->close_connection(ssl);
            SecureLogger::instance().error("Failed to send registration request: " + send_result.error_message());
            return send_result.error();
        }
        
        // Receive response
        auto recv_result = networking->receive_data(ssl);
        networking->close_connection(ssl);
        
        if (recv_result.is_err()) {
            SecureLogger::instance().error("Failed to receive registration response: " + recv_result.error_message());
            return recv_result.error();
        }
        
        auto response = recv_result.value();
        
        // Parse response
        if (response.size() < 1) {
            SecureLogger::instance().error("Invalid registration response size");
            return ErrorCode::INVALID_PARAMETER;
        }
        
        uint8_t status = response[0];
        
        if (status != 0x00) {
            // Error status
            SecureLogger::instance().error("Registration failed with status: " + std::to_string(status));
            return ErrorCode::NODE_REGISTRATION_FAILED;
        }
        
        SecureLogger::instance().info("Registered successfully with node manager");
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during node manager registration: " + std::string(e.what()));
        return ErrorCode::NODE_REGISTRATION_FAILED;
    }
}

// Initialize connection pool
void SecureGateway::initialize_connection_pool() {
    SecureLogger::instance().info("Initializing connection pool");
    
    // Create max connections mutex array
    for (size_t i = 0; i < MAX_CONNECTION_HOSTS; i++) {
        connection_pool_mutexes_.push_back(std::make_unique<std::mutex>());
    }
}

// Start worker threads
void SecureGateway::start_worker_threads() {
    SecureLogger::instance().info("Starting worker threads");
    
    // Create transaction processing threads
    for (size_t i = 0; i < config_.thread_pool_size; i++) {
        worker_threads_.emplace_back([this] {
            process_transactions_thread();
        });
    }
}

// Start key rotation timer
void SecureGateway::start_key_rotation_timer() {
    SecureLogger::instance().info("Starting key rotation timer");
    
    key_rotation_thread_ = std::thread([this] {
        while (running_) {
            // Sleep until key rotation interval
            auto now = std::chrono::steady_clock::now();
            auto elapsed = now - key_creation_time_;
            
            if (elapsed < config_.key_rotation_interval) {
                auto remaining = config_.key_rotation_interval - elapsed;
                std::this_thread::sleep_for(remaining);
            }
            
            if (!running_) break;
            
            // Rotate keys
            rotate_keys();
            
            // Update key creation time
            key_creation_time_ = std::chrono::steady_clock::now();
        }
    });
}

// Start node manager synchronization
void SecureGateway::start_node_manager_sync() {
    SecureLogger::instance().info("Starting node manager synchronization");
    
    node_manager_sync_thread_ = std::thread([this] {
        while (running_) {
            // Sleep for node registry sync interval
            std::this_thread::sleep_for(constants::NODE_REGISTRY_SYNC_INTERVAL);
            
            if (!running_) break;
            
            // Sync with node manager
            sync_with_node_manager();
        }
    });
}

// Start epoch processing
void SecureGateway::start_epoch_processing() {
    SecureLogger::instance().info("Starting epoch processing");
    
    epoch_processing_thread_ = std::thread([this] {
        while (running_) {
            // Sleep for epoch interval
            std::this_thread::sleep_for(config_.epoch_interval);
            
            if (!running_) break;
            
            // Process epoch
            process_epoch();
        }
    });
}

// Start node heartbeat
void SecureGateway::start_node_heartbeat() {
    SecureLogger::instance().info("Starting node heartbeat");
    
    node_heartbeat_thread_ = std::thread([this] {
        while (running_) {
            // Sleep for heartbeat interval
            std::this_thread::sleep_for(constants::NODE_HEARTBEAT_INTERVAL);
            
            if (!running_) break;
            
            // Send heartbeat
            send_heartbeat();
        }
    });
}

// Start connection pool maintenance
void SecureGateway::start_connection_pool_maintenance() {
    SecureLogger::instance().info("Starting connection pool maintenance");
    
    connection_pool_maintenance_thread_ = std::thread([this] {
        while (running_) {
            // Sleep for 1 minute
            std::this_thread::sleep_for(60s);
            
            if (!running_) break;
            
            // Clean up stale connections
            cleanup_stale_connections();
        }
    });
}

// Start metrics collection
void SecureGateway::start_metrics_collection() {
    SecureLogger::instance().info("Starting metrics collection");
    
    metrics_thread_ = std::thread([this] {
        while (running_) {
            // Sleep for 1 second
            std::this_thread::sleep_for(1s);
            
            if (!running_) break;
            
            // Update metrics
            update_metrics();
        }
    });
}

// Update metrics
void SecureGateway::update_metrics() {
    try {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        // Update queue sizes
        {
            std::lock_guard<std::mutex> queue_lock(pending_queue_mutex_);
            metrics_.pending_transactions = pending_transactions_queue_.size();
        }
        
        metrics_.attestation_queue_size = attestation_buffer_.size();
        
        // Update node metrics
        metrics_.active_nodes = node_registry_->count_active_nodes();
        metrics_.total_nodes = node_registry_->count_total_nodes();
        
        // Calculate load factor (0.0 - 1.0)
        double transaction_load = static_cast<double>(metrics_.pending_transactions) / 
                                 config_.transaction_buffer_size;
        
        double processing_load = static_cast<double>(metrics_.processing_transactions) / 
                               config_.max_concurrent_tx;
        
        // Combine loads with weightings
        metrics_.load_factor = 0.6 * transaction_load + 0.4 * processing_load;
        
        // Update attestation metrics
        metrics_.total_attestations = attestation_store_->get_all_attestations().value_or(std::vector<Attestation>()).size();
        
        // Update metrics timestamp
        metrics_.last_updated = std::chrono::steady_clock::now();
        
        // Only send heartbeat if more than 1 second has passed
        if (std::chrono::duration_cast<std::chrono::seconds>(
                metrics_.last_updated - last_metrics_update_
            ).count() >= 1) {
            
            last_metrics_update_ = metrics_.last_updated;
            
            // Update node load factor
            if (!config_.node_manager_address.empty()) {
                update_node_load(metrics_.load_factor);
            }
        }
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception updating metrics: " + std::string(e.what()));
    }
}

// Verify chain ID is supported
Result<void> SecureGateway::verify_chain_id(uint32_t chain_id) {
    // Get active nodes
    auto nodes = node_registry_->get_active_nodes();
    
    // Check if any node supports this chain
    std::string chain_capability = "light_agent_chain_" + std::to_string(chain_id);
    
    for (const auto& node : nodes) {
        auto it = node.capabilities.find(chain_capability);
        if (it != node.capabilities.end() && it->second == "true") {
            return ErrorCode::SUCCESS;
        }
    }
    
    SecureLogger::instance().error("Unsupported chain ID: " + std::to_string(chain_id));
    return ErrorCode::INVALID_PARAMETER;
}

// Send heartbeat to node manager
void SecureGateway::send_heartbeat() {
    if (config_.node_manager_address.empty()) {
        return;
    }
    
    try {
        // Create a network connection to the node manager
        auto networking = std::make_unique<PQNetworking>();
        auto init_result = networking->initialize_ssl();
        if (init_result.is_err()) {
            SecureLogger::instance().error("Failed to initialize networking for heartbeat: " + 
                                   init_result.error_message());
            return;
        }
        
        auto conn_result = networking->create_connection(config_.node_manager_address, config_.node_manager_port);
        if (conn_result.is_err()) {
            SecureLogger::instance().error("Failed to connect to node manager for heartbeat: " + 
                                   conn_result.error_message());
            return;
        }
        
        SSL* ssl = conn_result.value();
        
        // Prepare heartbeat request
        ByteVector request;
        request.push_back(0x02); // 0x02 for heartbeat
        
        // Add node ID
        request.insert(request.end(), config_.node_id.begin(), config_.node_id.end());
        
        // Add timestamp (8 bytes)
        uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        
        for (int i = 7; i >= 0; i--) {
            request.push_back((timestamp >> (i * 8)) & 0xFF);
        }
        
        // Add load factor (8 bytes as double)
        double load_factor;
        {
            std::lock_guard<std::mutex> lock(metrics_mutex_);
            load_factor = metrics_.load_factor;
        }
        
        uint64_t load_bits;
        std::memcpy(&load_bits, &load_factor, sizeof(double));
        
        for (int i = 7; i >= 0; i--) {
            request.push_back((load_bits >> (i * 8)) & 0xFF);
        }
        
        // Sign the heartbeat
        ByteVector data_to_sign;
        data_to_sign.insert(data_to_sign.end(), config_.node_id.begin(), config_.node_id.end());
        
        for (int i = 7; i >= 0; i--) {
            data_to_sign.push_back((timestamp >> (i * 8)) & 0xFF);
        }
        
        for (int i = 7; i >= 0; i--) {
            data_to_sign.push_back((load_bits >> (i * 8)) & 0xFF);
        }
        
        auto sign_result = FinalDefiSDK::instance().sign_data(data_to_sign, signature_keys_.second);
        if (sign_result.is_err()) {
            networking->close_connection(ssl);
            SecureLogger::instance().error("Failed to sign heartbeat: " + sign_result.error_message());
            return;
        }
        
        ByteVector signature = sign_result.value();
        
        // Add signature size
        uint16_t sig_size = static_cast<uint16_t>(signature.size());
        request.push_back((sig_size >> 8) & 0xFF);
        request.push_back(sig_size & 0xFF);
        
        // Add signature
        request.insert(request.end(), signature.begin(), signature.end());
        
        // Send request
        auto send_result = networking->send_data(ssl, request);
        if (send_result.is_err()) {
            networking->close_connection(ssl);
            SecureLogger::instance().error("Failed to send heartbeat: " + send_result.error_message());
            return;
        }
        
        // Receive response
        auto recv_result = networking->receive_data(ssl);
        networking->close_connection(ssl);
        
        if (recv_result.is_err()) {
            SecureLogger::instance().error("Failed to receive heartbeat response: " + 
                                   recv_result.error_message());
            return;
        }
        
        auto response = recv_result.value();
        
        // Parse response
        if (response.size() < 1) {
            SecureLogger::instance().error("Invalid heartbeat response size");
            return;
        }
        
        uint8_t status = response[0];
        
        if (status != 0x00) {
            // Error status
            SecureLogger::instance().error("Heartbeat failed with status: " + std::to_string(status));
            return;
        }
        
        SecureLogger::instance().debug("Heartbeat sent successfully");
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception sending heartbeat: " + std::string(e.what()));
    }
}

// Update node load with node manager
void SecureGateway::update_node_load(double load_factor) {
    try {
        network_circuit_breaker_.execute<void>([&]() {
            // Create a network connection to the node manager
            auto networking = std::make_unique<PQNetworking>();
            auto init_result = networking->initialize_ssl();
            if (init_result.is_err()) {
                SecureLogger::instance().error("Failed to initialize networking for load update: " + 
                                      init_result.error_message());
                return;
            }
            
            auto conn_result = networking->create_connection(config_.node_manager_address, config_.node_manager_port);
            if (conn_result.is_err()) {
                SecureLogger::instance().error("Failed to connect to node manager for load update: " + 
                                      conn_result.error_message());
                return;
            }
            
            SSL* ssl = conn_result.value();
            
            // Prepare load update request
            ByteVector request;
            request.push_back(0x05); // 0x05 for load update
            
            // Add node ID
            request.insert(request.end(), config_.node_id.begin(), config_.node_id.end());
            
            // Add load factor (8 bytes as double)
            uint64_t load_bits;
            std::memcpy(&load_bits, &load_factor, sizeof(double));
            
            for (int i = 7; i >= 0; i--) {
                request.push_back((load_bits >> (i * 8)) & 0xFF);
            }
            
            // Send request
            auto send_result = networking->send_data(ssl, request);
            if (send_result.is_err()) {
                networking->close_connection(ssl);
                SecureLogger::instance().error("Failed to send load update: " + send_result.error_message());
                return;
            }
            
            // Receive response
            auto recv_result = networking->receive_data(ssl);
            networking->close_connection(ssl);
            
            if (recv_result.is_err()) {
                SecureLogger::instance().error("Failed to receive load update response: " + 
                                      recv_result.error_message());
                return;
            }
            
            auto response = recv_result.value();
            
            // Parse response
            if (response.size() < 1) {
                SecureLogger::instance().error("Invalid load update response size");
                return;
            }
            
            uint8_t status = response[0];
            
            if (status != 0x00) {
                // Error status
                SecureLogger::instance().error("Load update failed with status: " + std::to_string(status));
                return;
            }
        });
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception updating node load: " + std::string(e.what()));
        network_circuit_breaker_.record_failure(e.what());
    }
}

// Sync with node manager
void SecureGateway::sync_with_node_manager() {
    if (config_.node_manager_address.empty()) {
        return;
    }
    
    try {
        SecureLogger::instance().info("Syncing with node manager");
        
        // Create a network connection to the node manager
        auto networking = std::make_unique<PQNetworking>();
        auto init_result = networking->initialize_ssl();
        if (init_result.is_err()) {
            SecureLogger::instance().error("Failed to initialize networking for sync: " + 
                                   init_result.error_message());
            return;
        }
        
        auto conn_result = networking->create_connection(config_.node_manager_address, config_.node_manager_port);
        if (conn_result.is_err()) {
            SecureLogger::instance().error("Failed to connect to node manager for sync: " + 
                                   conn_result.error_message());
            return;
        }
        
        SSL* ssl = conn_result.value();
        
        // Prepare registry sync request
        ByteVector request;
        request.push_back(0x03); // 0x03 for registry sync
        
        // Add node ID
        request.insert(request.end(), config_.node_id.begin(), config_.node_id.end());
        
        // Send request
        auto send_result = networking->send_data(ssl, request);
        if (send_result.is_err()) {
            networking->close_connection(ssl);
            SecureLogger::instance().error("Failed to send registry sync request: " + send_result.error_message());
            return;
        }
        
        // Receive response
        auto recv_result = networking->receive_data(ssl);
        networking->close_connection(ssl);
        
        if (recv_result.is_err()) {
            SecureLogger::instance().error("Failed to receive registry sync response: " + 
                                   recv_result.error_message());
            return;
        }
        
        auto response = recv_result.value();
        
        // Parse response
        if (response.size() < 5) { // Status byte + 4 bytes for count
            SecureLogger::instance().error("Invalid registry sync response size");
            return;
        }
        
        uint8_t status = response[0];
        
        if (status != 0x00) {
            // Error status
            SecureLogger::instance().error("Registry sync failed with status: " + std::to_string(status));
            return;
        }
        
        // Extract node count
        uint32_t node_count = (response[1] << 24) | (response[2] << 16) | 
                             (response[3] << 8) | response[4];
        
        size_t pos = 5;
        std::vector<NodeInfo> received_nodes;
        
        // Extract each node
        for (uint32_t i = 0; i < node_count; i++) {
            if (pos + 4 > response.size()) {
                SecureLogger::instance().error("Invalid registry sync response format");
                return;
            }
            
            // Extract node size
            uint32_t node_size = (response[pos] << 24) | (response[pos + 1] << 16) | 
                                (response[pos + 2] << 8) | response[pos + 3];
            pos += 4;
            
            if (pos + node_size > response.size()) {
                SecureLogger::instance().error("Invalid registry sync response format");
                return;
            }
            
            // Extract node data
            ByteVector node_data(response.begin() + pos, response.begin() + pos + node_size);
            pos += node_size;
            
            // Deserialize node
            auto node_result = NodeInfo::deserialize(node_data);
            if (node_result.is_err()) {
                SecureLogger::instance().error("Failed to deserialize node from sync: " + 
                                      node_result.error_message());
                continue;
            }
            
            NodeInfo node = node_result.value();
            
            // Verify node fingerprint
            ByteVector expected_fingerprint = NodeInfo::calculate_fingerprint(node);
            if (expected_fingerprint != node.fingerprint) {
                SecureLogger::instance().error("Node fingerprint verification failed during sync");
                continue;
            }
            
            // Check version compatibility
            if (node.version != "0.2.0") {
                SecureLogger::instance().warning("Ignoring node with incompatible version: " + node.version);
                continue;
            }
            
            received_nodes.push_back(node);
        }
        
        // Update the node registry with received nodes
        for (const auto& node : received_nodes) {
            node_registry_->register_node(node);
        }
        
        SecureLogger::instance().info("Synced " + std::to_string(received_nodes.size()) + " nodes from node manager");
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception syncing with node manager: " + std::string(e.what()));
    }
}

// Rotate cryptographic keys
void SecureGateway::rotate_keys() {
    try {
        SecureLogger::instance().info("Rotating cryptographic keys");
        
        // Generate new Kyber keypair
        auto kyber_result = FinalDefiSDK::instance().generate_kyber_keypair();
        if (kyber_result.is_err()) {
            SecureLogger::instance().error("Failed to generate new Kyber keypair: " + 
                                   kyber_result.error_message());
            return;
        }
        
        // Generate new Dilithium keypair
        auto dilithium_result = FinalDefiSDK::instance().generate_dilithium_keypair();
        if (dilithium_result.is_err()) {
            SecureLogger::instance().error("Failed to generate new Dilithium keypair: " + 
                                   dilithium_result.error_message());
            return;
        }
        
        // Update keys
        gateway_keys_ = kyber_result.value();
        signature_keys_ = dilithium_result.value();
        
        // Save the new keys
        auto save_result = save_keys();
        if (save_result.is_err()) {
            SecureLogger::instance().error("Failed to save rotated keys: " + save_result.error_message());
            return;
        }
        
        // Register the new keys with the node manager
        if (!config_.node_manager_address.empty()) {
            auto reg_result = update_node_keys();
            if (reg_result.is_err()) {
                SecureLogger::instance().error("Failed to update keys with node manager: " + 
                                      reg_result.error_message());
                return;
            }
        }
        
        // Generate key rotation attestation
        auto attestation_result = generate_key_rotation_attestation();
        if (attestation_result.is_err()) {
            SecureLogger::instance().error("Failed to generate key rotation attestation: " + 
                                   attestation_result.error_message());
            return;
        }
        
        Attestation attestation = attestation_result.value();
        
        // Store key rotation attestation
        attestation_store_->store_attestation(attestation);
        
        // Add to attestation buffer
        attestation_buffer_.push(attestation);
        
        SecureLogger::instance().info("Keys rotated successfully");
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during key rotation: " + std::string(e.what()));
    }
}

// Generate key rotation attestation
Result<Attestation> SecureGateway::generate_key_rotation_attestation() {
    try {
        // Create new attestation
        Attestation attestation;
        attestation.id = Attestation::generate_id();
        attestation.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        attestation.type = Attestation::Type::KEY_ROTATION;
        
        // Add node ID to entity_ids
        ByteVector node_id_vec(config_.node_id.begin(), config_.node_id.end());
        attestation.entity_ids.push_back(node_id_vec);
        
        // Sign with new secure gateway key
        ByteVector data_to_sign = node_id_vec;
        data_to_sign.insert(data_to_sign.end(), gateway_keys_.first.begin(), gateway_keys_.first.end());
        data_to_sign.insert(data_to_sign.end(), signature_keys_.first.begin(), signature_keys_.first.end());
        
        auto signature_result = FinalDefiSDK::instance().sign_data(data_to_sign, signature_keys_.second);
        if (signature_result.is_err()) {
            return signature_result.error();
        }
        
        attestation.gateway_signature = signature_result.value();
        
        // Add metadata
        attestation.metadata["attestation_type"] = "key_rotation";
        attestation.metadata["node_id"] = bytes_to_hex(node_id_vec);
        attestation.metadata["kyber_public_key"] = bytes_to_hex(gateway_keys_.first);
        attestation.metadata["dilithium_public_key"] = bytes_to_hex(signature_keys_.first);
        attestation.metadata["timestamp"] = std::to_string(attestation.timestamp);
        
        return attestation;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception generating key rotation attestation: " + std::string(e.what()));
        return ErrorCode::ATTESTATION_GENERATION_FAILED;
    }
}

// Update node keys with node manager
Result<void> SecureGateway::update_node_keys() {
    try {
        // Get current node info
        auto node_result = node_registry_->get_node(config_.node_id);
        if (node_result.is_err()) {
            SecureLogger::instance().error("Failed to get current node info: " + node_result.error_message());
            return node_result.error();
        }
        
        NodeInfo node = node_result.value();
        
        // Update keys
        node.kyber_public_key = gateway_keys_.first;
        node.dilithium_public_key = signature_keys_.first;
        node.key_generation_time = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        
        // Recalculate fingerprint
        node.fingerprint = NodeInfo::calculate_fingerprint(node);
        
        // Register with node manager
        auto reg_result = register_node_with_manager(node);
        if (reg_result.is_err()) {
            SecureLogger::instance().error("Failed to register updated node: " + reg_result.error_message());
            return reg_result.error();
        }
        
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception updating node keys: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Register a node with the node manager
Result<void> SecureGateway::register_node_with_manager(const NodeInfo& node) {
    try {
        // Create a network connection to the node manager
        auto networking = std::make_unique<PQNetworking>();
        auto init_result = networking->initialize_ssl();
        if (init_result.is_err()) {
            return init_result.error();
        }
        
        auto conn_result = networking->create_connection(config_.node_manager_address, config_.node_manager_port);
        if (conn_result.is_err()) {
            return conn_result.error();
        }
        
        SSL* ssl = conn_result.value();
        
        // Serialize the node info
        ByteVector node_data = node.serialize();
        
        // Prepare registration request
        ByteVector request;
        request.push_back(0x01); // 0x01 for node registration
        
        // Add node data size
        uint32_t node_size = static_cast<uint32_t>(node_data.size());
        request.push_back((node_size >> 24) & 0xFF);
        request.push_back((node_size >> 16) & 0xFF);
        request.push_back((node_size >> 8) & 0xFF);
        request.push_back(node_size & 0xFF);
        
        // Add node data
        request.insert(request.end(), node_data.begin(), node_data.end());
        
        // Send request
        auto send_result = networking->send_data(ssl, request);
        if (send_result.is_err()) {
            networking->close_connection(ssl);
            return send_result.error();
        }
        
        // Receive response
        auto recv_result = networking->receive_data(ssl);
        networking->close_connection(ssl);
        
        if (recv_result.is_err()) {
            return recv_result.error();
        }
        
        auto response = recv_result.value();
        
        // Parse response
        if (response.size() < 1) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        uint8_t status = response[0];
        
        if (status != 0x00) {
            // Error status
            return ErrorCode::NODE_REGISTRATION_FAILED;
        }
        
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception registering node with manager: " + std::string(e.what()));
        return ErrorCode::NODE_REGISTRATION_FAILED;
    }
}

// Save keys to disk
Result<void> SecureGateway::save_keys() {
    try {
        // Ensure the directory exists
        std::filesystem::path secret_dir = std::filesystem::path(constants::SECRET_FILE_PATH).parent_path();
        if (!std::filesystem::exists(secret_dir)) {
            std::filesystem::create_directories(secret_dir);
        }
        
        // Prepare data to save
        ByteVector data;
        
        // Add Kyber public key
        uint32_t kyber_pub_size = static_cast<uint32_t>(gateway_keys_.first.size());
        data.push_back((kyber_pub_size >> 24) & 0xFF);
        data.push_back((kyber_pub_size >> 16) & 0xFF);
        data.push_back((kyber_pub_size >> 8) & 0xFF);
        data.push_back(kyber_pub_size & 0xFF);
        data.insert(data.end(), gateway_keys_.first.begin(), gateway_keys_.first.end());
        
        // Add Kyber secret key
        uint32_t kyber_sec_size = static_cast<uint32_t>(gateway_keys_.second.size());
        data.push_back((kyber_sec_size >> 24) & 0xFF);
        data.push_back((kyber_sec_size >> 16) & 0xFF);
        data.push_back((kyber_sec_size >> 8) & 0xFF);
        data.push_back(kyber_sec_size & 0xFF);
        data.insert(data.end(), gateway_keys_.second.begin(), gateway_keys_.second.end());
        
        // Add Dilithium public key
        uint32_t dilithium_pub_size = static_cast<uint32_t>(signature_keys_.first.size());
        data.push_back((dilithium_pub_size >> 24) & 0xFF);
        data.push_back((dilithium_pub_size >> 16) & 0xFF);
        data.push_back((dilithium_pub_size >> 8) & 0xFF);
        data.push_back(dilithium_pub_size & 0xFF);
        data.insert(data.end(), signature_keys_.first.begin(), signature_keys_.first.end());
        
        // Add Dilithium secret key
        uint32_t dilithium_sec_size = static_cast<uint32_t>(signature_keys_.second.size());
        data.push_back((dilithium_sec_size >> 24) & 0xFF);
        data.push_back((dilithium_sec_size >> 16) & 0xFF);
        data.push_back((dilithium_sec_size >> 8) & 0xFF);
        data.push_back(dilithium_sec_size & 0xFF);
        data.insert(data.end(), signature_keys_.second.begin(), signature_keys_.second.end());
        
        // Encrypt the data
        auto encrypt_result = encrypt_keys(data);
        if (encrypt_result.is_err()) {
            return encrypt_result.error();
        }
        
        ByteVector encrypted_data = encrypt_result.value();
        
        // Write to file
        std::ofstream file(constants::SECRET_FILE_PATH, std::ios::binary);
        if (!file) {
            return ErrorCode::FILE_IO_ERROR;
        }
        
        file.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
        file.close();
        
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception saving keys: " + std::string(e.what()));
        return ErrorCode::FILE_IO_ERROR;
    }
}

// Encrypt keys for storage
Result<ByteVector> SecureGateway::encrypt_keys(const ByteVector& data) {
    try {
        // Generate encryption key from node ID
        ByteVector encryption_key(crypto_secretbox_KEYBYTES);
        crypto_kdf_derive_from_key(encryption_key.data(), encryption_key.size(), 1, 
                                 "keyencry", constants::NODE_FINGERPRINT_KEY);
        
        // Generate a random nonce
        ByteVector nonce(crypto_secretbox_NONCEBYTES);
        randombytes_buf(nonce.data(), nonce.size());
        
        // Allocate space for the encrypted data
        ByteVector encrypted(nonce.size() + data.size() + crypto_secretbox_MACBYTES);
        
        // Copy the nonce to the beginning of the encrypted data
        std::copy(nonce.begin(), nonce.end(), encrypted.begin());
        
        // Encrypt the data
        if (crypto_secretbox_easy(
                encrypted.data() + nonce.size(),
                data.data(),
                data.size(),
                nonce.data(),
                encryption_key.data()) != 0) {
            return ErrorCode::ENCRYPTION_FAILED;
        }
        
        // Clear sensitive data
        sodium_memzero(encryption_key.data(), encryption_key.size());
        
        return encrypted;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception encrypting keys: " + std::string(e.what()));
        return ErrorCode::ENCRYPTION_FAILED;
    }
}

// Decrypt keys from storage
Result<std::pair<std::pair<ByteVector, ByteVector>, std::pair<ByteVector, ByteVector>>> 
SecureGateway::decrypt_keys(const ByteVector& encrypted_data) {
    try {
        // Check if the data is large enough to contain a nonce and MAC
        if (encrypted_data.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        // Generate encryption key from node ID
        ByteVector encryption_key(crypto_secretbox_KEYBYTES);
        crypto_kdf_derive_from_key(encryption_key.data(), encryption_key.size(), 1, 
                                 "keyencry", constants::NODE_FINGERPRINT_KEY);
        
        // Extract the nonce
        ByteVector nonce(encrypted_data.begin(), encrypted_data.begin() + crypto_secretbox_NONCEBYTES);
        
        // Allocate space for the decrypted data
        size_t decrypted_size = encrypted_data.size() - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
        ByteVector decrypted(decrypted_size);
        
        // Decrypt the data
        if (crypto_secretbox_open_easy(
                decrypted.data(),
                encrypted_data.data() + crypto_secretbox_NONCEBYTES,
                encrypted_data.size() - crypto_secretbox_NONCEBYTES,
                nonce.data(),
                encryption_key.data()) != 0) {
            return ErrorCode::DECRYPTION_FAILED;
        }
        
        // Clear sensitive data
        sodium_memzero(encryption_key.data(), encryption_key.size());
        
        // Parse the decrypted data
        size_t pos = 0;
        
        // Extract Kyber public key
        if (pos + 4 > decrypted.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        uint32_t kyber_pub_size = (decrypted[pos] << 24) | (decrypted[pos + 1] << 16) | 
                                 (decrypted[pos + 2] << 8) | decrypted[pos + 3];
        pos += 4;
        
        if (pos + kyber_pub_size > decrypted.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        ByteVector kyber_pub(decrypted.begin() + pos, decrypted.begin() + pos + kyber_pub_size);
        pos += kyber_pub_size;
        
        // Extract Kyber secret key
        if (pos + 4 > decrypted.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        uint32_t kyber_sec_size = (decrypted[pos] << 24) | (decrypted[pos + 1] << 16) | 
                                 (decrypted[pos + 2] << 8) | decrypted[pos + 3];
        pos += 4;
        
        if (pos + kyber_sec_size > decrypted.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        ByteVector kyber_sec(decrypted.begin() + pos, decrypted.begin() + pos + kyber_sec_size);
        pos += kyber_sec_size;
        
        // Extract Dilithium public key
        if (pos + 4 > decrypted.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        uint32_t dilithium_pub_size = (decrypted[pos] << 24) | (decrypted[pos + 1] << 16) | 
                                     (decrypted[pos + 2] << 8) | decrypted[pos + 3];
        pos += 4;
        
        if (pos + dilithium_pub_size > decrypted.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        ByteVector dilithium_pub(decrypted.begin() + pos, decrypted.begin() + pos + dilithium_pub_size);
        pos += dilithium_pub_size;
        
        // Extract Dilithium secret key
        if (pos + 4 > decrypted.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        uint32_t dilithium_sec_size = (decrypted[pos] << 24) | (decrypted[pos + 1] << 16) | 
                                     (decrypted[pos + 2] << 8) | decrypted[pos + 3];
        pos += 4;
        
        if (pos + dilithium_sec_size > decrypted.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        ByteVector dilithium_sec(decrypted.begin() + pos, decrypted.begin() + pos + dilithium_sec_size);
        
        // Return the keys
        return std::make_pair(
            std::make_pair(kyber_pub, kyber_sec),
            std::make_pair(dilithium_pub, dilithium_sec)
        );
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception decrypting keys: " + std::string(e.what()));
        return ErrorCode::DECRYPTION_FAILED;
    }
}

// Get or create a connection from the connection pool
Result<SSL*> SecureGateway::get_or_create_connection(const std::string& host, uint16_t port) {
    try {
        // Create a connection key
        std::string conn_key = host + ":" + std::to_string(port);
        
        // Hash the connection key to get an index
        size_t hash_value = std::hash<std::string>{}(conn_key);
        size_t mutex_idx = hash_value % connection_pool_mutexes_.size();
        
        // Lock the connection pool for this host:port
        std::lock_guard<std::mutex> lock(*connection_pool_mutexes_[mutex_idx]);
        
        // Check if we have a connection in the pool
        auto& connection_queue = connection_pool_[conn_key];
        
        while (!connection_queue.empty()) {
            // Get the first connection
            auto& [ssl, last_used] = connection_queue.front();
            
            // Check if the connection is stale
            auto now = std::chrono::steady_clock::now();
            if (now - last_used > CONNECTION_STALE_THRESHOLD) {
                // Connection is stale, close it and try the next one
                FinalDefiSDK::instance().close_secure_connection(ssl);
                connection_queue.pop();
                continue;
            }
            
            // Connection is good, return it
            SSL* result = ssl;
            connection_queue.pop();
            return result;
        }
        
        // No valid connection in the pool, create a new one
        auto result = FinalDefiSDK::instance().create_secure_connection(host, port);
        if (result.is_err()) {
            return result.error();
        }
        
        return result.value();
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception getting connection from pool: " + std::string(e.what()));
        return ErrorCode::NETWORK_ERROR;
    }
}

// Return a connection to the pool
void SecureGateway::return_connection_to_pool(const std::string& host, uint16_t port, SSL* ssl) {
    try {
        // Don't return null connections
        if (!ssl) {
            return;
        }
        
        // Create a connection key
        std::string conn_key = host + ":" + std::to_string(port);
        
        // Hash the connection key to get an index
        size_t hash_value = std::hash<std::string>{}(conn_key);
        size_t mutex_idx = hash_value % connection_pool_mutexes_.size();
        
        // Lock the connection pool for this host:port
        std::lock_guard<std::mutex> lock(*connection_pool_mutexes_[mutex_idx]);
        
        // Check if we've reached the maximum pool size for this host:port
        auto& connection_queue = connection_pool_[conn_key];
        
        if (connection_queue.size() >= MAX_CONNECTIONS_PER_HOST) {
            // Pool is full, close the connection
            FinalDefiSDK::instance().close_secure_connection(ssl);
            return;
        }
        
        // Add the connection to the pool
        connection_queue.push({ssl, std::chrono::steady_clock::now()});
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception returning connection to pool: " + std::string(e.what()));
        
        // Make sure the connection is closed
        if (ssl) {
            FinalDefiSDK::instance().close_secure_connection(ssl);
        }
    }
}

// Clean up stale connections in the pool
void SecureGateway::cleanup_stale_connections() {
    try {
        // For each mutex in the connection pool
        for (size_t i = 0; i < connection_pool_mutexes_.size(); i++) {
            // Lock this part of the pool
            std::lock_guard<std::mutex> lock(*connection_pool_mutexes_[i]);
            
            auto now = std::chrono::steady_clock::now();
            
            // For each host:port in this part of the pool
            auto it = connection_pool_.begin();
            while (it != connection_pool_.end()) {
                auto& [conn_key, connection_queue] = *it;
                
                // Process this connection queue
                size_t original_size = connection_queue.size();
                
                // Temporary queue for non-stale connections
                std::queue<std::pair<SSL*, std::chrono::steady_clock::time_point>> kept_connections;
                
                // Check each connection
                while (!connection_queue.empty()) {
                    auto& [ssl, last_used] = connection_queue.front();
                    
                    if (now - last_used > CONNECTION_STALE_THRESHOLD) {
                        // Connection is stale, close it
                        FinalDefiSDK::instance().close_secure_connection(ssl);
                    } else {
                        // Connection is still good, keep it
                        kept_connections.push({ssl, last_used});
                    }
                    
                    connection_queue.pop();
                }
                
                // Replace the queue with the kept connections
                connection_queue = std::move(kept_connections);
                
                // If there were stale connections, log it
                if (connection_queue.size() < original_size) {
                    SecureLogger::instance().debug("Closed " + 
                                           std::to_string(original_size - connection_queue.size()) + 
                                           " stale connections for " + conn_key);
                }
                
                // If the queue is empty, remove it
                if (connection_queue.empty()) {
                    it = connection_pool_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception cleaning up stale connections: " + std::string(e.what()));
    }
}

// Close all connections in the pool
void SecureGateway::close_all_connections() {
    try {
        SecureLogger::instance().info("Closing all connections in the pool");
        
        // For each mutex in the connection pool
        for (size_t i = 0; i < connection_pool_mutexes_.size(); i++) {
            // Lock this part of the pool
            std::lock_guard<std::mutex> lock(*connection_pool_mutexes_[i]);
            
            // For each host:port in this part of the pool
            for (auto& [conn_key, connection_queue] : connection_pool_) {
                // Close all connections
                while (!connection_queue.empty()) {
                    auto& [ssl, _] = connection_queue.front();
                    FinalDefiSDK::instance().close_secure_connection(ssl);
                    connection_queue.pop();
                }
            }
        }
        
        // Clear the connection pool
        connection_pool_.clear();
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception closing all connections: " + std::string(e.what()));
    }
}

// Initialize the metrics
void SecureGateway::initialize_metrics() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    // Reset all metrics
    metrics_ = GatewayMetrics();
    
    // Set initial values
    metrics_.last_updated = std::chrono::steady_clock::now();
    metrics_.last_epoch_time = std::chrono::system_clock::now();
    
    // Record the start time for uptime calculation
    metrics_.start_time = std::chrono::steady_clock::now();
    
    last_metrics_update_ = metrics_.last_updated;
}

// Get the local machine's address
std::string SecureGateway::get_local_address() const {
    // Try to get local address
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct addrinfo hints, *info;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        if (getaddrinfo(hostname, NULL, &hints, &info) == 0) {
            for (struct addrinfo* p = info; p != NULL; p = p->ai_next) {
                struct sockaddr_in* addr = (struct sockaddr_in*)p->ai_addr;
                
                // Skip loopback addresses
                if (ntohl(addr->sin_addr.s_addr) != INADDR_LOOPBACK) {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
                    
                    freeaddrinfo(info);
                    return std::string(ip_str);
                }
            }
            
            freeaddrinfo(info);
        }
    }
    
    // Fallback to localhost
    return "127.0.0.1";
}

// Convert bytes to hex string
std::string SecureGateway::bytes_to_hex(const ByteVector& bytes) const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (const auto& byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return ss.str();
}

// Convert hex string to bytes
ByteVector SecureGateway::hex_to_bytes(const std::string& hex) const {
    ByteVector bytes;
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }
    
    return bytes;
}

} // namespace secure_gateway
} // namespace finaldefi

// Transaction processing thread
void SecureGateway::process_transactions_thread() {
    while (running_) {
        Transaction tx;
        bool has_tx = false;
        
        // Get a transaction from the queue
        {
            std::unique_lock<std::mutex> lock(pending_queue_mutex_);
            if (pending_transactions_queue_.empty()) {
                // Wait for a transaction or stop signal
                pending_transactions_queue_.wait_for_non_empty(lock, 1s, [this] {
                    return !running_;
                });
                
                // Check if we're shutting down
                if (!running_) {
                    break;
                }
                
                // Check if there's a transaction
                if (!pending_transactions_queue_.empty()) {
                    tx = pending_transactions_queue_.front();
                    pending_transactions_queue_.pop();
                    has_tx = true;
                }
            } else {
                tx = pending_transactions_queue_.front();
                pending_transactions_queue_.pop();
                has_tx = true;
            }
        }
        
        // Process the transaction if we have one
        if (has_tx) {
            process_transaction(tx);
        }
    }
}

// Process a single transaction
void SecureGateway::process_transaction(Transaction& tx) {
    try {
        // Set the transaction to processing state
        tx.status = Transaction::Status::PROCESSING;
        transaction_store_->update_transaction(tx);
        
        // Update metrics
        {
            std::lock_guard<std::mutex> lock(metrics_mutex_);
            metrics_.pending_transactions--;
            metrics_.processing_transactions++;
        }
        
        // Start timing the processing
        auto start_time = std::chrono::steady_clock::now();
        
        // Submit to light agent
        auto submit_result = submit_to_light_agent(tx);
        
        // End timing
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        // Update metrics
        {
            std::lock_guard<std::mutex> lock(metrics_mutex_);
            metrics_.processing_transactions--;
            
            // Update average processing time
            metrics_.total_processing_time_ms += duration.count();
            metrics_.transactions_processed++;
            metrics_.average_processing_time_ms = 
                static_cast<double>(metrics_.total_processing_time_ms) / metrics_.transactions_processed;
            
            // Update success/failure counts
            if (submit_result.is_ok()) {
                metrics_.completed_transactions++;
            } else {
                metrics_.failed_transactions++;
            }
        }
        
        if (submit_result.is_err()) {
            // Handle error
            tx.status = Transaction::Status::FAILED;
            tx.metadata["error"] = submit_result.error_message();
            transaction_store_->update_transaction(tx);
            
            SecureLogger::instance().error("Transaction processing failed: " + submit_result.error_message() + 
                                    " for tx: " + bytes_to_hex(tx.id));
            return;
        }
        
        // Update the transaction with light agent response
        tx.status = Transaction::Status::COMPLETED;
        tx.response = submit_result.value();
        
        // If we have Merkle proof from a batch, add it
        auto batch_attestations = attestation_store_->get_attestations_by_entity_id(tx.id);
        if (batch_attestations.is_ok()) {
            for (const auto& att : batch_attestations.value()) {
                if (att.type == Attestation::Type::BATCH) {
                    // Try to get Merkle proof
                    auto tx_hash = tx.calculate_hash();
                    
                    MerkleTree merkle_tree;
                    auto all_tx = transaction_store_->get_all_transactions();
                    if (all_tx.is_ok()) {
                        // Find all transactions in this batch
                        std::vector<Transaction> batch_tx;
                        for (const auto& batch_tx_id : att.entity_ids) {
                            auto find_it = std::find_if(
                                all_tx.value().begin(), 
                                all_tx.value().end(),
                                [&batch_tx_id](const Transaction& t) {
                                    return t.id == batch_tx_id;
                                }
                            );
                            
                            if (find_it != all_tx.value().end()) {
                                batch_tx.push_back(*find_it);
                            }
                        }
                        
                        if (!batch_tx.empty()) {
                            merkle_tree.build(batch_tx);
                            auto proof_result = merkle_tree.get_proof(tx);
                            if (proof_result.is_ok()) {
                                tx.merkle_proof = proof_result.value();
                            }
                        }
                    }
                    
                    break;
                }
            }
        }
        
        // Timestamp the completion
        tx.metadata["completion_time"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count());
        
        // Update transaction
        transaction_store_->update_transaction(tx);
        
        // Generate completion attestation
        auto completion_attestation = generate_completion_attestation(tx);
        if (completion_attestation.is_ok()) {
            // Store and queue the attestation
            auto att = completion_attestation.value();
            attestation_store_->store_attestation(att);
            attestation_buffer_.push(att);
        }
        
        SecureLogger::instance().info("Transaction processed successfully: " + bytes_to_hex(tx.id));
        
    } catch (const std::exception& e) {
        // Handle exception
        tx.status = Transaction::Status::FAILED;
        tx.metadata["error"] = std::string("Exception: ") + e.what();
        transaction_store_->update_transaction(tx);
        
        // Update metrics
        {
            std::lock_guard<std::mutex> lock(metrics_mutex_);
            metrics_.processing_transactions--;
            metrics_.failed_transactions++;
        }
        
        SecureLogger::instance().error("Exception processing transaction: " + std::string(e.what()) + 
                                " for tx: " + bytes_to_hex(tx.id));
    }
}

// Submit a transaction to a light agent
Result<std::optional<ByteVector>> SecureGateway::submit_to_light_agent(const Transaction& tx) {
    // Get best nodes for this chain
    auto best_nodes_result = get_best_nodes_for_chain(tx.chain_id);
    if (best_nodes_result.is_err()) {
        return best_nodes_result.error();
    }
    
    auto best_nodes = best_nodes_result.value();
    if (best_nodes.empty()) {
        SecureLogger::instance().error("No suitable nodes found for chain " + std::to_string(tx.chain_id));
        return ErrorCode::NODE_NOT_FOUND;
    }
    
    // Try each node in order until one succeeds
    for (const auto& node : best_nodes) {
        auto result = submit_to_specific_light_agent(tx, node);
        if (result.is_ok()) {
            return result.value();
        }
        
        // Log error and try next node
        SecureLogger::instance().warning("Failed to submit to light agent at " + 
                                  node.hostname + ":" + std::to_string(node.port) + 
                                  ": " + result.error_message());
    }
    
    // All nodes failed
    SecureLogger::instance().error("All light agents failed for chain " + std::to_string(tx.chain_id));
    return ErrorCode::COMMUNICATION_FAILED;
}

// Submit a transaction to a specific light agent
Result<std::optional<ByteVector>> SecureGateway::submit_to_specific_light_agent(
    const Transaction& tx, 
    const NodeInfo& node) {
    
    try {
        // Get a connection from the pool or create a new one
        auto conn_result = get_or_create_connection(node.hostname, node.port);
        if (conn_result.is_err()) {
            return conn_result.error();
        }
        
        SSL* ssl = conn_result.value();
        
        // Serialize the transaction
        ByteVector tx_data = tx.serialize();
        
        // Prepare submission request
        ByteVector request;
        
        // Add request type (1 byte)
        request.push_back(0x01); // 0x01 for transaction submission
        
        // Add transaction data size
        uint32_t tx_size = static_cast<uint32_t>(tx_data.size());
        request.push_back((tx_size >> 24) & 0xFF);
        request.push_back((tx_size >> 16) & 0xFF);
        request.push_back((tx_size >> 8) & 0xFF);
        request.push_back(tx_size & 0xFF);
        
        // Add transaction data
        request.insert(request.end(), tx_data.begin(), tx_data.end());
        
        // Double encapsulate with node's Kyber public key
        auto encaps_result = FinalDefiSDK::instance().double_encapsulate(node.kyber_public_key);
        if (encaps_result.is_err()) {
            // Return connection to the pool
            return_connection_to_pool(node.hostname, node.port, ssl);
            return encaps_result.error();
        }
        
        auto [ciphertexts, shared_secret] = encaps_result.value();
        auto [ct1, ct2] = ciphertexts;
        
        // Encrypt request with shared secret
        auto encrypt_result = FinalDefiSDK::instance().encrypt_data(request, shared_secret);
        if (encrypt_result.is_err()) {
            // Return connection to the pool
            return_connection_to_pool(node.hostname, node.port, ssl);
            return encrypt_result.error();
        }
        
        ByteVector encrypted_request = encrypt_result.value();
        
        // Prepare final request with ciphertexts
        ByteVector final_request;
        
        // Add ciphertext 1 size
        uint32_t ct1_size = static_cast<uint32_t>(ct1.size());
        final_request.push_back((ct1_size >> 24) & 0xFF);
        final_request.push_back((ct1_size >> 16) & 0xFF);
        final_request.push_back((ct1_size >> 8) & 0xFF);
        final_request.push_back(ct1_size & 0xFF);
        
        // Add ciphertext 1
        final_request.insert(final_request.end(), ct1.begin(), ct1.end());
        
        // Add ciphertext 2 size
        uint32_t ct2_size = static_cast<uint32_t>(ct2.size());
        final_request.push_back((ct2_size >> 24) & 0xFF);
        final_request.push_back((ct2_size >> 16) & 0xFF);
        final_request.push_back((ct2_size >> 8) & 0xFF);
        final_request.push_back(ct2_size & 0xFF);
        
        // Add ciphertext 2
        final_request.insert(final_request.end(), ct2.begin(), ct2.end());
        
        // Add encrypted request size
        uint32_t er_size = static_cast<uint32_t>(encrypted_request.size());
        final_request.push_back((er_size >> 24) & 0xFF);
        final_request.push_back((er_size >> 16) & 0xFF);
        final_request.push_back((er_size >> 8) & 0xFF);
        final_request.push_back(er_size & 0xFF);
        
        // Add encrypted request
        final_request.insert(final_request.end(), encrypted_request.begin(), encrypted_request.end());
        
        // Sign the request with Dilithium
        auto sign_result = FinalDefiSDK::instance().sign_data(encrypted_request, signature_keys_.second);
        if (sign_result.is_err()) {
            // Return connection to the pool
            return_connection_to_pool(node.hostname, node.port, ssl);
            return sign_result.error();
        }
        
        ByteVector signature = sign_result.value();
        
        // Add signature size
        uint32_t sig_size = static_cast<uint32_t>(signature.size());
        final_request.push_back((sig_size >> 24) & 0xFF);
        final_request.push_back((sig_size >> 16) & 0xFF);
        final_request.push_back((sig_size >> 8) & 0xFF);
        final_request.push_back(sig_size & 0xFF);
        
        // Add signature
        final_request.insert(final_request.end(), signature.begin(), signature.end());
        
        // Send request
        auto send_result = FinalDefiSDK::instance().send_secure_data(ssl, final_request);
        if (send_result.is_err()) {
            // Close connection (don't return to pool - it's broken)
            FinalDefiSDK::instance().close_secure_connection(ssl);
            return send_result.error();
        }
        
        // Receive response
        auto recv_result = FinalDefiSDK::instance().receive_secure_data(ssl);
        
        // Return connection to the pool
        return_connection_to_pool(node.hostname, node.port, ssl);
        
        if (recv_result.is_err()) {
            return recv_result.error();
        }
        
        // Decrypt the response
        auto decrypt_result = FinalDefiSDK::instance().decrypt_data(recv_result.value(), shared_secret);
        if (decrypt_result.is_err()) {
            return decrypt_result.error();
        }
        
        ByteVector decrypted_response = decrypt_result.value();
        
        // Parse response
        if (decrypted_response.size() < 1) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        uint8_t status = decrypted_response[0];
        
        if (status != 0x00) {
            // Error status
            SecureLogger::instance().error("Light agent submission error: " + std::to_string(status));
            return ErrorCode::TRANSACTION_VALIDATION_FAILED;
        }
        
        // Check if there's a response payload
        if (decrypted_response.size() > 5) { // Status byte + 4 bytes for size
            uint32_t response_size = (decrypted_response[1] << 24) | 
                                    (decrypted_response[2] << 16) | 
                                    (decrypted_response[3] << 8) | 
                                    decrypted_response[4];
            
            if (decrypted_response.size() >= 5 + response_size) {
                ByteVector response_data(
                    decrypted_response.begin() + 5,
                    decrypted_response.begin() + 5 + response_size
                );
                
                return response_data;
            }
        }
        
        // No response payload
        return std::optional<ByteVector>();
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception submitting to light agent: " + std::string(e.what()));
        return ErrorCode::COMMUNICATION_FAILED;
    }
}

// Get the best nodes for a specific chain
Result<std::vector<NodeInfo>> SecureGateway::get_best_nodes_for_chain(uint32_t chain_id) {
    try {
        // Get active nodes
        auto nodes = node_registry_->get_active_nodes();
        
        // Filter nodes with capability for this chain
        std::string chain_capability = "light_agent_chain_" + std::to_string(chain_id);
        
        std::vector<NodeInfo> suitable_nodes;
        for (const auto& node : nodes) {
            auto it = node.capabilities.find(chain_capability);
            if (it != node.capabilities.end() && it->second == "true") {
                suitable_nodes.push_back(node);
            }
        }
        
        if (suitable_nodes.empty()) {
            return ErrorCode::NODE_NOT_FOUND;
        }
        
        // Sort by load factor
        std::sort(suitable_nodes.begin(), suitable_nodes.end(), 
                 [](const NodeInfo& a, const NodeInfo& b) {
                     return a.load_factor < b.load_factor;
                 });
        
        return suitable_nodes;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception getting best nodes: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Generate a transaction attestation
Result<Attestation> SecureGateway::generate_transaction_attestation(const Transaction& tx) {
    try {
        // Create new attestation
        Attestation attestation;
        attestation.id = Attestation::generate_id();
        attestation.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        attestation.type = Attestation::Type::TRANSACTION;
        
        // Add transaction ID to entity_ids
        attestation.entity_ids.push_back(tx.id);
        
        // Set chain ID
        attestation.chain_id = tx.chain_id;
        
        // Calculate transaction hash
        ByteVector tx_hash = tx.calculate_hash();
        
        // Sign with secure gateway key
        auto signature_result = FinalDefiSDK::instance().sign_data(tx_hash, signature_keys_.second);
        if (signature_result.is_err()) {
            return signature_result.error();
        }
        
        attestation.gateway_signature = signature_result.value();
        
        // Add metadata
        attestation.metadata["transaction_hash"] = bytes_to_hex(tx_hash);
        attestation.metadata["attestation_type"] = "transaction";
        attestation.metadata["chain_id"] = std::to_string(tx.chain_id);
        attestation.metadata["timestamp"] = std::to_string(attestation.timestamp);
        
        // Include sender address if available
        if (!tx.sender_address.empty()) {
            attestation.metadata["sender_address"] = bytes_to_hex(tx.sender_address);
        }
        
        return attestation;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception generating transaction attestation: " + std::string(e.what()));
        return ErrorCode::ATTESTATION_GENERATION_FAILED;
    }
}

// Generate an intent attestation
Result<Attestation> SecureGateway::generate_intent_attestation(
    const Transaction& tx, 
    const ByteVector& signature) {
    
    try {
        // Create new attestation
        Attestation attestation;
        attestation.id = Attestation::generate_id();
        attestation.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        attestation.type = Attestation::Type::CUSTOM;
        
        // Add transaction ID to entity_ids
        attestation.entity_ids.push_back(tx.id);
        
        // Set chain ID
        attestation.chain_id = tx.chain_id;
        
        // Calculate transaction hash
        ByteVector tx_hash = tx.calculate_hash();
        
        // Sign with secure gateway key
        auto gateway_sig_result = FinalDefiSDK::instance().sign_data(tx_hash, signature_keys_.second);
        if (gateway_sig_result.is_err()) {
            return gateway_sig_result.error();
        }
        
        attestation.gateway_signature = gateway_sig_result.value();
        
        // Add metadata
        attestation.metadata["transaction_hash"] = bytes_to_hex(tx_hash);
        attestation.metadata["attestation_type"] = "intent_verification";
        attestation.metadata["chain_id"] = std::to_string(tx.chain_id);
        attestation.metadata["timestamp"] = std::to_string(attestation.timestamp);
        attestation.metadata["user_signature"] = bytes_to_hex(signature);
        
        // Include sender address if available
        if (!tx.sender_address.empty()) {
            attestation.metadata["sender_address"] = bytes_to_hex(tx.sender_address);
        }
        
        return attestation;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception generating intent attestation: " + std::string(e.what()));
        return ErrorCode::ATTESTATION_GENERATION_FAILED;
    }
}

// Generate a completion attestation
Result<Attestation> SecureGateway::generate_completion_attestation(const Transaction& tx) {
    try {
        // Create new attestation
        Attestation attestation;
        attestation.id = Attestation::generate_id();
        attestation.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        attestation.type = Attestation::Type::CUSTOM;
        
        // Add transaction ID to entity_ids
        attestation.entity_ids.push_back(tx.id);
        
        // Set chain ID
        attestation.chain_id = tx.chain_id;
        
        // Calculate transaction hash
        ByteVector tx_hash = tx.calculate_hash();
        
        // Sign with secure gateway key
        auto signature_result = FinalDefiSDK::instance().sign_data(tx_hash, signature_keys_.second);
        if (signature_result.is_err()) {
            return signature_result.error();
        }
        
        attestation.gateway_signature = signature_result.value();
        
        // Add metadata
        attestation.metadata["transaction_hash"] = bytes_to_hex(tx_hash);
        attestation.metadata["attestation_type"] = "transaction_completion";
        attestation.metadata["chain_id"] = std::to_string(tx.chain_id);
        attestation.metadata["timestamp"] = std::to_string(attestation.timestamp);
        attestation.metadata["status"] = "completed";
        
        // Include response hash if available
        if (tx.response.has_value()) {
            ByteVector response_hash(crypto_generichash_BYTES);
            crypto_generichash(
                response_hash.data(), 
                response_hash.size(), 
                tx.response.value().data(), 
                tx.response.value().size(), 
                nullptr, 0
            );
            
            attestation.metadata["response_hash"] = bytes_to_hex(response_hash);
        }
        
        return attestation;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception generating completion attestation: " + std::string(e.what()));
        return ErrorCode::ATTESTATION_GENERATION_FAILED;
    }
}

// Process an epoch of transactions
void SecureGateway::process_epoch() {
    try {
        SecureLogger::instance().info("Processing epoch");
        
        // Collect attestations from buffer
        std::vector<Attestation> attestations;
        
        while (!attestation_buffer_.empty() && attestations.size() < MAX_ATTESTATIONS_PER_EPOCH) {
            attestations.push_back(attestation_buffer_.pop());
        }
        
        if (attestations.empty()) {
            SecureLogger::instance().debug("No attestations to process in epoch");
            return;
        }
        
        SecureLogger::instance().info("Processing " + std::to_string(attestations.size()) + " attestations in epoch");
        
        // Group attestations by type
        std::vector<Attestation> transaction_attestations;
        std::vector<Attestation> other_attestations;
        
        for (const auto& att : attestations) {
            if (att.type == Attestation::Type::TRANSACTION) {
                transaction_attestations.push_back(att);
            } else {
                other_attestations.push_back(att);
            }
        }
        
        // Process transaction attestations in a batch
        if (!transaction_attestations.empty()) {
            process_transaction_batch(transaction_attestations);
        }
        
        // Submit other attestations individually
        for (const auto& att : other_attestations) {
            submit_attestation_to_finalchain(att);
        }
        
        // Create epoch attestation
        auto epoch_result = create_epoch_attestation(attestations);
        if (epoch_result.is_ok()) {
            auto epoch_attestation = epoch_result.value();
            
            // Store epoch attestation
            attestation_store_->store_attestation(epoch_attestation);
            
            // Submit to FinalChain
            submit_attestation_to_finalchain(epoch_attestation);
            
            // Update metrics
            std::lock_guard<std::mutex> lock(metrics_mutex_);
            metrics_.last_epoch_time = std::chrono::system_clock::now();
            metrics_.last_batch_root = epoch_attestation.merkle_root.value_or(ByteVector());
            metrics_.total_epochs++;
        }
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during epoch processing: " + std::string(e.what()));
    }
}

// Process a batch of transaction attestations
void SecureGateway::process_transaction_batch(const std::vector<Attestation>& attestations) {
    try {
        SecureLogger::instance().info("Processing batch of " + std::to_string(attestations.size()) + " transactions");
        
        // Build Merkle tree of attestation hashes
        std::vector<ByteVector> attestation_hashes;
        for (const auto& att : attestations) {
            attestation_hashes.push_back(att.calculate_hash());
        }
        
        MerkleTree merkle_tree;
        merkle_tree.build(attestation_hashes);
        
        // Create batch attestation
        Attestation batch_attestation;
        batch_attestation.id = Attestation::generate_id();
        batch_attestation.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        batch_attestation.type = Attestation::Type::BATCH;
        
        // Collect entity IDs from all attestations
        for (const auto& att : attestations) {
            batch_attestation.entity_ids.insert(
                batch_attestation.entity_ids.end(), 
                att.entity_ids.begin(), 
                att.entity_ids.end()
            );
        }
        
        // Set Merkle root
        batch_attestation.merkle_root = merkle_tree.get_root_hash();
        
        // Sign with gateway key
        auto signature_result = FinalDefiSDK::instance().sign_data(
            batch_attestation.merkle_root.value(), 
            signature_keys_.second
        );
        
        if (signature_result.is_err()) {
            SecureLogger::instance().error("Failed to sign batch: " + signature_result.error_message());
            return;
        }
        
        batch_attestation.gateway_signature = signature_result.value();
        
        // Get quorum signatures
        auto quorum_result = get_quorum_signatures(batch_attestation.merkle_root.value());
        if (quorum_result.is_ok()) {
            batch_attestation.quorum_signatures = quorum_result.value();
        }
        
        // Add metadata
        batch_attestation.metadata["attestation_count"] = std::to_string(attestations.size());
        batch_attestation.metadata["attestation_type"] = "transaction_batch";
        batch_attestation.metadata["merkle_root"] = bytes_to_hex(batch_attestation.merkle_root.value());
        batch_attestation.metadata["timestamp"] = std::to_string(batch_attestation.timestamp);
        
        // Store batch attestation
        attestation_store_->store_attestation(batch_attestation);
        
        // Submit to FinalChain
        submit_attestation_to_finalchain(batch_attestation);
        
    }     catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during batch processing: " + std::string(e.what()));
    }
}

// Submit an attestation to FinalChain
void SecureGateway::submit_attestation_to_finalchain(const Attestation& attestation) {
    try {
        // Use the circuit breaker pattern
        attestation_circuit_breaker_.execute<void>([&]() {
            // Create a FinalChain submitter
            FinalChainSubmitter submitter(config_.finalchain_url);
            
            // Submit the attestation
            auto result = submitter.submit_attestation(attestation);
            
            if (result.is_err()) {
                SecureLogger::instance().error("Failed to submit attestation to FinalChain: " + 
                                      result.error_message());
                attestation_circuit_breaker_.record_failure("FinalChain submission failed");
                return;
            }
            
            ByteVector tx_hash = result.value();
            
            // Update the attestation with FinalChain tx hash
            Attestation updated_attestation = attestation;
            updated_attestation.metadata["finalchain_tx_hash"] = bytes_to_hex(tx_hash);
            attestation_store_->update_attestation(updated_attestation);
            
            // Update metrics
            std::lock_guard<std::mutex> lock(metrics_mutex_);
            metrics_.finalchain_submissions++;
            
            // Log success
            SecureLogger::instance().info("Attestation submitted to FinalChain: " + 
                                  bytes_to_hex(attestation.id) + 
                                  " with tx hash: " + bytes_to_hex(tx_hash));
        });
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception submitting attestation to FinalChain: " + 
                               std::string(e.what()));
        attestation_circuit_breaker_.record_failure(e.what());
    }
}

// Get quorum signatures from other nodes
Result<std::vector<std::pair<NodeId, ByteVector>>> SecureGateway::get_quorum_signatures(const ByteVector& data) {
    try {
        // Get active nodes
        auto nodes = node_registry_->get_active_nodes();
        
        // We need at least config_.quorum_threshold nodes
        if (nodes.size() < config_.quorum_threshold) {
            SecureLogger::instance().warning("Insufficient nodes for quorum: " + 
                                    std::to_string(nodes.size()) + 
                                    " nodes available, need " + 
                                    std::to_string(config_.quorum_threshold));
            return ErrorCode::QUORUM_NOT_REACHED;
        }
        
        // Sort nodes by ID to ensure deterministic order
        std::sort(nodes.begin(), nodes.end(), [](const NodeInfo& a, const NodeInfo& b) {
            return std::lexicographical_compare(
                a.id.begin(), a.id.end(),
                b.id.begin(), b.id.end()
            );
        });
        
        // Select the first config_.quorum_threshold nodes
        std::vector<NodeInfo> quorum_nodes(
            nodes.begin(),
            nodes.begin() + std::min(nodes.size(), config_.quorum_threshold)
        );
        
        // Collect signatures from nodes
        std::vector<std::pair<NodeId, ByteVector>> signatures;
        
        // Create thread pool for parallel signature collection
        ThreadPool signature_pool(quorum_nodes.size());
        std::vector<std::future<std::pair<NodeId, Result<ByteVector>>>> futures;
        
        // Request signatures from all nodes in parallel
        for (const auto& node : quorum_nodes) {
            futures.push_back(signature_pool.enqueue_normal(
                [this, &data, &node]() -> std::pair<NodeId, Result<ByteVector>> {
                    auto result = request_signature_from_node(data, node);
                    return std::make_pair(node.id, result);
                }
            ));
        }
        
        // Wait for all futures and collect results
        for (auto& future : futures) {
            auto [node_id, result] = future.get();
            
            if (result.is_ok()) {
                signatures.push_back(std::make_pair(node_id, result.value()));
            } else {
                SecureLogger::instance().warning("Failed to get signature from node: " + 
                                         bytes_to_hex(ByteVector(node_id.begin(), node_id.end())) + 
                                         " - " + result.error_message());
            }
        }
        
        // Check if we have enough signatures
        if (signatures.size() < config_.quorum_threshold) {
            SecureLogger::instance().error("Failed to collect enough signatures for quorum: " + 
                                   std::to_string(signatures.size()) + 
                                   " signatures collected, need " + 
                                   std::to_string(config_.quorum_threshold));
            return ErrorCode::QUORUM_NOT_REACHED;
        }
        
        return signatures;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception collecting quorum signatures: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Request a signature from a specific node
Result<ByteVector> SecureGateway::request_signature_from_node(
    const ByteVector& data, 
    const NodeInfo& node) {
    
    try {
        // Get a connection from the pool or create a new one
        auto conn_result = get_or_create_connection(node.hostname, node.port);
        if (conn_result.is_err()) {
            return conn_result.error();
        }
        
        SSL* ssl = conn_result.value();
        
        // Prepare request
        ByteVector request;
        
        // Add request type (1 byte)
        request.push_back(0x03); // 0x03 for signature request
        
        // Add data to sign
        uint32_t data_size = static_cast<uint32_t>(data.size());
        request.push_back((data_size >> 24) & 0xFF);
        request.push_back((data_size >> 16) & 0xFF);
        request.push_back((data_size >> 8) & 0xFF);
        request.push_back(data_size & 0xFF);
        
        request.insert(request.end(), data.begin(), data.end());
        
        // Double encapsulate with node's Kyber public key
        auto encaps_result = FinalDefiSDK::instance().double_encapsulate(node.kyber_public_key);
        if (encaps_result.is_err()) {
            // Return connection to the pool
            return_connection_to_pool(node.hostname, node.port, ssl);
            return encaps_result.error();
        }
        
        auto [ciphertexts, shared_secret] = encaps_result.value();
        auto [ct1, ct2] = ciphertexts;
        
        // Encrypt request with shared secret
        auto encrypt_result = FinalDefiSDK::instance().encrypt_data(request, shared_secret);
        if (encrypt_result.is_err()) {
            // Return connection to the pool
            return_connection_to_pool(node.hostname, node.port, ssl);
            return encrypt_result.error();
        }
        
        ByteVector encrypted_request = encrypt_result.value();
        
        // Prepare final request with ciphertexts
        ByteVector final_request;
        
        // Add ciphertext 1 size
        uint32_t ct1_size = static_cast<uint32_t>(ct1.size());
        final_request.push_back((ct1_size >> 24) & 0xFF);
        final_request.push_back((ct1_size >> 16) & 0xFF);
        final_request.push_back((ct1_size >> 8) & 0xFF);
        final_request.push_back(ct1_size & 0xFF);
        
        // Add ciphertext 1
        final_request.insert(final_request.end(), ct1.begin(), ct1.end());
        
        // Add ciphertext 2 size
        uint32_t ct2_size = static_cast<uint32_t>(ct2.size());
        final_request.push_back((ct2_size >> 24) & 0xFF);
        final_request.push_back((ct2_size >> 16) & 0xFF);
        final_request.push_back((ct2_size >> 8) & 0xFF);
        final_request.push_back(ct2_size & 0xFF);
        
        // Add ciphertext 2
        final_request.insert(final_request.end(), ct2.begin(), ct2.end());
        
        // Add encrypted request size
        uint32_t er_size = static_cast<uint32_t>(encrypted_request.size());
        final_request.push_back((er_size >> 24) & 0xFF);
        final_request.push_back((er_size >> 16) & 0xFF);
        final_request.push_back((er_size >> 8) & 0xFF);
        final_request.push_back(er_size & 0xFF);
        
        // Add encrypted request
        final_request.insert(final_request.end(), encrypted_request.begin(), encrypted_request.end());
        
        // Send request
        auto send_result = FinalDefiSDK::instance().send_secure_data(ssl, final_request);
        if (send_result.is_err()) {
            // Close connection (don't return to pool - it's broken)
            FinalDefiSDK::instance().close_secure_connection(ssl);
            return send_result.error();
        }
        
        // Receive response
        auto recv_result = FinalDefiSDK::instance().receive_secure_data(ssl);
        
        // Return connection to the pool
        return_connection_to_pool(node.hostname, node.port, ssl);
        
        if (recv_result.is_err()) {
            return recv_result.error();
        }
        
        // Decrypt the response
        auto decrypt_result = FinalDefiSDK::instance().decrypt_data(recv_result.value(), shared_secret);
        if (decrypt_result.is_err()) {
            return decrypt_result.error();
        }
        
        ByteVector decrypted_response = decrypt_result.value();
        
        // Parse response
        if (decrypted_response.size() < 5) { // Status byte + 4 bytes for size
            return ErrorCode::INVALID_PARAMETER;
        }
        
        uint8_t status = decrypted_response[0];
        
        if (status != 0x00) {
            // Error status
            SecureLogger::instance().error("Signature request error: " + std::to_string(status));
            return ErrorCode::SIGNATURE_FAILED;
        }
        
        // Extract signature
        uint32_t signature_size = (decrypted_response[1] << 24) | 
                                 (decrypted_response[2] << 16) | 
                                 (decrypted_response[3] << 8) | 
                                 decrypted_response[4];
        
        if (decrypted_response.size() < 5 + signature_size) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        ByteVector signature(
            decrypted_response.begin() + 5,
            decrypted_response.begin() + 5 + signature_size
        );
        
        return signature;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception requesting signature from node: " + std::string(e.what()));
        return ErrorCode::COMMUNICATION_FAILED;
    }
}

// Verify a transaction with quorum
Result<void> SecureGateway::verify_transaction_quorum(const Transaction& transaction) {
    try {
        // Calculate transaction hash
        ByteVector tx_hash = transaction.calculate_hash();
        
        // Get quorum verification from nodes
        auto quorum_result = get_quorum_verification(tx_hash, transaction.id, transaction.chain_id);
        if (quorum_result.is_err()) {
            SecureLogger::instance().error("Failed to get quorum verification: " + 
                                   quorum_result.error_message());
            return quorum_result.error();
        }
        
        // Success
        SecureLogger::instance().info("Transaction verified by quorum: " + bytes_to_hex(transaction.id));
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception verifying transaction with quorum: " + 
                               std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Get quorum verification from nodes
Result<void> SecureGateway::get_quorum_verification(
    const ByteVector& tx_hash, 
    const ByteVector& tx_id,
    uint32_t chain_id) {
    
    try {
        // Get active nodes
        auto nodes = node_registry_->get_active_nodes();
        
        // Filter nodes with capability for this chain
        std::string chain_capability = "light_agent_chain_" + std::to_string(chain_id);
        
        std::vector<NodeInfo> suitable_nodes;
        for (const auto& node : nodes) {
            auto it = node.capabilities.find(chain_capability);
            if (it != node.capabilities.end() && it->second == "true") {
                suitable_nodes.push_back(node);
            }
        }
        
        // We need at least config_.quorum_threshold nodes
        if (suitable_nodes.size() < config_.quorum_threshold) {
            SecureLogger::instance().warning("Insufficient nodes for quorum verification: " + 
                                    std::to_string(suitable_nodes.size()) + 
                                    " nodes available, need " + 
                                    std::to_string(config_.quorum_threshold));
            return ErrorCode::QUORUM_NOT_REACHED;
        }
        
        // Create thread pool for parallel verification
        ThreadPool verification_pool(suitable_nodes.size());
        std::vector<std::future<std::pair<NodeId, bool>>> futures;
        
        // Request verification from all nodes in parallel
        for (const auto& node : suitable_nodes) {
            futures.push_back(verification_pool.enqueue_normal(
                [this, &tx_hash, &tx_id, &node]() -> std::pair<NodeId, bool> {
                    bool verified = false;
                    
                    try {
                        auto result = request_verification_from_node(tx_hash, tx_id, node);
                        verified = result.is_ok();
                    } catch (...) {
                        verified = false;
                    }
                    
                    return std::make_pair(node.id, verified);
                }
            ));
        }
        
        // Wait for all futures and collect results
        size_t verified_count = 0;
        
        for (auto& future : futures) {
            auto [node_id, verified] = future.get();
            
            if (verified) {
                verified_count++;
                
                // If we have enough verifications, we can stop
                if (verified_count >= config_.quorum_threshold) {
                    break;
                }
            }
        }
        
        // Check if we have enough verifications
        if (verified_count < config_.quorum_threshold) {
            SecureLogger::instance().error("Failed to get enough verifications for quorum: " + 
                                   std::to_string(verified_count) + 
                                   " verifications collected, need " + 
                                   std::to_string(config_.quorum_threshold));
            return ErrorCode::QUORUM_NOT_REACHED;
        }
        
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception getting quorum verification: " + std::string(e.what()));
        return ErrorCode::INTERNAL_ERROR;
    }
}

// Request verification from a specific node
Result<void> SecureGateway::request_verification_from_node(
    const ByteVector& tx_hash, 
    const ByteVector& tx_id,
    const NodeInfo& node) {
    
    try {
        // Get a connection from the pool or create a new one
        auto conn_result = get_or_create_connection(node.hostname, node.port);
        if (conn_result.is_err()) {
            return conn_result.error();
        }
        
        SSL* ssl = conn_result.value();
        
        // Prepare request
        ByteVector request;
        
        // Add request type (1 byte)
        request.push_back(0x04); // 0x04 for verification request
        
        // Add tx_id
        uint32_t tx_id_size = static_cast<uint32_t>(tx_id.size());
        request.push_back((tx_id_size >> 24) & 0xFF);
        request.push_back((tx_id_size >> 16) & 0xFF);
        request.push_back((tx_id_size >> 8) & 0xFF);
        request.push_back(tx_id_size & 0xFF);
        
        request.insert(request.end(), tx_id.begin(), tx_id.end());
        
        // Add tx_hash
        uint32_t tx_hash_size = static_cast<uint32_t>(tx_hash.size());
        request.push_back((tx_hash_size >> 24) & 0xFF);
        request.push_back((tx_hash_size >> 16) & 0xFF);
        request.push_back((tx_hash_size >> 8) & 0xFF);
        request.push_back(tx_hash_size & 0xFF);
        
        request.insert(request.end(), tx_hash.begin(), tx_hash.end());
        
        // Double encapsulate with node's Kyber public key
        auto encaps_result = FinalDefiSDK::instance().double_encapsulate(node.kyber_public_key);
        if (encaps_result.is_err()) {
            // Return connection to the pool
            return_connection_to_pool(node.hostname, node.port, ssl);
            return encaps_result.error();
        }
        
        auto [ciphertexts, shared_secret] = encaps_result.value();
        auto [ct1, ct2] = ciphertexts;
        
        // Encrypt request with shared secret
        auto encrypt_result = FinalDefiSDK::instance().encrypt_data(request, shared_secret);
        if (encrypt_result.is_err()) {
            // Return connection to the pool
            return_connection_to_pool(node.hostname, node.port, ssl);
            return encrypt_result.error();
        }
        
        ByteVector encrypted_request = encrypt_result.value();
        
        // Prepare final request with ciphertexts
        ByteVector final_request;
        
        // Add ciphertext 1 size
        uint32_t ct1_size = static_cast<uint32_t>(ct1.size());
        final_request.push_back((ct1_size >> 24) & 0xFF);
        final_request.push_back((ct1_size >> 16) & 0xFF);
        final_request.push_back((ct1_size >> 8) & 0xFF);
        final_request.push_back(ct1_size & 0xFF);
        
        // Add ciphertext 1
        final_request.insert(final_request.end(), ct1.begin(), ct1.end());
        
        // Add ciphertext 2 size
        uint32_t ct2_size = static_cast<uint32_t>(ct2.size());
        final_request.push_back((ct2_size >> 24) & 0xFF);
        final_request.push_back((ct2_size >> 16) & 0xFF);
        final_request.push_back((ct2_size >> 8) & 0xFF);
        final_request.push_back(ct2_size & 0xFF);
        
        // Add ciphertext 2
        final_request.insert(final_request.end(), ct2.begin(), ct2.end());
        
        // Add encrypted request size
        uint32_t er_size = static_cast<uint32_t>(encrypted_request.size());
        final_request.push_back((er_size >> 24) & 0xFF);
        final_request.push_back((er_size >> 16) & 0xFF);
        final_request.push_back((er_size >> 8) & 0xFF);
        final_request.push_back(er_size & 0xFF);
        
        // Add encrypted request
        final_request.insert(final_request.end(), encrypted_request.begin(), encrypted_request.end());
        
        // Send request
        auto send_result = FinalDefiSDK::instance().send_secure_data(ssl, final_request);
        if (send_result.is_err()) {
            // Close connection (don't return to pool - it's broken)
            FinalDefiSDK::instance().close_secure_connection(ssl);
            return send_result.error();
        }
        
        // Receive response
        auto recv_result = FinalDefiSDK::instance().receive_secure_data(ssl);
        
        // Return connection to the pool
        return_connection_to_pool(node.hostname, node.port, ssl);
        
        if (recv_result.is_err()) {
            return recv_result.error();
        }
        
        // Decrypt the response
        auto decrypt_result = FinalDefiSDK::instance().decrypt_data(recv_result.value(), shared_secret);
        if (decrypt_result.is_err()) {
            return decrypt_result.error();
        }
        
        ByteVector decrypted_response = decrypt_result.value();
        
        // Parse response
        if (decrypted_response.size() < 1) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        uint8_t status = decrypted_response[0];
        
        if (status != 0x00) {
            // Error status
            SecureLogger::instance().error("Verification request error: " + std::to_string(status));
            return ErrorCode::VERIFICATION_FAILED;
        }
        
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception requesting verification from node: " + std::string(e.what()));
        return ErrorCode::COMMUNICATION_FAILED;
    }
}

// Create an epoch attestation
Result<Attestation> SecureGateway::create_epoch_attestation(const std::vector<Attestation>& attestations) {
    try {
        // Create new attestation
        Attestation epoch_attestation;
        epoch_attestation.id = Attestation::generate_id();
        epoch_attestation.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        epoch_attestation.type = Attestation::Type::EPOCH;
        
        // Collect batch IDs
        std::vector<ByteVector> batch_ids;
        for (const auto& att : attestations) {
            if (att.type == Attestation::Type::BATCH) {
                batch_ids.push_back(att.id);
            }
        }
        
        // Set entity IDs to batch IDs
        epoch_attestation.entity_ids = batch_ids;
        
        // Calculate Merkle root of all attestation hashes
        std::vector<ByteVector> attestation_hashes;
        for (const auto& att : attestations) {
            attestation_hashes.push_back(att.calculate_hash());
        }
        
        MerkleTree merkle_tree;
        merkle_tree.build(attestation_hashes);
        epoch_attestation.merkle_root = merkle_tree.get_root_hash();
        
        // Sign with gateway key
        auto signature_result = FinalDefiSDK::instance().sign_data(
            epoch_attestation.merkle_root.value(), 
            signature_keys_.second
        );
        
        if (signature_result.is_err()) {
            SecureLogger::instance().error("Failed to sign epoch: " + signature_result.error_message());
            return signature_result.error();
        }
        
        epoch_attestation.gateway_signature = signature_result.value();
        
        // Get quorum signatures
        auto quorum_result = get_quorum_signatures(epoch_attestation.merkle_root.value());
        if (quorum_result.is_ok()) {
            epoch_attestation.quorum_signatures = quorum_result.value();
        }
        
        // Add metadata
        epoch_attestation.metadata["attestation_count"] = std::to_string(attestations.size());
        epoch_attestation.metadata["batch_count"] = std::to_string(batch_ids.size());
        epoch_attestation.metadata["attestation_type"] = "epoch";
        epoch_attestation.metadata["merkle_root"] = bytes_to_hex(epoch_attestation.merkle_root.value());
        epoch_attestation.metadata["timestamp"] = std::to_string(epoch_attestation.timestamp);
        epoch_attestation.metadata["epoch_id"] = bytes_to_hex(epoch_attestation.id);
        
        SecureLogger::instance().info("Created epoch attestation with " + 
                              std::to_string(attestations.size()) + " attestations");
        
        return epoch_attestation;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception creating epoch attestation: " + std::string(e.what()));
        return ErrorCode::ATTESTATION_GENERATION_FAILED;
    }
}