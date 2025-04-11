#include "TransactionProcessor.hpp"
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace finaldefi {
namespace secure_gateway {

TransactionProcessor::TransactionProcessor(std::shared_ptr<NodeRegistry> node_registry,
                                         std::shared_ptr<ThreadPool> thread_pool)
    : node_registry_(node_registry), thread_pool_(thread_pool) {
}

TransactionProcessor::~TransactionProcessor() {
    stop();
}

void TransactionProcessor::start() {
    if (running_) {
        SecureLogger::instance().warning("Transaction processor already running");
        return;
    }
    
    running_ = true;
    
    // Start worker threads
    size_t num_threads = std::min(MAX_WORKER_THREADS, std::thread::hardware_concurrency());
    for (size_t i = 0; i < num_threads; ++i) {
        worker_threads_.emplace_back(&TransactionProcessor::worker_thread, this);
    }
    
    SecureLogger::instance().info("Transaction processor started with " + 
                           std::to_string(num_threads) + " worker threads");
}

void TransactionProcessor::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    // Wake up all worker threads
    queue_cv_.notify_all();
    
    // Join all worker threads
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    worker_threads_.clear();
    
    SecureLogger::instance().info("Transaction processor stopped");
}

Result<void> TransactionProcessor::submit_transaction(const Transaction& transaction) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        transaction_queue_.push(transaction);
    }
    
    // Notify one worker thread
    queue_cv_.notify_one();
    
    return ErrorCode::SUCCESS;
}

size_t TransactionProcessor::get_queue_size() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return transaction_queue_.size();
}

size_t TransactionProcessor::get_processed_count() const {
    return processed_count_.load();
}

size_t TransactionProcessor::get_failed_count() const {
    return failed_count_.load();
}

size_t TransactionProcessor::get_fallback_count() const {
    return fallback_count_.load();
}

void TransactionProcessor::worker_thread() {
    while (running_) {
        Transaction tx;
        
        // Get a transaction from the queue
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            // Wait for a transaction or stop signal
            queue_cv_.wait(lock, [this] {
                return !running_ || !transaction_queue_.empty();
            });
            
            if (!running_) {
                break;
            }
            
            if (transaction_queue_.empty()) {
                continue;
            }
            
            tx = transaction_queue_.front();
            transaction_queue_.pop();
        }
        
        // Process the transaction with fallback
        auto result = process_transaction_with_fallback(tx);
        
        if (result.is_ok()) {
            processed_count_++;
        } else {
            failed_count_++;
        }
    }
}

Result<void> TransactionProcessor::process_transaction_with_fallback(Transaction transaction) {
    // Find the best node for processing
    auto best_node_result = find_best_node(transaction.chain_id);
    if (best_node_result.is_err()) {
        SecureLogger::instance().error("Failed to find node for chain " + 
                               std::to_string(transaction.chain_id) + ": " + 
                               best_node_result.error_message());
        return best_node_result.error();
    }
    
    NodeInfo node = best_node_result.value();
    
    // Try to process on the selected node
    auto result = process_transaction_on_node(transaction, node);
    
    // If failed, try fallback nodes
    if (result.is_err()) {
        SecureLogger::instance().warning("Failed to process transaction on node " + 
                                 node.hostname + ":" + std::to_string(node.port) + 
                                 ": " + result.error_message());
        
        // Find fallback node
        auto fallback_result = handle_node_failure(node, transaction.chain_id);
        if (fallback_result.is_err()) {
            // No fallback available
            SecureLogger::instance().error("No fallback available for chain " + 
                                   std::to_string(transaction.chain_id));
            return fallback_result.error();
        }
        
        NodeInfo fallback_node = fallback_result.value();
        
        SecureLogger::instance().info("Using fallback node " + 
                               fallback_node.hostname + ":" + std::to_string(fallback_node.port));
        
        // Try fallback node
        fallback_count_++;
        result = process_transaction_on_node(transaction, fallback_node);
        
        if (result.is_err()) {
            // Fallback also failed
            SecureLogger::instance().error("Fallback node also failed: " + result.error_message());
            return result;
        }
    }
    
    return ErrorCode::SUCCESS;
}

Result<void> TransactionProcessor::process_transaction_on_node(const Transaction& transaction, const NodeInfo& node) {
    try {
        // Create PQNetworking instance
        PQNetworking networking;
        auto init_result = networking.initialize_ssl();
        if (init_result.is_err()) {
            return init_result.error();
        }
        
        // Connect to the node
        auto conn_result = networking.create_connection(node.hostname, node.port);
        if (conn_result.is_err()) {
            record_node_failure(node);
            return conn_result.error();
        }
        
        SSL* ssl = conn_result.value();
        
        // Serialize transaction
        ByteVector tx_data = transaction.serialize();
        
        // Prepare request
        ByteVector request;
        request.push_back(0x01); // 0x01 for transaction submission
        
        // Add transaction size (4 bytes)
        uint32_t tx_size = static_cast<uint32_t>(tx_data.size());
        request.push_back((tx_size >> 24) & 0xFF);
        request.push_back((tx_size >> 16) & 0xFF);
        request.push_back((tx_size >> 8) & 0xFF);
        request.push_back(tx_size & 0xFF);
        
        // Add transaction data
        request.insert(request.end(), tx_data.begin(), tx_data.end());
        
        // Encrypt request with node's public key
        auto encaps_result = KYBER::double_encapsulate(node.kyber_public_key);
        if (encaps_result.is_err()) {
            networking.close_connection(ssl);
            return encaps_result.error();
        }
        
        auto [ciphertexts, shared_secret] = encaps_result.value();
        auto [ct1, ct2] = ciphertexts;
        
        // Encrypt request
        auto encrypt_result = KYBER::encrypt_data(request, shared_secret);
        if (encrypt_result.is_err()) {
            networking.close_connection(ssl);
            return encrypt_result.error();
        }
        
        ByteVector encrypted_request = encrypt_result.value();
        
        // Prepare message with ciphertexts and encrypted request
        ByteVector message;
        
        // Add ciphertext 1 size
        uint32_t ct1_size = static_cast<uint32_t>(ct1.size());
        message.push_back((ct1_size >> 24) & 0xFF);
        message.push_back((ct1_size >> 16) & 0xFF);
        message.push_back((ct1_size >> 8) & 0xFF);
        message.push_back(ct1_size & 0xFF);
        
        // Add ciphertext 1
        message.insert(message.end(), ct1.begin(), ct1.end());
        
        // Add ciphertext 2 size
        uint32_t ct2_size = static_cast<uint32_t>(ct2.size());
        message.push_back((ct2_size >> 24) & 0xFF);
        message.push_back((ct2_size >> 16) & 0xFF);
        message.push_back((ct2_size >> 8) & 0xFF);
        message.push_back(ct2_size & 0xFF);
        
        // Add ciphertext 2
        message.insert(message.end(), ct2.begin(), ct2.end());
        
        // Add encrypted request size
        uint32_t er_size = static_cast<uint32_t>(encrypted_request.size());
        message.push_back((er_size >> 24) & 0xFF);
        message.push_back((er_size >> 16) & 0xFF);
        message.push_back((er_size >> 8) & 0xFF);
        message.push_back(er_size & 0xFF);
        
        // Add encrypted request
        message.insert(message.end(), encrypted_request.begin(), encrypted_request.end());
        
        // Send message
        auto send_result = networking.send_data(ssl, message);
        if (send_result.is_err()) {
            networking.close_connection(ssl);
            record_node_failure(node);
            return send_result.error();
        }
        
        // Receive response
        auto recv_result = networking.receive_data(ssl);
        networking.close_connection(ssl);
        
        if (recv_result.is_err()) {
            record_node_failure(node);
            return recv_result.error();
        }
        
        ByteVector response = recv_result.value();
        
        // Decrypt response with shared secret
        auto decrypt_result = KYBER::decrypt_data(response, shared_secret);
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
            return ErrorCode::TRANSACTION_VALIDATION_FAILED;
        }
        
        // Reset node failure count on success
        reset_node_failure(node);
        
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception processing transaction on node: " + std::string(e.what()));
        record_node_failure(node);
        return ErrorCode::INTERNAL_ERROR;
    }
}

Result<NodeInfo> TransactionProcessor::find_best_node(uint32_t chain_id) {
    // Get active nodes
    auto nodes = node_registry_->get_active_nodes();
    
    // Filter nodes with capability for this chain
    std::vector<NodeInfo> suitable_nodes;
    std::string chain_capability = "light_agent_chain_" + std::to_string(chain_id);
    
    for (const auto& node : nodes) {
        // Skip nodes that are circuit broken
        if (is_node_circuit_broken(node)) {
            continue;
        }
        
        auto it = node.capabilities.find(chain_capability);
        if (it != node.capabilities.end()) {
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
    
    // Return the node with lowest load
    return suitable_nodes.front();
}

Result<NodeInfo> TransactionProcessor::handle_node_failure(const NodeInfo& failed_node, uint32_t chain_id) {
    // Find another node for the same chain, excluding the failed one
    auto nodes = node_registry_->get_active_nodes();
    
    // Filter nodes with capability for this chain, excluding the failed one
    std::vector<NodeInfo> suitable_nodes;
    std::string chain_capability = "light_agent_chain_" + std::to_string(chain_id);
    
    for (const auto& node : nodes) {
        // Skip the failed node
        if (std::equal(node.id.begin(), node.id.end(), failed_node.id.begin())) {
            continue;
        }
        
        // Skip nodes that are circuit broken
        if (is_node_circuit_broken(node)) {
            continue;
        }
        
        auto it = node.capabilities.find(chain_capability);
        if (it != node.capabilities.end()) {
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
    
    // Return the node with lowest load
    return suitable_nodes.front();
}

void TransactionProcessor::record_node_failure(const NodeInfo& node) {
    std::lock_guard<std::mutex> lock(node_failures_mutex_);
    
    std::string node_id = bytes_to_hex(ByteVector(node.id.begin(), node.id.end()));
    
    auto it = node_failures_.find(node_id);
    if (it == node_failures_.end()) {
        // First failure
        node_failures_[node_id] = {1, std::chrono::steady_clock::now()};
    } else {
        // Increment failure count
        it->second.first++;
        it->second.second = std::chrono::steady_clock::now();
    }
}

void TransactionProcessor::reset_node_failure(const NodeInfo& node) {
    std::lock_guard<std::mutex> lock(node_failures_mutex_);
    
    std::string node_id = bytes_to_hex(ByteVector(node.id.begin(), node.id.end()));
    
    auto it = node_failures_.find(node_id);
    if (it != node_failures_.end()) {
        // Reset failure count
        node_failures_.erase(it);
    }
}

bool TransactionProcessor::is_node_circuit_broken(const NodeInfo& node) {
    std::lock_guard<std::mutex> lock(node_failures_mutex_);
    
    std::string node_id = bytes_to_hex(ByteVector(node.id.begin(), node.id.end()));
    
    auto it = node_failures_.find(node_id);
    if (it == node_failures_.end()) {
        // No failures
        return false;
    }
    
    auto [failure_count, last_failure] = it->second;
    
    // Check if circuit breaker threshold is reached
    if (failure_count >= MAX_FAILURES_BEFORE_CIRCUIT_BREAK) {
        // Check if circuit breaker duration has elapsed
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_failure);
        
        if (elapsed < CIRCUIT_BREAK_DURATION) {
            // Circuit still open
            return true;
        } else {
            // Circuit breaker duration elapsed, reset failures
            node_failures_.erase(it);
            return false;
        }
    }
    
    return false;
}

// Helper function to convert bytes to hex string
std::string TransactionProcessor::bytes_to_hex(const ByteVector& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (const auto& byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return ss.str();
}

} // namespace secure_gateway
} // namespace finaldefi