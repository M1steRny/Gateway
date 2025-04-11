#pragma once

#include "FinalDefiSDK.hpp"
#include <atomic>
#include <memory>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <functional>
#include <future>

namespace finaldefi {
namespace secure_gateway {

using namespace finaldefi::sdk;

/**
 * @brief Transaction processor with fallback mechanisms for high reliability
 */
class TransactionProcessor {
public:
    // Constructor
    TransactionProcessor(std::shared_ptr<NodeRegistry> node_registry, 
                        std::shared_ptr<ThreadPool> thread_pool);
    
    // Destructor
    ~TransactionProcessor();
    
    // Start the processor
    void start();
    
    // Stop the processor
    void stop();
    
    // Submit a transaction for processing
    Result<void> submit_transaction(const Transaction& transaction);
    
    // Get the current queue size
    size_t get_queue_size() const;
    
    // Get the number of transactions processed
    size_t get_processed_count() const;
    
    // Get the number of transactions failed
    size_t get_failed_count() const;
    
    // Get the number of fallbacks used
    size_t get_fallback_count() const;
    
private:
    // Process a transaction with fallback
    Result<void> process_transaction_with_fallback(Transaction transaction);
    
    // Process a transaction on a specific node
    Result<void> process_transaction_on_node(const Transaction& transaction, const NodeInfo& node);
    
    // Find the best node for processing
    Result<NodeInfo> find_best_node(uint32_t chain_id);
    
    // Handle node failure and find fallback
    Result<NodeInfo> handle_node_failure(const NodeInfo& failed_node, uint32_t chain_id);
    
    // Worker thread function
    void worker_thread();
    
    // Record a node failure
    void record_node_failure(const NodeInfo& node);
    
    // Reset a node failure
    void reset_node_failure(const NodeInfo& node);
    
    // Check if a node is circuit broken
    bool is_node_circuit_broken(const NodeInfo& node);
    
    // Helper to convert bytes to hex string
    static std::string bytes_to_hex(const ByteVector& bytes);
    
    std::shared_ptr<NodeRegistry> node_registry_;
    std::shared_ptr<ThreadPool> thread_pool_;
    
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<Transaction> transaction_queue_;
    
    std::atomic<bool> running_{false};
    std::vector<std::thread> worker_threads_;
    
    // Performance metrics
    std::atomic<size_t> processed_count_{0};
    std::atomic<size_t> failed_count_{0};
    std::atomic<size_t> fallback_count_{0};
    
    // Node failure tracking for circuit breaking
    std::mutex node_failures_mutex_;
    std::unordered_map<std::string, std::pair<size_t, std::chrono::steady_clock::time_point>> node_failures_;
    
    // Constants
    static constexpr size_t MAX_WORKER_THREADS = 16;
    static constexpr size_t MAX_FAILURES_BEFORE_CIRCUIT_BREAK = 3;
    static constexpr std::chrono::seconds CIRCUIT_BREAK_DURATION = std::chrono::seconds(60);
};

} // namespace secure_gateway
} // namespace finaldefi