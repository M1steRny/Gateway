#pragma once

#include "FinalDefiSDK.hpp"
#include <memory>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>

namespace finaldefi {
namespace secure_gateway {

using namespace finaldefi::sdk;

/**
 * @brief Audit layer for generating attestations and submitting to FinalChain
 */
class AuditLayer {
public:
    // Constructor
    AuditLayer(const std::string& finalchain_url, 
              std::shared_ptr<AttestationStore> attestation_store,
              std::shared_ptr<TransactionStore> transaction_store);
    
    // Destructor
    ~AuditLayer();
    
    // Start the audit layer
    void start();
    
    // Stop the audit layer
    void stop();
    
    // Submit a transaction attestation
    Result<ByteVector> submit_transaction_attestation(const Transaction& transaction);
    
    // Generate and submit a batch attestation
    Result<ByteVector> submit_batch_attestation(const std::vector<Transaction>& transactions);
    
    // Generate and submit an epoch attestation
    Result<ByteVector> submit_epoch_attestation(const ByteVector& merkle_root, 
                                             const std::vector<ByteVector>& batch_ids);
    
    // Generate cryptographic proofs for assets
    Result<ByteVector> generate_asset_proof(const Transaction& transaction);
    
    // Get attestation by ID
    Result<Attestation> get_attestation(const ByteVector& attestation_id);
    
    // Get all attestations
    std::vector<Attestation> get_all_attestations() const;
    
    // Get attestations by type
    std::vector<Attestation> get_attestations_by_type(Attestation::Type type) const;
    
    // Get metrics
    struct Metrics {
        size_t total_attestations;
        size_t transaction_attestations;
        size_t batch_attestations;
        size_t epoch_attestations;
        size_t finalchain_submissions;
        size_t failed_submissions;
        size_t queued_attestations;
    };
    Metrics get_metrics() const;
    
private:
    // Process the attestation queue
    void process_queue();
    
    // Worker thread function
    void worker_thread();
    
    // Submit attestation to FinalChain
    Result<ByteVector> submit_to_finalchain(const Attestation& attestation);
    
    // Generate a transaction attestation
    Result<Attestation> generate_transaction_attestation(const Transaction& transaction);
    
    // Generate a batch attestation
    Result<Attestation> generate_batch_attestation(const std::vector<Transaction>& transactions);
    
    // Generate an epoch attestation
    Result<Attestation> generate_epoch_attestation(const ByteVector& merkle_root, 
                                                const std::vector<ByteVector>& batch_ids);
    
    // Generate a cryptographic proof for an asset
    Result<ByteVector> generate_proof(const Transaction& transaction);
    
    // Helper functions for byte conversion
    std::string bytes_to_hex(const ByteVector& bytes);
    ByteVector hex_to_bytes(const std::string& hex);
    
    std::string finalchain_url_;
    std::shared_ptr<AttestationStore> attestation_store_;
    std::shared_ptr<TransactionStore> transaction_store_;
    std::unique_ptr<FinalChainSubmitter> finalchain_submitter_;
    
    // Queue for asynchronous attestation submission
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<Attestation> attestation_queue_;
    
    // Worker thread for processing the queue
    std::atomic<bool> running_{false};
    std::thread worker_thread_;
    
    // Metrics
    std::atomic<size_t> transaction_attestation_count_{0};
    std::atomic<size_t> batch_attestation_count_{0};
    std::atomic<size_t> epoch_attestation_count_{0};
    std::atomic<size_t> finalchain_submission_count_{0};
    std::atomic<size_t> failed_submission_count_{0};
    
    // Circuit breaker for FinalChain submissions
    CircuitBreaker finalchain_circuit_breaker_;
};

} // namespace secure_gateway
} // namespace finaldefi