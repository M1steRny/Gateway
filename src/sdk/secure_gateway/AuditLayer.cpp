/**
 * @file AuditLayer.cpp
 * @brief Implementation of the audit layer for generating attestations and submitting to FinalChain
 */

 #include "finaldefi/secure_gateway/AuditLayer.hpp"
 #include "finaldefi/sdk/MessageCompression.hpp"
 #include <chrono>
 #include <iomanip>
 #include <sstream>
 #include <algorithm>
 #include <random>
 
 namespace finaldefi {
 namespace secure_gateway {
 
 AuditLayer::AuditLayer(const std::string& finalchain_url,
                      std::shared_ptr<AttestationStore> attestation_store,
                      std::shared_ptr<TransactionStore> transaction_store)
     : finalchain_url_(finalchain_url),
       attestation_store_(attestation_store),
       transaction_store_(transaction_store),
       finalchain_circuit_breaker_(constants::CIRCUIT_BREAKER_THRESHOLD, 
                                  constants::CIRCUIT_BREAKER_RESET_TIMEOUT) {
     
     // Initialize FinalChain submitter
     finalchain_submitter_ = std::make_unique<FinalChainSubmitter>(finalchain_url_);
     
     SecureLogger::instance().info("AuditLayer initialized with FinalChain URL: " + finalchain_url_);
 }
 
 AuditLayer::~AuditLayer() {
     stop();
 }
 
 void AuditLayer::start() {
     if (running_) {
         SecureLogger::instance().warning("Audit layer already running");
         return;
     }
     
     running_ = true;
     
     // Start worker thread
     worker_thread_ = std::thread(&AuditLayer::worker_thread, this);
     
     SecureLogger::instance().info("Audit layer started");
 }
 
 void AuditLayer::stop() {
     if (!running_) {
         return;
     }
     
     running_ = false;
     
     // Wake up worker thread
     queue_cv_.notify_all();
     
     // Join worker thread
     if (worker_thread_.joinable()) {
         worker_thread_.join();
     }
     
     SecureLogger::instance().info("Audit layer stopped");
 }
 
 Result<ByteVector> AuditLayer::submit_transaction_attestation(const Transaction& transaction) {
     try {
         // Generate transaction attestation
         auto attestation_result = generate_transaction_attestation(transaction);
         if (attestation_result.is_err()) {
             SecureLogger::instance().error("Failed to generate transaction attestation: " + 
                                   attestation_result.error_message());
             return attestation_result.error();
         }
         
         Attestation attestation = attestation_result.value();
         
         // Store the attestation
         auto store_result = attestation_store_->store_attestation(attestation);
         if (store_result.is_err()) {
             SecureLogger::instance().error("Failed to store transaction attestation: " + 
                                   store_result.error_message());
             return store_result.error();
         }
         
         // Queue for submission to FinalChain
         {
             std::lock_guard<std::mutex> lock(queue_mutex_);
             attestation_queue_.push(attestation);
         }
         
         // Notify worker thread
         queue_cv_.notify_one();
         
         // Update metrics
         transaction_attestation_count_++;
         
         SecureLogger::instance().info("Transaction attestation queued for submission: " + 
                               bytes_to_hex(attestation.id));
         
         return attestation.id;
         
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception in submit_transaction_attestation: " + std::string(e.what()));
         return ErrorCode::ATTESTATION_GENERATION_FAILED;
     }
 }
 
 Result<ByteVector> AuditLayer::submit_batch_attestation(const std::vector<Transaction>& transactions) {
     try {
         // Generate batch attestation
         auto attestation_result = generate_batch_attestation(transactions);
         if (attestation_result.is_err()) {
             SecureLogger::instance().error("Failed to generate batch attestation: " + 
                                   attestation_result.error_message());
             return attestation_result.error();
         }
         
         Attestation attestation = attestation_result.value();
         
         // Store the attestation
         auto store_result = attestation_store_->store_attestation(attestation);
         if (store_result.is_err()) {
             SecureLogger::instance().error("Failed to store batch attestation: " + 
                                   store_result.error_message());
             return store_result.error();
         }
         
         // Queue for submission to FinalChain
         {
             std::lock_guard<std::mutex> lock(queue_mutex_);
             attestation_queue_.push(attestation);
         }
         
         // Notify worker thread
         queue_cv_.notify_one();
         
         // Update metrics
         batch_attestation_count_++;
         
         SecureLogger::instance().info("Batch attestation queued for submission: " + 
                               bytes_to_hex(attestation.id));
         
         return attestation.id;
         
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception in submit_batch_attestation: " + std::string(e.what()));
         return ErrorCode::ATTESTATION_GENERATION_FAILED;
     }
 }
 
 Result<ByteVector> AuditLayer::submit_epoch_attestation(const ByteVector& merkle_root,
                                                      const std::vector<ByteVector>& batch_ids) {
     try {
         // Generate epoch attestation
         auto attestation_result = generate_epoch_attestation(merkle_root, batch_ids);
         if (attestation_result.is_err()) {
             SecureLogger::instance().error("Failed to generate epoch attestation: " + 
                                   attestation_result.error_message());
             return attestation_result.error();
         }
         
         Attestation attestation = attestation_result.value();
         
         // Store the attestation
         auto store_result = attestation_store_->store_attestation(attestation);
         if (store_result.is_err()) {
             SecureLogger::instance().error("Failed to store epoch attestation: " + 
                                   store_result.error_message());
             return store_result.error();
         }
         
         // Queue for submission to FinalChain
         {
             std::lock_guard<std::mutex> lock(queue_mutex_);
             attestation_queue_.push(attestation);
             
             // Epoch attestations are high priority, so we move it to the front
             // This is a simple prioritization mechanism
             std::queue<Attestation> temp_queue;
             temp_queue.push(attestation);
             
             while (!attestation_queue_.empty()) {
                 if (attestation_queue_.front().id != attestation.id) {
                     temp_queue.push(attestation_queue_.front());
                 }
                 attestation_queue_.pop();
             }
             
             attestation_queue_.swap(temp_queue);
         }
         
         // Notify worker thread
         queue_cv_.notify_one();
         
         // Update metrics
         epoch_attestation_count_++;
         
         SecureLogger::instance().info("Epoch attestation queued for submission: " + 
                               bytes_to_hex(attestation.id));
         
         return attestation.id;
         
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception in submit_epoch_attestation: " + std::string(e.what()));
         return ErrorCode::ATTESTATION_GENERATION_FAILED;
     }
 }
 
 Result<ByteVector> AuditLayer::generate_asset_proof(const Transaction& transaction) {
     try {
         return generate_proof(transaction);
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception in generate_asset_proof: " + std::string(e.what()));
         return ErrorCode::ATTESTATION_GENERATION_FAILED;
     }
 }
 
 Result<Attestation> AuditLayer::get_attestation(const ByteVector& attestation_id) {
     return attestation_store_->load_attestation(attestation_id);
 }
 
 std::vector<Attestation> AuditLayer::get_all_attestations() const {
     auto result = attestation_store_->get_all_attestations();
     if (result.is_err()) {
         SecureLogger::instance().error("Failed to get all attestations: " + 
                               result.error_message());
         return {};
     }
     return result.value();
 }
 
 std::vector<Attestation> AuditLayer::get_attestations_by_type(Attestation::Type type) const {
     auto result = attestation_store_->get_attestations_by_type(type);
     if (result.is_err()) {
         SecureLogger::instance().error("Failed to get attestations by type: " + 
                               result.error_message());
         return {};
     }
     return result.value();
 }
 
 AuditLayer::Metrics AuditLayer::get_metrics() const {
     Metrics metrics;
     
     metrics.transaction_attestations = transaction_attestation_count_;
     metrics.batch_attestations = batch_attestation_count_;
     metrics.epoch_attestations = epoch_attestation_count_;
     metrics.finalchain_submissions = finalchain_submission_count_;
     metrics.failed_submissions = failed_submission_count_;
     
     // Calculate total attestations
     metrics.total_attestations = metrics.transaction_attestations +
                                 metrics.batch_attestations +
                                 metrics.epoch_attestations;
     
     // Get queue size
     {
         std::lock_guard<std::mutex> lock(queue_mutex_);
         metrics.queued_attestations = attestation_queue_.size();
     }
     
     return metrics;
 }
 
 void AuditLayer::process_queue() {
     while (running_) {
         Attestation attestation;
         bool has_attestation = false;
         
         // Get an attestation from the queue
         {
             std::unique_lock<std::mutex> lock(queue_mutex_);
             
             // Wait for an attestation or stop signal
             queue_cv_.wait(lock, [this] {
                 return !running_ || !attestation_queue_.empty();
             });
             
             if (!running_) {
                 break;
             }
             
             if (attestation_queue_.empty()) {
                 continue;
             }
             
             attestation = attestation_queue_.front();
             attestation_queue_.pop();
             has_attestation = true;
         }
         
         if (has_attestation) {
             // Submit to FinalChain with backoff retry strategy
             bool submitted = false;
             for (int retry = 0; retry < 3 && !submitted && running_; ++retry) {
                 if (retry > 0) {
                     // Exponential backoff
                     std::this_thread::sleep_for(std::chrono::seconds(1 << retry));
                 }
                 
                 auto result = submit_to_finalchain(attestation);
                 
                 if (result.is_ok()) {
                     // Update attestation with FinalChain tx hash
                     attestation.metadata["finalchain_tx_hash"] = bytes_to_hex(result.value());
                     attestation_store_->update_attestation(attestation);
                     
                     finalchain_submission_count_++;
                     submitted = true;
                     
                     // Update transaction status if this is a transaction attestation
                     if (attestation.type == Attestation::Type::TRANSACTION && 
                         !attestation.entity_ids.empty()) {
                         
                         auto tx_result = transaction_store_->load_transaction(attestation.entity_ids[0]);
                         if (tx_result.is_ok()) {
                             Transaction tx = tx_result.value();
                             tx.finalchain_tx_hash = result.value();
                             transaction_store_->update_transaction(tx);
                         }
                     }
                 } else {
                     SecureLogger::instance().warning("Failed to submit attestation to FinalChain (attempt " + 
                                           std::to_string(retry + 1) + "): " + 
                                           result.error_message());
                 }
             }
             
             if (!submitted) {
                 // Failed all retries, increment failure count
                 failed_submission_count_++;
                 
                 // Log error
                 SecureLogger::instance().error("Failed to submit attestation " + 
                                       bytes_to_hex(attestation.id) + 
                                       " to FinalChain after multiple retries");
                 
                 // Requeue if still running (unless we've already tried too many times)
                 if (running_) {
                     auto attempt_it = attestation.metadata.find("submission_attempts");
                     int attempts = 0;
                     
                     if (attempt_it != attestation.metadata.end()) {
                         attempts = std::stoi(attempt_it->second);
                     }
                     
                     // Only requeue if we haven't exceeded the maximum attempts
                     if (attempts < 5) {
                         attestation.metadata["submission_attempts"] = std::to_string(attempts + 1);
                         attestation_store_->update_attestation(attestation);
                         
                         std::lock_guard<std::mutex> lock(queue_mutex_);
                         attestation_queue_.push(attestation);
                     } else {
                         SecureLogger::instance().error("Abandoning attestation " + 
                                               bytes_to_hex(attestation.id) + 
                                               " after 5 failed submission attempts");
                     }
                 }
             }
         }
     }
 }
 
 void AuditLayer::worker_thread() {
     SecureLogger::instance().info("AuditLayer worker thread started");
     
     // Process the queue
     process_queue();
     
     SecureLogger::instance().info("AuditLayer worker thread stopped");
 }
 
 Result<ByteVector> AuditLayer::submit_to_finalchain(const Attestation& attestation) {
     return finalchain_circuit_breaker_.execute<ByteVector>([&]() {
         // Compress attestation for efficiency
         ByteVector serialized_attestation = attestation.serialize();
         auto compressed_result = MessageCompression::compress(serialized_attestation);
         
         if (compressed_result.is_err()) {
             SecureLogger::instance().warning("Failed to compress attestation: " + 
                                    compressed_result.error_message());
             // Fall back to uncompressed
             return finalchain_submitter_->submit_attestation(attestation);
         }
         
         // Decompress to verify integrity
         auto decompressed_result = MessageCompression::decompress(compressed_result.value());
         if (decompressed_result.is_err() || decompressed_result.value() != serialized_attestation) {
             SecureLogger::instance().warning("Compression verification failed, using uncompressed");
             return finalchain_submitter_->submit_attestation(attestation);
         }
         
         // Create a temporary attestation with compression metadata
         Attestation compressed_attestation = attestation;
         compressed_attestation.metadata["compressed"] = "true";
         compressed_attestation.metadata["original_size"] = std::to_string(serialized_attestation.size());
         compressed_attestation.metadata["compressed_size"] = std::to_string(compressed_result.value().size());
         
         // Submit the compressed attestation
         return finalchain_submitter_->submit_attestation(compressed_attestation);
     });
 }
 
 Result<Attestation> AuditLayer::generate_transaction_attestation(const Transaction& transaction) {
     try {
         // Create new attestation
         Attestation attestation;
         attestation.id = Attestation::generate_id();
         attestation.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch()
         ).count();
         attestation.type = Attestation::Type::TRANSACTION;
         
         // Add transaction ID to entity_ids
         attestation.entity_ids.push_back(transaction.id);
         
         // Set chain ID
         attestation.chain_id = transaction.chain_id;
         
         // Calculate transaction hash
         ByteVector tx_hash = transaction.calculate_hash();
         
         // Sign with secure gateway key (get from Dilithium)
         auto dilithium = std::make_unique<DilithiumSignature>();
         dilithium->initialize();
         
         // Generate ephemeral keypair for this attestation
         auto keypair_result = dilithium->generate_keypair();
         if (keypair_result.is_err()) {
             SecureLogger::instance().error("Failed to generate keypair for transaction attestation: " + 
                                   keypair_result.error_message());
             return keypair_result.error();
         }
         
         auto [public_key, secret_key] = keypair_result.value();
         
         // Sign transaction hash
         auto signature_result = dilithium->sign(tx_hash, secret_key);
         if (signature_result.is_err()) {
             SecureLogger::instance().error("Failed to sign transaction attestation: " + 
                                   signature_result.error_message());
             return signature_result.error();
         }
         
         attestation.gateway_signature = signature_result.value();
         
         // Add metadata
         attestation.metadata["transaction_hash"] = bytes_to_hex(tx_hash);
         attestation.metadata["attestation_type"] = "transaction";
         attestation.metadata["chain_id"] = std::to_string(transaction.chain_id);
         attestation.metadata["timestamp"] = std::to_string(attestation.timestamp);
         
         // Add security metadata
         attestation.metadata["signature_algorithm"] = "dilithium3";
         attestation.metadata["hash_algorithm"] = "blake2b";
         
         // Include sender address if available
         if (!transaction.sender_address.empty()) {
             attestation.metadata["sender_address"] = bytes_to_hex(transaction.sender_address);
         }
         
         // Include additional information for auditability
         if (!transaction.gateway_signature.empty()) {
             attestation.metadata["has_gateway_signature"] = "true";
         }
         
         if (!transaction.user_signature.empty()) {
             attestation.metadata["has_user_signature"] = "true";
         }
         
         SecureLogger::instance().info("Generated transaction attestation: " + bytes_to_hex(attestation.id));
         return attestation;
         
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception generating transaction attestation: " + std::string(e.what()));
         return ErrorCode::ATTESTATION_GENERATION_FAILED;
     }
 }
 
 Result<Attestation> AuditLayer::generate_batch_attestation(const std::vector<Transaction>& transactions) {
     try {
         // Create new attestation
         Attestation attestation;
         attestation.id = Attestation::generate_id();
         attestation.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch()
         ).count();
         attestation.type = Attestation::Type::BATCH;
         
         // Prepare for Merkle tree construction
         std::vector<ByteVector> transaction_hashes;
         for (const auto& tx : transactions) {
             // Add transaction ID to entity_ids
             attestation.entity_ids.push_back(tx.id);
             
             // Add hash for Merkle tree
             transaction_hashes.push_back(tx.calculate_hash());
         }
         
         // Sort hashes for deterministic tree construction
         std::sort(transaction_hashes.begin(), transaction_hashes.end());
         
         // Build Merkle tree
         MerkleTree merkle_tree;
         merkle_tree.build(transaction_hashes);
         ByteVector merkle_root = merkle_tree.get_root_hash();
         
         // Set Merkle root
         attestation.merkle_root = merkle_root;
         
         // Set chain ID if all transactions are for the same chain
         bool same_chain = true;
         uint32_t first_chain_id = transactions[0].chain_id;
         
         for (size_t i = 1; i < transactions.size(); ++i) {
             if (transactions[i].chain_id != first_chain_id) {
                 same_chain = false;
                 break;
             }
         }
         
         if (same_chain) {
             attestation.chain_id = first_chain_id;
         }
         
         // Sign with secure gateway key (get from Dilithium)
         auto dilithium = std::make_unique<DilithiumSignature>();
         dilithium->initialize();
         
         // Generate ephemeral keypair for this attestation
         auto keypair_result = dilithium->generate_keypair();
         if (keypair_result.is_err()) {
             SecureLogger::instance().error("Failed to generate keypair for batch attestation: " + 
                                   keypair_result.error_message());
             return keypair_result.error();
         }
         
         auto [public_key, secret_key] = keypair_result.value();
         
         // Sign Merkle root
         auto signature_result = dilithium->sign(merkle_root, secret_key);
         if (signature_result.is_err()) {
             SecureLogger::instance().error("Failed to sign batch attestation: " + 
                                   signature_result.error_message());
             return signature_result.error();
         }
         
         attestation.gateway_signature = signature_result.value();
         
         // Add metadata
         attestation.metadata["transaction_count"] = std::to_string(transactions.size());
         attestation.metadata["attestation_type"] = "batch";
         attestation.metadata["merkle_root"] = bytes_to_hex(merkle_root);
         attestation.metadata["timestamp"] = std::to_string(attestation.timestamp);
         
         // Add security metadata
         attestation.metadata["signature_algorithm"] = "dilithium3";
         attestation.metadata["hash_algorithm"] = "blake2b";
         attestation.metadata["merkle_algorithm"] = "blake2b";
         
         // Chain metadata
         if (same_chain) {
             attestation.metadata["chain_id"] = std::to_string(first_chain_id);
             attestation.metadata["multi_chain"] = "false";
         } else {
             attestation.metadata["multi_chain"] = "true";
             
             // Count transactions per chain
             std::unordered_map<uint32_t, size_t> chains_count;
             for (const auto& tx : transactions) {
                 chains_count[tx.chain_id]++;
             }
             
             // Add chain distribution to metadata
             std::string chains_info;
             for (const auto& [chain_id, count] : chains_count) {
                 if (!chains_info.empty()) {
                     chains_info += ",";
                 }
                 chains_info += std::to_string(chain_id) + ":" + std::to_string(count);
             }
             attestation.metadata["chains_distribution"] = chains_info;
         }
         
         SecureLogger::instance().info("Generated batch attestation: " + bytes_to_hex(attestation.id) + 
                              " with " + std::to_string(transactions.size()) + " transactions");
         return attestation;
         
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception generating batch attestation: " + std::string(e.what()));
         return ErrorCode::ATTESTATION_GENERATION_FAILED;
     }
 }
 
 Result<Attestation> AuditLayer::generate_epoch_attestation(const ByteVector& merkle_root,
                                                         const std::vector<ByteVector>& batch_ids) {
     try {
         // Create new attestation
         Attestation attestation;
         attestation.id = Attestation::generate_id();
         attestation.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch()
         ).count();
         attestation.type = Attestation::Type::EPOCH;
         
         // Add batch IDs to entity_ids
         attestation.entity_ids = batch_ids;
         
         // Set Merkle root
         attestation.merkle_root = merkle_root;
         
         // Sign with secure gateway key (get from Dilithium)
         auto dilithium = std::make_unique<DilithiumSignature>();
         dilithium->initialize();
         
         // Generate ephemeral keypair for this attestation
         auto keypair_result = dilithium->generate_keypair();
         if (keypair_result.is_err()) {
             SecureLogger::instance().error("Failed to generate keypair for epoch attestation: " + 
                                   keypair_result.error_message());
             return keypair_result.error();
         }
         
         auto [public_key, secret_key] = keypair_result.value();
         
         // Sign Merkle root
         auto signature_result = dilithium->sign(merkle_root, secret_key);
         if (signature_result.is_err()) {
             SecureLogger::instance().error("Failed to sign epoch attestation: " + 
                                   signature_result.error_message());
             return signature_result.error();
         }
         
         attestation.gateway_signature = signature_result.value();
         
         // Get transaction details from batch attestations
         std::unordered_map<uint32_t, size_t> chain_tx_counts;
         size_t total_tx_count = 0;
         
         for (const auto& batch_id : batch_ids) {
             // Load the batch attestation
             auto batch_result = attestation_store_->load_attestation(batch_id);
             if (batch_result.is_ok()) {
                 auto batch = batch_result.value();
                 
                 // Count transactions
                 auto tx_count_it = batch.metadata.find("transaction_count");
                 if (tx_count_it != batch.metadata.end()) {
                     size_t tx_count = std::stoi(tx_count_it->second);
                     total_tx_count += tx_count;
                     
                     // Count by chain if available
                     if (batch.chain_id.has_value()) {
                         chain_tx_counts[batch.chain_id.value()] += tx_count;
                     }
                 }
             }
         }
         
         // Add metadata
         attestation.metadata["batch_count"] = std::to_string(batch_ids.size());
         attestation.metadata["transaction_count"] = std::to_string(total_tx_count);
         attestation.metadata["attestation_type"] = "epoch";
         attestation.metadata["merkle_root"] = bytes_to_hex(merkle_root);
         attestation.metadata["timestamp"] = std::to_string(attestation.timestamp);
         attestation.metadata["epoch_id"] = bytes_to_hex(attestation.id);
         
         // Add security metadata
         attestation.metadata["signature_algorithm"] = "dilithium3";
         attestation.metadata["hash_algorithm"] = "blake2b";
         attestation.metadata["merkle_algorithm"] = "blake2b";
         
         // Add chain distribution to metadata
         if (!chain_tx_counts.empty()) {
             std::string chains_info;
             for (const auto& [chain_id, count] : chain_tx_counts) {
                 if (!chains_info.empty()) {
                     chains_info += ",";
                 }
                 chains_info += std::to_string(chain_id) + ":" + std::to_string(count);
             }
             attestation.metadata["chains_distribution"] = chains_info;
         }
         
         SecureLogger::instance().info("Generated epoch attestation: " + bytes_to_hex(attestation.id) + 
                              " with " + std::to_string(batch_ids.size()) + " batches and " + 
                              std::to_string(total_tx_count) + " transactions");
         return attestation;
         
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception generating epoch attestation: " + std::string(e.what()));
         return ErrorCode::ATTESTATION_GENERATION_FAILED;
     }
 }
 
 Result<ByteVector> AuditLayer::generate_proof(const Transaction& transaction) {
     try {
         // Get the attestation for this transaction
         auto attestations_result = attestation_store_->get_attestations_by_entity_id(transaction.id);
         if (attestations_result.is_err()) {
             SecureLogger::instance().error("Failed to get attestations for transaction: " + 
                                   attestations_result.error_message());
             return attestations_result.error();
         }
         
         auto attestations = attestations_result.value();
         
         // Find the transaction attestation
         Attestation tx_attestation;
         bool found = false;
         
         for (const auto& att : attestations) {
             if (att.type == Attestation::Type::TRANSACTION) {
                 tx_attestation = att;
                 found = true;
                 break;
             }
         }
         
         if (!found) {
             SecureLogger::instance().error("No transaction attestation found for transaction: " + 
                                   bytes_to_hex(transaction.id));
             return ErrorCode::NODE_NOT_FOUND;
         }
         
         // Find the batch attestation
         Attestation batch_attestation;
         bool batch_found = false;
         
         for (const auto& att : attestations) {
             if (att.type == Attestation::Type::BATCH) {
                 batch_attestation = att;
                 batch_found = true;
                 break;
             }
         }
         
         // Include Merkle proof if available
         ByteVector merkle_proof;
         if (transaction.merkle_proof.has_value()) {
             merkle_proof = transaction.merkle_proof.value();
         } else if (batch_found && batch_attestation.merkle_root.has_value()) {
             // Try to generate Merkle proof
             // Get all transactions in this batch
             std::vector<Transaction> batch_transactions;
             
             for (const auto& entity_id : batch_attestation.entity_ids) {
                 auto tx_result = transaction_store_->load_transaction(entity_id);
                 if (tx_result.is_ok()) {
                     batch_transactions.push_back(tx_result.value());
                 }
             }
             
             if (!batch_transactions.empty()) {
                 // Build Merkle tree
                 MerkleTree merkle_tree;
                 merkle_tree.build(batch_transactions);
                 
                 // Get proof
                 auto proof_result = merkle_tree.get_proof(transaction);
                 if (proof_result.is_ok()) {
                     merkle_proof = proof_result.value();
                     
                     // Update transaction with the proof
                     Transaction updated_tx = transaction;
                     updated_tx.merkle_proof = merkle_proof;
                     transaction_store_->update_transaction(updated_tx);
                 }
             }
         }
         
         // Create proof structure
         // Format: 
         // - Attestation ID [32 bytes]
         // - Gateway signature [variable]
         // - Merkle proof [variable, optional]
         // - FinalChain TX hash [variable, optional]
         
         ByteVector proof;
         
         // Add attestation ID
         proof.insert(proof.end(), tx_attestation.id.begin(), tx_attestation.id.end());
         
         // Add gateway signature
         uint16_t sig_size = static_cast<uint16_t>(tx_attestation.gateway_signature.size());
         proof.push_back((sig_size >> 8) & 0xFF);
         proof.push_back(sig_size & 0xFF);
         proof.insert(proof.end(), tx_attestation.gateway_signature.begin(), tx_attestation.gateway_signature.end());
         
         // Add Merkle proof if available
         if (!merkle_proof.empty()) {
             uint16_t proof_size = static_cast<uint16_t>(merkle_proof.size());
             proof.push_back((proof_size >> 8) & 0xFF);
             proof.push_back(proof_size & 0xFF);
             proof.insert(proof.end(), merkle_proof.begin(), merkle_proof.end());
         } else {
             // No Merkle proof
             proof.push_back(0);
             proof.push_back(0);
         }
         
         // Add FinalChain TX hash if available
         auto it = tx_attestation.metadata.find("finalchain_tx_hash");
         if (it != tx_attestation.metadata.end()) {
             ByteVector tx_hash = hex_to_bytes(it->second);
             uint16_t hash_size = static_cast<uint16_t>(tx_hash.size());
             proof.push_back((hash_size >> 8) & 0xFF);
             proof.push_back(hash_size & 0xFF);
             proof.insert(proof.end(), tx_hash.begin(), tx_hash.end());
         } else if (batch_found) {
             // Try to get FinalChain TX hash from batch attestation
             auto batch_it = batch_attestation.metadata.find("finalchain_tx_hash");
             if (batch_it != batch_attestation.metadata.end()) {
                 ByteVector tx_hash = hex_to_bytes(batch_it->second);
                 uint16_t hash_size = static_cast<uint16_t>(tx_hash.size());
                 proof.push_back((hash_size >> 8) & 0xFF);
                 proof.push_back(hash_size & 0xFF);
                 proof.insert(proof.end(), tx_hash.begin(), tx_hash.end());
             } else {
                 // No FinalChain TX hash
                 proof.push_back(0);
                 proof.push_back(0);
             }
         } else {
             // No FinalChain TX hash
             proof.push_back(0);
             proof.push_back(0);
         }
         
         // Add batch information if available
         if (batch_found) {
             proof.push_back(1); // Has batch info
             
             // Add batch ID
             proof.insert(proof.end(), batch_attestation.id.begin(), batch_attestation.id.end());
             
             // Add batch merkle root
             if (batch_attestation.merkle_root.has_value()) {
                 uint16_t root_size = static_cast<uint16_t>(batch_attestation.merkle_root.value().size());
                 proof.push_back((root_size >> 8) & 0xFF);
                 proof.push_back(root_size & 0xFF);
                 proof.insert(proof.end(), batch_attestation.merkle_root.value().begin(), 
                             batch_attestation.merkle_root.value().end());
             } else {
                 proof.push_back(0);
                 proof.push_back(0);
             }
         } else {
             proof.push_back(0); // No batch info
         }
         
         // Add timestamp for proof freshness
         uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch()
         ).count();
         
         for (int i = 7; i >= 0; i--) {
             proof.push_back((timestamp >> (i * 8)) & 0xFF);
         }
         
         SecureLogger::instance().info("Generated asset proof for transaction: " + 
                              bytes_to_hex(transaction.id));
         
         return proof;
         
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception in generate_proof: " + std::string(e.what()));
         return ErrorCode::ATTESTATION_GENERATION_FAILED;
     }
 }
 
 // Helper function to convert bytes to hex string
 std::string AuditLayer::bytes_to_hex(const ByteVector& bytes) {
     std::stringstream ss;
     ss << std::hex << std::setfill('0');
     
     for (const auto& byte : bytes) {
         ss << std::setw(2) << static_cast<int>(byte);
     }
     
     return ss.str();
 }
 
 // Helper function to convert hex string to bytes
 ByteVector AuditLayer::hex_to_bytes(const std::string& hex) {
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