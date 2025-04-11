#pragma once

#include "types.hpp"
#include "constants.hpp"
#include <filesystem>
#include <string>
#include <vector>
#include <unordered_map>

namespace finaldefi {
namespace sdk {

/**
 * @brief Transaction model for the Secure Gateway
 */
struct Transaction {
    // Transaction ID
    ByteVector id;
    
    // Chain ID
    uint32_t chain_id;
    
    // Timestamp
    uint64_t timestamp;
    
    // Sender information
    ByteVector sender_address;
    ByteVector sender_public_key;
    
    // Transaction data
    ByteVector data;
    
    // Gateway signature
    ByteVector gateway_signature;
    
    // Original user signature
    ByteVector user_signature;
    
    // Status
    enum class Status {
        PENDING,
        PROCESSING,
        COMPLETED,
        FAILED
    };
    Status status;
    
    // Light agent ID that processed the transaction
    std::optional<NodeId> processor_id;
    
    // Response data (if any)
    std::optional<ByteVector> response;
    
    // Merkle proof (if included in a batch)
    std::optional<ByteVector> merkle_proof;
    
    // FinalChain transaction hash (if submitted)
    std::optional<ByteVector> finalchain_tx_hash;
    
    // Meta data for the transaction
    std::unordered_map<std::string, std::string> metadata;
    
    // Serialize to binary
    ByteVector serialize() const;
    
    // Deserialize from binary
    static Result<Transaction> deserialize(const ByteVector& data);
    
    // Generate transaction ID
    static ByteVector generate_id();
    
    // Calculate transaction hash for verification
    ByteVector calculate_hash() const;
};

/**
 * @brief Transaction store for persisting and retrieving transactions
 */
class TransactionStore {
public:
    // Constructor
    TransactionStore(const std::string& store_path = constants::TRANSACTION_STORE_PATH);
    
    // Store a transaction
    Result<void> store_transaction(const Transaction& tx);
    
    // Load a transaction
    Result<Transaction> load_transaction(const ByteVector& tx_id);
    
    // Update a transaction
    Result<void> update_transaction(const Transaction& tx);
    
    // Delete a transaction
    Result<void> delete_transaction(const ByteVector& tx_id);
    
    // Get all transactions
    Result<std::vector<Transaction>> get_all_transactions();
    
    // Get transactions by status
    Result<std::vector<Transaction>> get_transactions_by_status(Transaction::Status status);
    
private:
    // Helper to convert bytes to hex string
    static std::string bytes_to_hex(const ByteVector& bytes);
    
    // Helper to convert hex string to bytes
    static ByteVector hex_to_bytes(const std::string& hex);
    
    std::string store_path_;
};

} // namespace sdk
} // namespace finaldefi