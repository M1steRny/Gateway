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
 * @brief Attestation model for publishing to FinalChain
 */
struct Attestation {
    // Attestation ID
    ByteVector id;
    
    // Timestamp
    uint64_t timestamp;
    
    // Attestation type
    enum class Type {
        TRANSACTION,
        BATCH,
        EPOCH,
        NODE_REGISTRATION,
        KEY_ROTATION,
        CUSTOM
    };
    Type type;
    
    // Related entity IDs (transactions, batches, etc.)
    std::vector<ByteVector> entity_ids;
    
    // Merkle root (for batches and epochs)
    std::optional<ByteVector> merkle_root;
    
    // Gateway signature
    ByteVector gateway_signature;
    
    // Quorum signatures (threshold signatures)
    std::vector<std::pair<NodeId, ByteVector>> quorum_signatures;
    
    // Chain ID (for transactions)
    std::optional<uint32_t> chain_id;
    
    // Meta data
    std::unordered_map<std::string, std::string> metadata;
    
    // Serialize to binary
    ByteVector serialize() const;
    
    // Deserialize from binary
    static Result<Attestation> deserialize(const ByteVector& data);
    
    // Generate attestation ID
    static ByteVector generate_id();
    
    // Calculate attestation hash for verification
    ByteVector calculate_hash() const;
};

/**
 * @brief Attestation store for persisting and retrieving attestations
 */
class AttestationStore {
public:
    // Constructor
    AttestationStore(const std::string& store_path = constants::ATTESTATION_STORE_PATH);
    
    // Store an attestation
    Result<void> store_attestation(const Attestation& attestation);
    
    // Load an attestation
    Result<Attestation> load_attestation(const ByteVector& attestation_id);
    
    // Update an attestation
    Result<void> update_attestation(const Attestation& attestation);
    
    // Delete an attestation
    Result<void> delete_attestation(const ByteVector& attestation_id);
    
    // Get all attestations
    Result<std::vector<Attestation>> get_all_attestations();
    
    // Get attestations by type
    Result<std::vector<Attestation>> get_attestations_by_type(Attestation::Type type);
    
    // Get attestations containing a specific entity ID
    Result<std::vector<Attestation>> get_attestations_by_entity_id(const ByteVector& entity_id);
    
private:
    // Helper to convert bytes to hex string
    static std::string bytes_to_hex(const ByteVector& bytes);
    
    // Helper to convert hex string to bytes
    static ByteVector hex_to_bytes(const std::string& hex);
    
    std::string store_path_;
};

} // namespace sdk
} // namespace finaldefi