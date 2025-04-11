#pragma once

#include "types.hpp"
#include "constants.hpp"
#include <memory>
#include <vector>

namespace finaldefi {
namespace sdk {

/**
 * @brief Merkle tree implementation for transaction batching
 */
class MerkleTree {
public:
    // Merkle tree node
    struct Node {
        ByteVector hash;
        std::shared_ptr<Node> left;
        std::shared_ptr<Node> right;
        
        Node(const ByteVector& h) : hash(h), left(nullptr), right(nullptr) {}
        Node(const ByteVector& h, std::shared_ptr<Node> l, std::shared_ptr<Node> r) 
            : hash(h), left(l), right(r) {}
        
        bool is_leaf() const {
            return !left && !right;
        }
    };
    
    MerkleTree() = default;
    
    // Build a Merkle tree from a list of transactions
    void build(const std::vector<Transaction>& transactions);
    
    // Build a tree from generic hashes
    void build(const std::vector<ByteVector>& hashes);
    
    // Get the Merkle root hash
    ByteVector get_root_hash() const;
    
    // Get the Merkle proof for a transaction
    Result<ByteVector> get_proof(const Transaction& tx) const;
    
    // Get the Merkle proof for a hash
    Result<ByteVector> get_proof(const ByteVector& hash) const;
    
    // Verify a Merkle proof
    static Result<bool> verify_proof(const ByteVector& proof, const ByteVector& root_hash);
    
private:
    // Build a subtree from a list of nodes
    std::shared_ptr<Node> build_tree(const std::vector<std::shared_ptr<Node>>& nodes);
    
    // Get the nodes needed for a Merkle proof
    void get_proof_nodes(size_t leaf_index, std::vector<std::pair<bool, ByteVector>>& proof_nodes) const;
    
    std::vector<std::shared_ptr<Node>> leaves_;
    std::shared_ptr<Node> root_;
};

} // namespace sdk
} // namespace finaldefi