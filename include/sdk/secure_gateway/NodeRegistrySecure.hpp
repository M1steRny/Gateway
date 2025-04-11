#pragma once

#include "FinalDefiSDK.hpp"
#include <memory>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <chrono>
#include <filesystem>
#include <fstream>

namespace finaldefi {
namespace secure_gateway {

using namespace finaldefi::sdk;

/**
 * @brief Secure node registry that persists data with double Kyber encapsulation
 */
class NodeRegistrySecure {
public:
    // Constructor
    NodeRegistrySecure(const std::string& persist_path = constants::REGISTRY_FILE_PATH);
    
    // Destructor
    ~NodeRegistrySecure();
    
    // Add or update a node
    Result<void> register_node(const NodeInfo& node);
    
    // Remove a node
    Result<void> unregister_node(const NodeId& id);
    
    // Get a node by ID
    Result<NodeInfo> get_node(const NodeId& id);
    
    // Update node heartbeat
    Result<void> update_heartbeat(const NodeId& id);
    
    // Update node load
    Result<void> update_load(const NodeId& id, double load_factor);
    
    // Get all nodes
    std::vector<NodeInfo> get_all_nodes();
    
    // Get active nodes
    std::vector<NodeInfo> get_active_nodes();
    
    // Get best nodes for processing
    std::vector<NodeInfo> get_best_nodes(size_t count);
    
    // Check if node exists
    bool node_exists(const NodeId& id);
    
    // Count active nodes
    size_t count_active_nodes();
    
    // Count total nodes
    size_t count_total_nodes();
    
    // Save registry to disk
    Result<void> save();
    
    // Load registry from disk
    Result<void> load();
    
private:
    // Generate encryption key for registry
    Result<ByteVector> generate_encryption_key();
    
    // Encrypt registry with double Kyber encapsulation
    Result<ByteVector> encrypt_registry(const ByteVector& data);
    
    // Decrypt registry with double Kyber decapsulation
    Result<ByteVector> decrypt_registry(const ByteVector& encrypted_data);
    
    // Clean up inactive nodes
    void cleanup_inactive_nodes();
    
    std::string persist_path_;
    std::vector<NodeInfo> nodes_;
    mutable std::shared_mutex mutex_;
    std::thread cleanup_thread_;
    std::atomic<bool> running_{true};
    
    // Cryptographic keys
    std::unique_ptr<KyberEncryption> kyber_;
    std::pair<ByteVector, ByteVector> registry_keypair_;
};

} // namespace secure_gateway
} // namespace finaldefi