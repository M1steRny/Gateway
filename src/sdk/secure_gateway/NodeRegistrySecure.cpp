#include "NodeRegistrySecure.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace finaldefi {
namespace secure_gateway {

NodeRegistrySecure::NodeRegistrySecure(const std::string& persist_path)
    : persist_path_(persist_path) {
    
    // Create directory for registry if it doesn't exist
    std::filesystem::path dir = std::filesystem::path(persist_path_).parent_path();
    if (!std::filesystem::exists(dir)) {
        std::filesystem::create_directories(dir);
    }
    
    // Initialize Kyber encryption
    kyber_ = std::make_unique<KyberEncryption>();
    auto init_result = kyber_->initialize();
    if (init_result.is_err()) {
        SecureLogger::instance().error("Failed to initialize Kyber: " + init_result.error_message());
        throw std::runtime_error("Failed to initialize Kyber for node registry");
    }
    
    // Generate or load encryption keys
    auto keypair_result = kyber_->generate_keypair();
    if (keypair_result.is_err()) {
        SecureLogger::instance().error("Failed to generate Kyber keypair: " + keypair_result.error_message());
        throw std::runtime_error("Failed to generate Kyber keypair for node registry");
    }
    
    registry_keypair_ = keypair_result.value();
    
    // Load registry
    auto load_result = load();
    if (load_result.is_err()) {
        SecureLogger::instance().warning("Failed to load node registry: " + load_result.error_message());
        SecureLogger::instance().info("Starting with empty node registry");
    }
    
    // Start cleanup thread
    cleanup_thread_ = std::thread([this] {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::minutes(5));
            
            if (!running_) break;
            
            cleanup_inactive_nodes();
        }
    });
}

NodeRegistrySecure::~NodeRegistrySecure() {
    running_ = false;
    
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
    
    save();
}

Result<void> NodeRegistrySecure::register_node(const NodeInfo& node) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    // Calculate expected fingerprint
    ByteVector expected_fingerprint = NodeInfo::calculate_fingerprint(node);
    
    // Verify fingerprint
    if (expected_fingerprint != node.fingerprint) {
        SecureLogger::instance().error("Node fingerprint validation failed during registration");
        return ErrorCode::VERIFICATION_FAILED;
    }
    
    // Check version compatibility (only allow exact match for now)
    if (node.version != "0.2.0") {
        SecureLogger::instance().error("Node version incompatible: " + node.version);
        return ErrorCode::NODE_INCOMPATIBLE_VERSION;
    }
    
    // Check if node already exists
    auto it = std::find_if(nodes_.begin(), nodes_.end(), [&node](const NodeInfo& n) {
        return std::equal(n.id.begin(), n.id.end(), node.id.begin());
    });
    
    if (it != nodes_.end()) {
        // Update existing node
        *it = node;
        SecureLogger::instance().debug("Updated node in registry: " + node.hostname + ":" + 
                                std::to_string(node.port));
    } else {
        // Add new node
        nodes_.push_back(node);
        SecureLogger::instance().info("Added new node to registry: " + node.hostname + ":" + 
                               std::to_string(node.port));
    }
    
    // Save registry to disk
    auto save_result = save();
    if (save_result.is_err()) {
        SecureLogger::instance().warning("Failed to save node registry: " + save_result.error_message());
        // Continue anyway, we'll try to save again later
    }
    
    return ErrorCode::SUCCESS;
}

Result<void> NodeRegistrySecure::unregister_node(const NodeId& id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = std::find_if(nodes_.begin(), nodes_.end(), [&id](const NodeInfo& node) {
        return std::equal(node.id.begin(), node.id.end(), id.begin());
    });
    
    if (it != nodes_.end()) {
        nodes_.erase(it);
        
        // Save registry to disk
        auto save_result = save();
        if (save_result.is_err()) {
            SecureLogger::instance().warning("Failed to save node registry after unregistration: " + 
                                     save_result.error_message());
            // Continue anyway
        }
        
        SecureLogger::instance().info("Removed node from registry");
        return ErrorCode::SUCCESS;
    }
    
    return ErrorCode::NODE_NOT_FOUND;
}

Result<NodeInfo> NodeRegistrySecure::get_node(const NodeId& id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    auto it = std::find_if(nodes_.begin(), nodes_.end(), [&id](const NodeInfo& node) {
        return std::equal(node.id.begin(), node.id.end(), id.begin());
    });
    
    if (it != nodes_.end()) {
        return *it;
    }
    
    return ErrorCode::NODE_NOT_FOUND;
}

Result<void> NodeRegistrySecure::update_heartbeat(const NodeId& id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = std::find_if(nodes_.begin(), nodes_.end(), [&id](const NodeInfo& node) {
        return std::equal(node.id.begin(), node.id.end(), id.begin());
    });
    
    if (it != nodes_.end()) {
        it->last_heartbeat = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        it->is_active = true;
        
        return ErrorCode::SUCCESS;
    }
    
    return ErrorCode::NODE_NOT_FOUND;
}

Result<void> NodeRegistrySecure::update_load(const NodeId& id, double load_factor) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = std::find_if(nodes_.begin(), nodes_.end(), [&id](const NodeInfo& node) {
        return std::equal(node.id.begin(), node.id.end(), id.begin());
    });
    
    if (it != nodes_.end()) {
        it->load_factor = load_factor;
        
        return ErrorCode::SUCCESS;
    }
    
    return ErrorCode::NODE_NOT_FOUND;
}

std::vector<NodeInfo> NodeRegistrySecure::get_all_nodes() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    return nodes_;
}

std::vector<NodeInfo> NodeRegistrySecure::get_active_nodes() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    std::vector<NodeInfo> active_nodes;
    std::copy_if(nodes_.begin(), nodes_.end(), std::back_inserter(active_nodes), 
                [](const NodeInfo& node) { return node.is_active; });
    
    return active_nodes;
}

std::vector<NodeInfo> NodeRegistrySecure::get_best_nodes(size_t count) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    // Filter active nodes
    std::vector<NodeInfo> active_nodes;
    std::copy_if(nodes_.begin(), nodes_.end(), std::back_inserter(active_nodes), 
                [](const NodeInfo& node) { return node.is_active; });
    
    if (active_nodes.empty()) {
        return {};
    }
    
    // Sort by load factor
    std::sort(active_nodes.begin(), active_nodes.end(), 
             [](const NodeInfo& a, const NodeInfo& b) {
                 return a.load_factor < b.load_factor;
             });
    
    // Return the requested number of nodes (or all if count > available)
    size_t result_count = std::min(count, active_nodes.size());
    return std::vector<NodeInfo>(active_nodes.begin(), active_nodes.begin() + result_count);
}

bool NodeRegistrySecure::node_exists(const NodeId& id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    return std::any_of(nodes_.begin(), nodes_.end(), [&id](const NodeInfo& node) {
        return std::equal(node.id.begin(), node.id.end(), id.begin());
    });
}

size_t NodeRegistrySecure::count_active_nodes() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    return std::count_if(nodes_.begin(), nodes_.end(), 
                       [](const NodeInfo& node) { return node.is_active; });
}

size_t NodeRegistrySecure::count_total_nodes() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    return nodes_.size();
}

Result<void> NodeRegistrySecure::save() {
    try {
        // Serialize nodes
        ByteVector registry_data;
        
        // Write node count (4 bytes)
        uint32_t node_count = static_cast<uint32_t>(nodes_.size());
        registry_data.push_back((node_count >> 24) & 0xFF);
        registry_data.push_back((node_count >> 16) & 0xFF);
        registry_data.push_back((node_count >> 8) & 0xFF);
        registry_data.push_back(node_count & 0xFF);
        
        for (const auto& node : nodes_) {
            // Serialize node
            ByteVector node_data = node.serialize();
            
            // Write node size (4 bytes)
            uint32_t node_size = static_cast<uint32_t>(node_data.size());
            registry_data.push_back((node_size >> 24) & 0xFF);
            registry_data.push_back((node_size >> 16) & 0xFF);
            registry_data.push_back((node_size >> 8) & 0xFF);
            registry_data.push_back(node_size & 0xFF);
            
            // Write node data
            registry_data.insert(registry_data.end(), node_data.begin(), node_data.end());
        }
        
        // Encrypt the registry with double Kyber encapsulation
        auto encrypt_result = encrypt_registry(registry_data);
        if (encrypt_result.is_err()) {
            SecureLogger::instance().error("Failed to encrypt node registry: " + 
                                   encrypt_result.error_message());
            return encrypt_result.error();
        }
        
        auto encrypted_data = encrypt_result.value();
        
        // Write to file
        std::ofstream file(persist_path_, std::ios::binary);
        if (!file) {
            SecureLogger::instance().error("Failed to open node registry file for writing");
            return ErrorCode::FILE_IO_ERROR;
        }
        
        file.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
        file.close();
        
        SecureLogger::instance().debug("Saved " + std::to_string(nodes_.size()) + " nodes to registry");
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during registry saving: " + std::string(e.what()));
        return ErrorCode::FILE_IO_ERROR;
    }
}

Result<void> NodeRegistrySecure::load() {
    try {
        if (!std::filesystem::exists(persist_path_)) {
            SecureLogger::instance().info("Node registry file not found, starting with empty registry");
            return ErrorCode::FILE_IO_ERROR;
        }
        
        // Read encrypted file
        std::ifstream file(persist_path_, std::ios::binary | std::ios::ate);
        if (!file) {
            SecureLogger::instance().error("Failed to open node registry file for reading");
            return ErrorCode::FILE_IO_ERROR;
        }
        
        // Get file size
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        // Read encrypted data
        ByteVector encrypted_data(size);
        if (!file.read(reinterpret_cast<char*>(encrypted_data.data()), size)) {
            SecureLogger::instance().error("Failed to read node registry file");
            return ErrorCode::FILE_IO_ERROR;
        }
        
        file.close();
        
        // Decrypt the registry with double Kyber decapsulation
        auto decrypt_result = decrypt_registry(encrypted_data);
        if (decrypt_result.is_err()) {
            SecureLogger::instance().error("Failed to decrypt node registry: " + 
                                   decrypt_result.error_message());
            return decrypt_result.error();
        }
        
        auto registry_data = decrypt_result.value();
        
        // Deserialize nodes
        nodes_.clear();
        
        // Read node count (first 4 bytes)
        if (registry_data.size() < 4) {
            SecureLogger::instance().error("Invalid registry data format");
            return ErrorCode::INVALID_PARAMETER;
        }
        
        uint32_t node_count = (registry_data[0] << 24) | (registry_data[1] << 16) |
                             (registry_data[2] << 8) | registry_data[3];
        size_t pos = 4;
        
        for (uint32_t i = 0; i < node_count; i++) {
            // Read node size
            if (pos + 4 > registry_data.size()) {
                SecureLogger::instance().error("Invalid registry data format");
                return ErrorCode::INVALID_PARAMETER;
            }
            
            uint32_t node_size = (registry_data[pos] << 24) | (registry_data[pos + 1] << 16) |
                                (registry_data[pos + 2] << 8) | registry_data[pos + 3];
            pos += 4;
            
            if (pos + node_size > registry_data.size()) {
                SecureLogger::instance().error("Invalid registry data format");
                return ErrorCode::INVALID_PARAMETER;
            }
            
            // Extract node data
            ByteVector node_data(registry_data.begin() + pos, registry_data.begin() + pos + node_size);
            pos += node_size;
            
            // Deserialize node
            auto node_result = NodeInfo::deserialize(node_data);
            if (node_result.is_ok()) {
                nodes_.push_back(node_result.value());
            } else {
                SecureLogger::instance().error("Failed to deserialize node: " + 
                                       node_result.error_message());
            }
        }
        
        SecureLogger::instance().info("Loaded " + std::to_string(nodes_.size()) + " nodes from registry");
        return ErrorCode::SUCCESS;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during registry loading: " + std::string(e.what()));
        return ErrorCode::FILE_IO_ERROR;
    }
}

Result<ByteVector> NodeRegistrySecure::generate_encryption_key() {
    // Use a derived key from the node fingerprint key
    ByteVector encryption_key(crypto_kdf_KEYBYTES);
    
    // Derive key using the fingerprint key
    crypto_kdf_keygen(encryption_key.data());
    
    return encryption_key;
}

Result<ByteVector> NodeRegistrySecure::encrypt_registry(const ByteVector& data) {
    try {
        // Double encapsulate with Kyber1024
        auto encaps_result = kyber_->double_encapsulate(registry_keypair_.first);
        if (encaps_result.is_err()) {
            return encaps_result.error();
        }
        
        auto [ciphertexts, shared_secret] = encaps_result.value();
        auto [ct1, ct2] = ciphertexts;
        
        // Encrypt the data with the shared secret
        auto encrypt_result = kyber_->encrypt_data(data, shared_secret);
        if (encrypt_result.is_err()) {
            return encrypt_result.error();
        }
        
        ByteVector encrypted_data = encrypt_result.value();
        
        // Combine ciphertexts and encrypted data
        ByteVector result;
        
        // Add ciphertext 1 size
        uint32_t ct1_size = static_cast<uint32_t>(ct1.size());
        result.push_back((ct1_size >> 24) & 0xFF);
        result.push_back((ct1_size >> 16) & 0xFF);
        result.push_back((ct1_size >> 8) & 0xFF);
        result.push_back(ct1_size & 0xFF);
        
        // Add ciphertext 1
        result.insert(result.end(), ct1.begin(), ct1.end());
        
        // Add ciphertext 2 size
        uint32_t ct2_size = static_cast<uint32_t>(ct2.size());
        result.push_back((ct2_size >> 24) & 0xFF);
        result.push_back((ct2_size >> 16) & 0xFF);
        result.push_back((ct2_size >> 8) & 0xFF);
        result.push_back(ct2_size & 0xFF);
        
        // Add ciphertext 2
        result.insert(result.end(), ct2.begin(), ct2.end());
        
        // Add encrypted data size
        uint32_t data_size = static_cast<uint32_t>(encrypted_data.size());
        result.push_back((data_size >> 24) & 0xFF);
        result.push_back((data_size >> 16) & 0xFF);
        result.push_back((data_size >> 8) & 0xFF);
        result.push_back(data_size & 0xFF);
        
        // Add encrypted data
        result.insert(result.end(), encrypted_data.begin(), encrypted_data.end());
        
        return result;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during registry encryption: " + std::string(e.what()));
        return ErrorCode::ENCRYPTION_FAILED;
    }
}

Result<ByteVector> NodeRegistrySecure::decrypt_registry(const ByteVector& encrypted_data) {
    try {
        // Parse the encrypted data
        if (encrypted_data.size() < 4) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        // Extract ciphertext 1 size
        uint32_t ct1_size = (encrypted_data[0] << 24) | (encrypted_data[1] << 16) |
                           (encrypted_data[2] << 8) | encrypted_data[3];
        size_t pos = 4;
        
        if (pos + ct1_size > encrypted_data.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        // Extract ciphertext 1
        ByteVector ct1(encrypted_data.begin() + pos, encrypted_data.begin() + pos + ct1_size);
        pos += ct1_size;
        
        // Extract ciphertext 2 size
        if (pos + 4 > encrypted_data.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        uint32_t ct2_size = (encrypted_data[pos] << 24) | (encrypted_data[pos + 1] << 16) |
                           (encrypted_data[pos + 2] << 8) | encrypted_data[pos + 3];
        pos += 4;
        
        if (pos + ct2_size > encrypted_data.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        // Extract ciphertext 2
        ByteVector ct2(encrypted_data.begin() + pos, encrypted_data.begin() + pos + ct2_size);
        pos += ct2_size;
        
        // Extract encrypted data size
        if (pos + 4 > encrypted_data.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        uint32_t data_size = (encrypted_data[pos] << 24) | (encrypted_data[pos + 1] << 16) |
                            (encrypted_data[pos + 2] << 8) | encrypted_data[pos + 3];
        pos += 4;
        
        if (pos + data_size > encrypted_data.size()) {
            return ErrorCode::INVALID_PARAMETER;
        }
        
        // Extract encrypted data
        ByteVector encrypted_registry_data(encrypted_data.begin() + pos, encrypted_data.begin() + pos + data_size);
        
        // Double decapsulate with Kyber1024
        auto decaps_result = kyber_->double_decapsulate(ct1, ct2, registry_keypair_.second);
        if (decaps_result.is_err()) {
            return decaps_result.error();
        }
        
        auto shared_secret = decaps_result.value();
        
        // Decrypt the data with the shared secret
        auto decrypt_result = kyber_->decrypt_data(encrypted_registry_data, shared_secret);
        if (decrypt_result.is_err()) {
            return decrypt_result.error();
        }
        
        return decrypt_result;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during registry decryption: " + std::string(e.what()));
        return ErrorCode::DECRYPTION_FAILED;
    }
}

void NodeRegistrySecure::cleanup_inactive_nodes() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    uint64_t current_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    // Mark nodes as inactive if they haven't sent a heartbeat in 5 minutes
    size_t marked_inactive = 0;
    for (auto& node : nodes_) {
        if (node.is_active && (current_time - node.last_heartbeat) > 300) {
            node.is_active = false;
            marked_inactive++;
        }
    }
    
    // Remove nodes that have been inactive for over 24 hours
    size_t before_size = nodes_.size();
    nodes_.erase(
        std::remove_if(nodes_.begin(), nodes_.end(), [current_time](const NodeInfo& node) {
            return !node.is_active && (current_time - node.last_heartbeat) > 86400;
        }),
        nodes_.end()
    );
    
    size_t removed = before_size - nodes_.size();
    
    if (marked_inactive > 0 || removed > 0) {
        SecureLogger::instance().info("Node cleanup: marked " + std::to_string(marked_inactive) + 
                               " as inactive, removed " + std::to_string(removed) + " nodes");
        
        // Save registry if changes were made
        save();
    }
}

} // namespace secure_gateway
} // namespace finaldefi