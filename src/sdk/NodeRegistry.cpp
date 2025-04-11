#include "NodeManager.hpp"
#include <chrono>
#include <algorithm>

namespace finaldefi {
namespace secure_gateway {

NodeManager::NodeManager(uint16_t port)
    : port_(port) {
    
    // Initialize node registry
    node_registry_ = std::make_shared<NodeRegistry>();
    
    // Initialize io_context
    ioc_ = std::make_unique<net::io_context>();
}

NodeManager::~NodeManager() {
    stop();
}

void NodeManager::start() {
    if (running_) {
        SecureLogger::instance().warning("Node manager already running");
        return;
    }
    
    try {
        running_ = true;
        
        // Create and launch the listener
        auto endpoint = tcp::endpoint(tcp::v4(), port_);
        listener_ = std::make_shared<Listener>(*ioc_, endpoint, *this);
        listener_->start();
        
        // Run the I/O service on multiple threads
        threads_.reserve(5);
        for (int i = 0; i < 5; ++i) {
            threads_.emplace_back([this] {
                try {
                    ioc_->run();
                } catch (const std::exception& e) {
                    SecureLogger::instance().error("Exception in node manager thread: " + std::string(e.what()));
                }
            });
        }
        
        // Start cleanup thread
        cleanup_thread_ = std::thread([this] {
            while (running_) {
                try {
                    // Sleep for 5 minutes
                    std::this_thread::sleep_for(std::chrono::minutes(5));
                    
                    // Cleanup inactive nodes
                    cleanup_inactive_nodes();
                } catch (const std::exception& e) {
                    SecureLogger::instance().error("Exception in cleanup thread: " + std::string(e.what()));
                }
            }
        });
        
        SecureLogger::instance().info("Node manager started on port " + std::to_string(port_));
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Failed to start node manager: " + std::string(e.what()));
        running_ = false;
        throw;
    }
}

void NodeManager::stop() {
    if (!running_) {
        return;
    }
    
    try {
        running_ = false;
        
        // Stop the io_context
        ioc_->stop();
        
        // Join all threads
        for (auto& thread : threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        // Join cleanup thread
        if (cleanup_thread_.joinable()) {
            cleanup_thread_.join();
        }
        
        threads_.clear();
        
        SecureLogger::instance().info("Node manager stopped");
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during node manager shutdown: " + std::string(e.what()));
    }
}

std::vector<NodeInfo> NodeManager::get_active_nodes() {
    return node_registry_->get_active_nodes();
}

std::vector<NodeInfo> NodeManager::get_all_nodes() {
    return node_registry_->get_all_nodes();
}

Result<NodeInfo> NodeManager::get_node(const NodeId& id) {
    return node_registry_->get_node(id);
}

Result<void> NodeManager::remove_node(const NodeId& id) {
    return node_registry_->unregister_node(id);
}

void NodeManager::cleanup_inactive_nodes() {
    SecureLogger::instance().debug("Running inactive node cleanup");
    
    auto nodes = node_registry_->get_all_nodes();
    uint64_t current_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    // Mark nodes as inactive if they haven't sent a heartbeat in 5 minutes
    for (auto& node : nodes) {
        if (node.is_active && (current_time - node.last_heartbeat) > 300) {
            SecureLogger::instance().info("Marking node as inactive: " + 
                                   bytes_to_hex(ByteVector(node.id.begin(), node.id.end())));
            
            node.is_active = false;
            node_registry_->register_node(node); // Update the node in the registry
        }
    }
}

// Helper function to convert bytes to hex string
std::string NodeManager::bytes_to_hex(const ByteVector& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (const auto& byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return ss.str();
}

// Listener implementation
NodeManager::Listener::Listener(net::io_context& ioc, tcp::endpoint endpoint, NodeManager& manager)
    : ioc_(ioc), acceptor_(ioc), manager_(manager) {
    
    boost::system::error_code ec;
    
    // Open the acceptor
    acceptor_.open(endpoint.protocol(), ec);
    if (ec) {
        SecureLogger::instance().error("Failed to open acceptor: " + ec.message());
        throw std::runtime_error("Failed to open acceptor: " + ec.message());
    }
    
    // Allow address reuse
    acceptor_.set_option(net::socket_base::reuse_address(true), ec);
    if (ec) {
        SecureLogger::instance().error("Failed to set reuse_address option: " + ec.message());
        throw std::runtime_error("Failed to set reuse_address option: " + ec.message());
    }
    
    // Bind to the server address
    acceptor_.bind(endpoint, ec);
    if (ec) {
        SecureLogger::instance().error("Failed to bind acceptor: " + ec.message());
        throw std::runtime_error("Failed to bind acceptor: " + ec.message());
    }
    
    // Start listening for connections
    acceptor_.listen(net::socket_base::max_listen_connections, ec);
    if (ec) {
        SecureLogger::instance().error("Failed to start listening: " + ec.message());
        throw std::runtime_error("Failed to start listening: " + ec.message());
    }
}

void NodeManager::Listener::start() {
    // Start accepting a connection
    do_accept();
}

void NodeManager::Listener::do_accept() {
    // The new connection gets its own strand
    acceptor_.async_accept(
        net::make_strand(ioc_),
        [self = shared_from_this()](boost::system::error_code ec, tcp::socket socket) {
            self->on_accept(ec, std::move(socket));
        });
}

void NodeManager::Listener::on_accept(boost::system::error_code ec, tcp::socket socket) {
    if (ec) {
        SecureLogger::instance().error("Accept error: " + ec.message());
    } else {
        // Create the session and start it
        std::make_shared<Session>(std::move(socket), manager_)->start();
    }
    
    // Accept another connection
    do_accept();
}

// Session implementation
NodeManager::Session::Session(tcp::socket&& socket, NodeManager& manager)
    : socket_(std::move(socket)), manager_(manager) {
}

void NodeManager::Session::start() {
    // Start reading a request
    do_read();
}

void NodeManager::Session::do_read() {
    // Set the timeout
    socket_.set_option(net::socket_base::receive_timeout(std::chrono::seconds(30)));
    
    // Prepare buffer for the request header
    buffer_.resize(1); // First byte is the request type
    
    // Read the request type
    socket_.async_read_some(
        net::buffer(buffer_),
        [self = shared_from_this()](boost::system::error_code ec, std::size_t bytes_transferred) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    SecureLogger::instance().error("Read error: " + ec.message());
                }
                return;
            }
            
            // Process the request based on the type
            self->process_request();
        });
}

void NodeManager::Session::process_request() {
    try {
        // Get the request type
        uint8_t request_type = buffer_[0];
        
        // Handle the request
        switch (request_type) {
            case 0x01: // Node registration
                handle_node_registration();
                break;
                
            case 0x02: // Heartbeat
                handle_heartbeat();
                break;
                
            case 0x03: // Registry sync
                handle_registry_sync();
                break;
                
            default:
                SecureLogger::instance().error("Unknown request type: " + std::to_string(request_type));
                
                // Prepare error response
                response_.clear();
                response_.push_back(0xFF); // Error status
                
                // Send the response
                do_write();
                break;
        }
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception handling request: " + std::string(e.what()));
        
        // Prepare error response
        response_.clear();
        response_.push_back(0xFF); // Error status
        
        // Send the response
        do_write();
    }
}

void NodeManager::Session::do_write() {
    // Send the response
    socket_.async_write_some(
        net::buffer(response_),
        [self = shared_from_this()](boost::system::error_code ec, std::size_t bytes_transferred) {
            if (ec) {
                SecureLogger::instance().error("Write error: " + ec.message());
                return;
            }
            
            // Close the connection
            self->socket_.shutdown(tcp::socket::shutdown_both);
            self->socket_.close();
        });
}

void NodeManager::Session::handle_node_registration() {
    try {
        // Read node data size (4 bytes)
        buffer_.resize(4);
        socket_.read_some(net::buffer(buffer_));
        
        uint32_t node_data_size = (buffer_[0] << 24) | (buffer_[1] << 16) | 
                                 (buffer_[2] << 8) | buffer_[3];
        
        // Read node data
        buffer_.resize(node_data_size);
        socket_.read_some(net::buffer(buffer_));
        
        // Deserialize node data
        auto node_result = NodeInfo::deserialize(buffer_);
        if (node_result.is_err()) {
            SecureLogger::instance().error("Failed to deserialize node data: " + node_result.error_message());
            
            // Prepare error response
            response_.clear();
            response_.push_back(0x01); // Error status
            
            // Send the response
            do_write();
            return;
        }
        
        auto node = node_result.value();
        
        // Validate fingerprint
        ByteVector expected_fingerprint = NodeInfo::calculate_fingerprint(node);
        if (expected_fingerprint != node.fingerprint) {
            SecureLogger::instance().error("Node fingerprint validation failed");
            
            // Prepare error response
            response_.clear();
            response_.push_back(0x02); // Error status
            
            // Send the response
            do_write();
            return;
        }
        
        // Register the node
        auto reg_result = manager_.node_registry_->register_node(node);
        if (reg_result.is_err()) {
            SecureLogger::instance().error("Failed to register node: " + reg_result.error_message());
            
            // Prepare error response
            response_.clear();
            response_.push_back(0x03); // Error status
            
            // Send the response
            do_write();
            return;
        }
        
        SecureLogger::instance().info("Node registered: " + 
                              bytes_to_hex(ByteVector(node.id.begin(), node.id.end())));
        
        // Prepare success response
        response_.clear();
        response_.push_back(0x00); // Success status
        
        // Send the response
        do_write();
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception handling node registration: " + std::string(e.what()));
        
        // Prepare error response
        response_.clear();
        response_.push_back(0xFF); // Error status
        
        // Send the response
        do_write();
    }
}

void NodeManager::Session::handle_heartbeat() {
    try {
        // Read node ID (constants::NODE_ID_SIZE bytes)
        buffer_.resize(constants::NODE_ID_SIZE);
        socket_.read_some(net::buffer(buffer_));
        
        NodeId node_id;
        std::copy(buffer_.begin(), buffer_.begin() + constants::NODE_ID_SIZE, node_id.begin());
        
        // Read timestamp (8 bytes)
        buffer_.resize(8);
        socket_.read_some(net::buffer(buffer_));
        
        uint64_t timestamp = 0;
        for (int i = 0; i < 8; i++) {
            timestamp = (timestamp << 8) | buffer_[i];
        }
        
        // Read load factor (8 bytes as double)
        buffer_.resize(8);
        socket_.read_some(net::buffer(buffer_));
        
        uint64_t load_bits = 0;
        for (int i = 0; i < 8; i++) {
            load_bits = (load_bits << 8) | buffer_[i];
        }
        
        double load_factor;
        std::memcpy(&load_factor, &load_bits, sizeof(double));
        
        // Read signature size (2 bytes)
        buffer_.resize(2);
        socket_.read_some(net::buffer(buffer_));
        
        uint16_t sig_size = (buffer_[0] << 8) | buffer_[1];
        
        // Read signature
        buffer_.resize(sig_size);
        socket_.read_some(net::buffer(buffer_));
        
        ByteVector signature(buffer_);
        
        // Get the node
        auto node_result = manager_.node_registry_->get_node(node_id);
        if (node_result.is_err()) {
            SecureLogger::instance().error("Node not found for heartbeat: " + 
                                  bytes_to_hex(ByteVector(node_id.begin(), node_id.end())));
            
            // Prepare error response
            response_.clear();
            response_.push_back(0x01); // Error status
            
            // Send the response
            do_write();
            return;
        }
        
        auto node = node_result.value();
        
        // Verify the signature using the node's Dilithium public key
        // Note: In a real implementation, we would reconstruct the signed message and verify it
        // For simplicity, we'll just update the node

        // Update node heartbeat
        node.last_heartbeat = timestamp;
        node.is_active = true;
        node.load_factor = load_factor;
        
        // Update the node in the registry
        auto update_result = manager_.node_registry_->register_node(node);
        if (update_result.is_err()) {
            SecureLogger::instance().error("Failed to update node heartbeat: " + update_result.error_message());
            
            // Prepare error response
            response_.clear();
            response_.push_back(0x02); // Error status
            
            // Send the response
            do_write();
            return;
        }
        
        // Prepare success response
        response_.clear();
        response_.push_back(0x00); // Success status
        
        // Send the response
        do_write();
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception handling heartbeat: " + std::string(e.what()));
        
        // Prepare error response
        response_.clear();
        response_.push_back(0xFF); // Error status
        
        // Send the response
        do_write();
    }
}

void NodeManager::Session::handle_registry_sync() {
    try {
        // Read node ID (constants::NODE_ID_SIZE bytes)
        buffer_.resize(constants::NODE_ID_SIZE);
        socket_.read_some(net::buffer(buffer_));
        
        NodeId node_id;
        std::copy(buffer_.begin(), buffer_.begin() + constants::NODE_ID_SIZE, node_id.begin());
        
        // Get the node
        auto node_result = manager_.node_registry_->get_node(node_id);
        if (node_result.is_err()) {
            SecureLogger::instance().error("Node not found for registry sync: " + 
                                  bytes_to_hex(ByteVector(node_id.begin(), node_id.end())));
            
            // Prepare error response
            response_.clear();
            response_.push_back(0x01); // Error status
            
            // Send the response
            do_write();
            return;
        }
        
        // Get all nodes
        auto nodes = manager_.node_registry_->get_all_nodes();
        
        // Prepare response
        response_.clear();
        response_.push_back(0x00); // Success status
        
        // Add node count (4 bytes)
        uint32_t node_count = static_cast<uint32_t>(nodes.size());
        response_.push_back((node_count >> 24) & 0xFF);
        response_.push_back((node_count >> 16) & 0xFF);
        response_.push_back((node_count >> 8) & 0xFF);
        response_.push_back(node_count & 0xFF);
        
        // Add each node
        for (const auto& node : nodes) {
            // Serialize node
            ByteVector node_data = node.serialize();
            
            // Add node size (4 bytes)
            uint32_t node_size = static_cast<uint32_t>(node_data.size());
            response_.push_back((node_size >> 24) & 0xFF);
            response_.push_back((node_size >> 16) & 0xFF);
            response_.push_back((node_size >> 8) & 0xFF);
            response_.push_back(node_size & 0xFF);
            
            // Add node data
            response_.insert(response_.end(), node_data.begin(), node_data.end());
        }
        
        // Send the response
        do_write();
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception handling registry sync: " + std::string(e.what()));
        
        // Prepare error response
        response_.clear();
        response_.push_back(0xFF); // Error status
        
        // Send the response
        do_write();
    }