#pragma once

#include "FinalDefiSDK.hpp"
#include <boost/asio.hpp>
#include <memory>
#include <thread>
#include <vector>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <condition_variable>

namespace finaldefi {
namespace secure_gateway {

namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

/**
 * @brief Node manager server to handle node registration and communication
 */
class NodeManager {
public:
    // Constructor
    NodeManager(uint16_t port);
    
    // Destructor
    ~NodeManager();
    
    // Start the node manager
    void start();
    
    // Stop the node manager
    void stop();
    
    // Get a list of active nodes
    std::vector<NodeInfo> get_active_nodes();
    
    // Get a list of all nodes
    std::vector<NodeInfo> get_all_nodes();
    
    // Get a node by ID
    Result<NodeInfo> get_node(const NodeId& id);
    
    // Remove a node by ID
    Result<void> remove_node(const NodeId& id);
    
private:
    // Listener for incoming connections
    class Listener : public std::enable_shared_from_this<Listener> {
    public:
        Listener(net::io_context& ioc, tcp::endpoint endpoint, NodeManager& manager);
        
        // Start accepting connections
        void start();
        
    private:
        // Accept a new connection
        void do_accept();
        
        // Handle a new accepted connection
        void on_accept(boost::system::error_code ec, tcp::socket socket);
        
        net::io_context& ioc_;
        tcp::acceptor acceptor_;
        NodeManager& manager_;
    };
    
    // Session for handling node connections
    class Session : public std::enable_shared_from_this<Session> {
    public:
        Session(tcp::socket&& socket, NodeManager& manager);
        
        // Start the session
        void start();
        
    private:
        // Read a request
        void do_read();
        
        // Process the request
        void process_request();
        
        // Send a response
        void do_write();
        
        // Handle different request types
        void handle_node_registration();
        void handle_heartbeat();
        void handle_registry_sync();
        
        tcp::socket socket_;
        NodeManager& manager_;
        ByteVector buffer_;
        ByteVector response_;
    };
    
    uint16_t port_;
    std::shared_ptr<NodeRegistry> node_registry_;
    std::unique_ptr<net::io_context> ioc_;
    std::vector<std::thread> threads_;
    std::shared_ptr<Listener> listener_;
    std::atomic<bool> running_{false};
    
    // Periodic cleanup thread
    std::thread cleanup_thread_;
    void cleanup_inactive_nodes();
};

} // namespace secure_gateway
} // namespace finaldefi