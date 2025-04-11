#pragma once

#include "SecureGateway.hpp"
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/websocket.hpp>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <atomic>
#include <unordered_map>
#include <functional>

namespace finaldefi {
namespace secure_gateway {

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace websocket = beast::websocket;
using tcp = boost::asio::ip::tcp;

/**
 * @brief HTTP server for the Secure Gateway API
 */
class HTTPServer {
public:
    // Constructor
    HTTPServer(const std::string& address, uint16_t port, std::shared_ptr<SecureGateway> gateway);
    
    // Destructor
    ~HTTPServer();
    
    // Start the server
    void start();
    
    // Stop the server
    void stop();
    
private:
    // Listener for incoming connections
    class Listener : public std::enable_shared_from_this<Listener> {
    public:
        Listener(net::io_context& ioc, tcp::endpoint endpoint, std::shared_ptr<SecureGateway> gateway);
        
        // Start accepting connections
        void start();
        
    private:
        // Accept a new connection
        void do_accept();
        
        // Handle a new accepted connection
        void on_accept(beast::error_code ec, tcp::socket socket);
        
        net::io_context& ioc_;
        tcp::acceptor acceptor_;
        std::shared_ptr<SecureGateway> gateway_;
    };
    
    // Session for handling HTTP requests
    class HTTPSession : public std::enable_shared_from_this<HTTPSession> {
    public:
        HTTPSession(tcp::socket&& socket, std::shared_ptr<SecureGateway> gateway);
        
        // Start the session
        void start();
        
    private:
        // Read a request
        void do_read();
        
        // Process the request
        void process_request();
        
        // Send a response
        void do_write();
        
        // Handle different API endpoints
        void handle_transaction_submit(http::request<http::string_body>& req, http::response<http::string_body>& res);
        void handle_transaction_status(http::request<http::string_body>& req, http::response<http::string_body>& res);
        void handle_transaction_list(http::request<http::string_body>& req, http::response<http::string_body>& res);
        void handle_attestation_get(http::request<http::string_body>& req, http::response<http::string_body>& res);
        void handle_attestation_list(http::request<http::string_body>& req, http::response<http::string_body>& res);
        void handle_keypair_generate(http::request<http::string_body>& req, http::response<http::string_body>& res);
        void handle_verify_intent(http::request<http::string_body>& req, http::response<http::string_body>& res);
        void handle_metrics(http::request<http::string_body>& req, http::response<http::string_body>& res);
        
        // Helper functions
        std::string bytes_to_hex(const ByteVector& bytes);
        ByteVector hex_to_bytes(const std::string& hex);
        
        tcp::socket socket_;
        beast::flat_buffer buffer_;
        http::request<http::string_body> req_;
        http::response<http::string_body> res_;
        std::shared_ptr<SecureGateway> gateway_;
    };
    
    // WebSocket session for real-time updates
    class WebSocketSession : public std::enable_shared_from_this<WebSocketSession> {
    public:
        WebSocketSession(tcp::socket&& socket, std::shared_ptr<SecureGateway> gateway);
        
        // Start the session
        void start();
        
    private:
        // Accept the WebSocket upgrade
        void do_accept();
        
        // Read a message
        void do_read();
        
        // Process the message
        void process_message(const std::string& message);
        
        // Send a message
        void do_write(const std::string& message);
        
        websocket::stream<tcp::socket> ws_;
        beast::flat_buffer buffer_;
        std::string message_;
        std::shared_ptr<SecureGateway> gateway_;
    };
    
    std::string address_;
    uint16_t port_;
    std::shared_ptr<SecureGateway> gateway_;
    std::unique_ptr<net::io_context> ioc_;
    std::vector<std::thread> threads_;
    std::shared_ptr<Listener> listener_;
    std::atomic<bool> running_{false};
};

} // namespace secure_gateway
} // namespace finaldefi