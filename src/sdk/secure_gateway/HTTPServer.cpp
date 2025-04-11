#include "HTTPServer.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>

namespace finaldefi {
namespace secure_gateway {

namespace pt = boost::property_tree;

HTTPServer::HTTPServer(const std::string& address, uint16_t port, std::shared_ptr<SecureGateway> gateway)
    : address_(address), port_(port), gateway_(gateway) {
    
    // Initialize io_context
    ioc_ = std::make_unique<net::io_context>();
}

HTTPServer::~HTTPServer() {
    stop();
}

void HTTPServer::start() {
    if (running_) {
        SecureLogger::instance().warning("HTTP server already running");
        return;
    }
    
    try {
        running_ = true;
        
        // Create and launch the listener
        auto endpoint = tcp::endpoint(net::ip::make_address(address_), port_);
        listener_ = std::make_shared<Listener>(*ioc_, endpoint, gateway_);
        listener_->start();
        
        // Run the I/O service on multiple threads
        threads_.reserve(5);
        for (int i = 0; i < 5; ++i) {
            threads_.emplace_back([this] {
                try {
                    ioc_->run();
                } catch (const std::exception& e) {
                    SecureLogger::instance().error("Exception in HTTP server thread: " + std::string(e.what()));
                }
            });
        }
        
        SecureLogger::instance().info("HTTP server started on " + address_ + ":" + std::to_string(port_));
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Failed to start HTTP server: " + std::string(e.what()));
        running_ = false;
        throw;
    }
}

void HTTPServer::stop() {
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
        
        threads_.clear();
        
        SecureLogger::instance().info("HTTP server stopped");
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during HTTP server shutdown: " + std::string(e.what()));
    }
}

// Listener implementation
HTTPServer::Listener::Listener(net::io_context& ioc, tcp::endpoint endpoint, std::shared_ptr<SecureGateway> gateway)
    : ioc_(ioc), acceptor_(ioc), gateway_(gateway) {
    
    beast::error_code ec;
    
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

void HTTPServer::Listener::start() {
    // Start accepting a connection
    do_accept();
}

void HTTPServer::Listener::do_accept() {
    // The new connection gets its own strand
    acceptor_.async_accept(
        net::make_strand(ioc_),
        beast::bind_front_handler(
            &Listener::on_accept,
            shared_from_this()));
}

void HTTPServer::Listener::on_accept(beast::error_code ec, tcp::socket socket) {
    if (ec) {
        SecureLogger::instance().error("Accept error: " + ec.message());
    } else {
        // Create the session and start it
        if (socket.remote_endpoint().port() % 2 == 0) {
            // Even port numbers for HTTP
            std::make_shared<HTTPSession>(std::move(socket), gateway_)->start();
        } else {
            // Odd port numbers for WebSocket
            std::make_shared<WebSocketSession>(std::move(socket), gateway_)->start();
        }
    }
    
    // Accept another connection
    do_accept();
}

// HTTPSession implementation
HTTPServer::HTTPSession::HTTPSession(tcp::socket&& socket, std::shared_ptr<SecureGateway> gateway)
    : socket_(std::move(socket)), gateway_(gateway) {
}

void HTTPServer::HTTPSession::start() {
    // Start reading a request
    do_read();
}

void HTTPServer::HTTPSession::do_read() {
    // Make the request empty before reading
    req_ = {};
    
    // Set the timeout
    beast::get_lowest_layer(socket_).expires_after(std::chrono::seconds(30));
    
    // Read a request
    http::async_read(socket_, buffer_, req_,
        beast::bind_front_handler(
            [self = shared_from_this()](beast::error_code ec, std::size_t) {
                if (ec) {
                    if (ec != beast::error::timeout) {
                        SecureLogger::instance().error("HTTP read error: " + ec.message());
                    }
                    return;
                }
                
                // Process the request
                self->process_request();
            }));
}

void HTTPServer::HTTPSession::process_request() {
    // Set up the response
    res_.version(req_.version());
    res_.keep_alive(req_.keep_alive());
    
    // Add common headers
    res_.set(http::field::server, "FinalDeFi-SecureGateway/0.2.0");
    res_.set(http::field::content_type, "application/json");
    res_.set(http::field::access_control_allow_origin, "*");
    res_.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
    res_.set(http::field::access_control_allow_headers, "Content-Type");
    
    // Handle OPTIONS request (CORS preflight)
    if (req_.method() == http::verb::options) {
        res_.result(http::status::ok);
        res_.body() = "";
        return do_write();
    }
    
    // Route the request to the appropriate handler
    try {
        std::string path = req_.target().to_string();
        
        if (path == "/api/v1/transaction/submit" && req_.method() == http::verb::post) {
            handle_transaction_submit(req_, res_);
        } else if (path.find("/api/v1/transaction/status/") == 0 && req_.method() == http::verb::get) {
            handle_transaction_status(req_, res_);
        } else if (path == "/api/v1/transaction/list" && req_.method() == http::verb::get) {
            handle_transaction_list(req_, res_);
        } else if (path.find("/api/v1/attestation/") == 0 && req_.method() == http::verb::get) {
            handle_attestation_get(req_, res_);
        } else if (path == "/api/v1/attestation/list" && req_.method() == http::verb::get) {
            handle_attestation_list(req_, res_);
        } else if (path == "/api/v1/keypair/generate" && req_.method() == http::verb::post) {
            handle_keypair_generate(req_, res_);
        } else if (path == "/api/v1/verify/intent" && req_.method() == http::verb::post) {
            handle_verify_intent(req_, res_);
        } else if (path == "/api/v1/metrics" && req_.method() == http::verb::get) {
            handle_metrics(req_, res_);
        } else {
            // 404 Not Found
            res_.result(http::status::not_found);
            pt::ptree response;
            response.put("error", "Not found");
            
            std::ostringstream oss;
            pt::write_json(oss, response);
            res_.body() = oss.str();
        }
    } catch (const std::exception& e) {
        // 500 Internal Server Error
        SecureLogger::instance().error("Exception handling request: " + std::string(e.what()));
        
        res_.result(http::status::internal_server_error);
        pt::ptree response;
        response.put("error", "Internal server error");
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res_.body() = oss.str();
    }
    
    do_write();
}

void HTTPServer::HTTPSession::do_write() {
    // Set Content-Length
    res_.content_length(res_.body().size());
    
    // Write the response
    http::async_write(socket_, res_,
        beast::bind_front_handler(
            [self = shared_from_this()](beast::error_code ec, std::size_t) {
                if (ec) {
                    SecureLogger::instance().error("HTTP write error: " + ec.message());
                    return;
                }
                
                // If we aren't keeping the connection alive, close it
                if (!self->res_.keep_alive()) {
                    self->socket_.shutdown(tcp::socket::shutdown_send);
                    return;
                }
                
                // Read another request
                self->do_read();
            }));
}

void HTTPServer::HTTPSession::handle_transaction_submit(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    try {
        // Parse request JSON
        std::istringstream iss(req.body());
        pt::ptree request;
        pt::read_json(iss, request);
        
        // Extract transaction details
        Transaction tx;
        
        // Transaction ID (generate new if not provided)
        if (request.count("id") > 0) {
            std::string id_hex = request.get<std::string>("id");
            tx.id = hex_to_bytes(id_hex);
        } else {
            tx.id = Transaction::generate_id();
        }
        
        // Chain ID
        tx.chain_id = request.get<uint32_t>("chain_id");
        
        // Timestamp (use current time if not provided)
        if (request.count("timestamp") > 0) {
            tx.timestamp = request.get<uint64_t>("timestamp");
        } else {
            tx.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
        }
        
        // Sender information
        tx.sender_address = hex_to_bytes(request.get<std::string>("sender_address"));
        tx.sender_public_key = hex_to_bytes(request.get<std::string>("sender_public_key"));
        
        // Transaction data
        tx.data = hex_to_bytes(request.get<std::string>("data"));
        
        // User signature
        tx.user_signature = hex_to_bytes(request.get<std::string>("signature"));
        
        // Set status to pending
        tx.status = Transaction::Status::PENDING;
        
        // Metadata (optional)
        if (request.count("metadata") > 0) {
            for (const auto& item : request.get_child("metadata")) {
                tx.metadata[item.first] = item.second.data();
            }
        }
        
        // Submit the transaction
        auto result = gateway_->submit_transaction(tx);
        if (result.is_err()) {
            // Handle error
            res.result(http::status::internal_server_error);
            
            pt::ptree response;
            response.put("success", false);
            response.put("error", "Failed to submit transaction: " + result.error_message());
            response.put("id", bytes_to_hex(tx.id));
            
            std::ostringstream oss;
            pt::write_json(oss, response);
            res.body() = oss.str();
            return;
        }
        
        auto submission_result = result.value();
        
        // Create response JSON
        pt::ptree response;
        response.put("success", submission_result.success);
        response.put("message", submission_result.message);
        response.put("transaction_id", bytes_to_hex(submission_result.transaction_id));
        
        if (submission_result.attestation_id.has_value()) {
            response.put("attestation_id", bytes_to_hex(submission_result.attestation_id.value()));
        }
        
        if (submission_result.finalchain_tx_hash.has_value()) {
            response.put("finalchain_tx_hash", bytes_to_hex(submission_result.finalchain_tx_hash.value()));
        }
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
        res.result(http::status::ok);
        
    } catch (const pt::ptree_error& e) {
        // Invalid JSON or missing required field
        res.result(http::status::bad_request);
        
        pt::ptree response;
        response.put("success", false);
        response.put("error", "Invalid request format: " + std::string(e.what()));
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
    }
}

void HTTPServer::HTTPSession::handle_transaction_status(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    try {
        // Extract transaction ID from URL
        std::string path = req.target().to_string();
        std::string id_hex = path.substr(std::string("/api/v1/transaction/status/").length());
        
        // Convert to bytes
        ByteVector tx_id = hex_to_bytes(id_hex);
        
        // Get transaction status
        auto result = gateway_->get_transaction_status(tx_id);
        if (result.is_err()) {
            // Transaction not found or other error
            res.result(http::status::not_found);
            
            pt::ptree response;
            response.put("success", false);
            response.put("error", "Transaction not found: " + result.error_message());
            response.put("id", id_hex);
            
            std::ostringstream oss;
            pt::write_json(oss, response);
            res.body() = oss.str();
            return;
        }
        
        auto transaction = result.value();
        
        // Create response JSON
        pt::ptree response;
        response.put("success", true);
        response.put("transaction_id", bytes_to_hex(transaction.id));
        response.put("chain_id", transaction.chain_id);
        response.put("timestamp", transaction.timestamp);
        response.put("sender_address", bytes_to_hex(transaction.sender_address));
        
        // Status
        std::string status_str;
        switch (transaction.status) {
            case Transaction::Status::PENDING:
                status_str = "pending";
                break;
            case Transaction::Status::PROCESSING:
                status_str = "processing";
                break;
            case Transaction::Status::COMPLETED:
                status_str = "completed";
                break;
            case Transaction::Status::FAILED:
                status_str = "failed";
                break;
            default:
                status_str = "unknown";
        }
        response.put("status", status_str);
        
        // Optional fields
        if (transaction.processor_id.has_value()) {
            response.put("processor_id", bytes_to_hex(transaction.processor_id.value()));
        }
        
        if (transaction.response.has_value()) {
            response.put("response", bytes_to_hex(transaction.response.value()));
        }
        
        if (transaction.merkle_proof.has_value()) {
            response.put("merkle_proof", bytes_to_hex(transaction.merkle_proof.value()));
        }
        
        if (transaction.finalchain_tx_hash.has_value()) {
            response.put("finalchain_tx_hash", bytes_to_hex(transaction.finalchain_tx_hash.value()));
        }
        
        // Metadata
        if (!transaction.metadata.empty()) {
            pt::ptree metadata_node;
            for (const auto& [key, value] : transaction.metadata) {
                metadata_node.put(key, value);
            }
            response.add_child("metadata", metadata_node);
        }
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
        res.result(http::status::ok);
        
    } catch (const std::exception& e) {
        // Bad request
        res.result(http::status::bad_request);
        
        pt::ptree response;
        response.put("success", false);
        response.put("error", "Invalid request: " + std::string(e.what()));
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
    }
}

void HTTPServer::HTTPSession::handle_transaction_list(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    try {
        // Parse query parameters
        std::string query = req.target().to_string();
        std::string::size_type pos = query.find('?');
        
        std::string status_filter;
        if (pos != std::string::npos) {
            std::string params = query.substr(pos + 1);
            std::vector<std::string> pairs;
            
            // Split by &
            size_t start = 0, end = 0;
            while ((end = params.find('&', start)) != std::string::npos) {
                pairs.push_back(params.substr(start, end - start));
                start = end + 1;
            }
            pairs.push_back(params.substr(start));
            
            // Parse each parameter
            for (const auto& pair : pairs) {
                size_t eq_pos = pair.find('=');
                if (eq_pos != std::string::npos) {
                    std::string key = pair.substr(0, eq_pos);
                    std::string value = pair.substr(eq_pos + 1);
                    
                    if (key == "status") {
                        status_filter = value;
                    }
                }
            }
        }
        
        // Get transactions
        std::vector<Transaction> transactions;
        if (!status_filter.empty()) {
            Transaction::Status status;
            if (status_filter == "pending") {
                status = Transaction::Status::PENDING;
            } else if (status_filter == "processing") {
                status = Transaction::Status::PROCESSING;
            } else if (status_filter == "completed") {
                status = Transaction::Status::COMPLETED;
            } else if (status_filter == "failed") {
                status = Transaction::Status::FAILED;
            } else {
                // Invalid status
                res.result(http::status::bad_request);
                
                pt::ptree response;
                response.put("success", false);
                response.put("error", "Invalid status filter: " + status_filter);
                
                std::ostringstream oss;
                pt::write_json(oss, response);
                res.body() = oss.str();
                return;
            }
            
            auto result = gateway_->get_transactions_by_status(status);
            if (result.is_ok()) {
                transactions = result.value();
            } else {
                // Error retrieving transactions
                res.result(http::status::internal_server_error);
                
                pt::ptree response;
                response.put("success", false);
                response.put("error", "Failed to retrieve transactions: " + result.error_message());
                
                std::ostringstream oss;
                pt::write_json(oss, response);
                res.body() = oss.str();
                return;
            }
        } else {
            // Get all transactions
            auto result = gateway_->get_all_transactions();
            if (result.is_ok()) {
                transactions = result.value();
            } else {
                // Error retrieving transactions
                res.result(http::status::internal_server_error);
                
                pt::ptree response;
                response.put("success", false);
                response.put("error", "Failed to retrieve transactions: " + result.error_message());
                
                std::ostringstream oss;
                pt::write_json(oss, response);
                res.body() = oss.str();
                return;
            }
        }
        
        // Create response JSON
        pt::ptree response;
        response.put("success", true);
        response.put("count", transactions.size());
        
        pt::ptree tx_array;
        for (const auto& tx : transactions) {
            pt::ptree tx_node;
            
            tx_node.put("id", bytes_to_hex(tx.id));
            tx_node.put("chain_id", tx.chain_id);
            tx_node.put("timestamp", tx.timestamp);
            tx_node.put("sender_address", bytes_to_hex(tx.sender_address));
            
            // Status
            std::string status_str;
            switch (tx.status) {
                case Transaction::Status::PENDING:
                    status_str = "pending";
                    break;
                case Transaction::Status::PROCESSING:
                    status_str = "processing";
                    break;
                case Transaction::Status::COMPLETED:
                    status_str = "completed";
                    break;
                case Transaction::Status::FAILED:
                    status_str = "failed";
                    break;
                default:
                    status_str = "unknown";
            }
            tx_node.put("status", status_str);
            
            tx_array.push_back(std::make_pair("", tx_node));
        }
        
        response.add_child("transactions", tx_array);
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
        res.result(http::status::ok);
        
    } catch (const std::exception& e) {
        // Bad request
        res.result(http::status::bad_request);
        
        pt::ptree response;
        response.put("success", false);
        response.put("error", "Invalid request: " + std::string(e.what()));
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
    }
}

void HTTPServer::HTTPSession::handle_attestation_get(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    try {
        // Extract attestation ID from URL
        std::string path = req.target().to_string();
        std::string id_hex = path.substr(std::string("/api/v1/attestation/").length());
        
        // Convert to bytes
        ByteVector attestation_id = hex_to_bytes(id_hex);
        
        // Get attestation
        auto result = gateway_->get_attestation(attestation_id);
        if (result.is_err()) {
            // Attestation not found or other error
            res.result(http::status::not_found);
            
            pt::ptree response;
            response.put("success", false);
            response.put("error", "Attestation not found: " + result.error_message());
            response.put("id", id_hex);
            
            std::ostringstream oss;
            pt::write_json(oss, response);
            res.body() = oss.str();
            return;
        }
        
        auto attestation = result.value();
        
        // Create response JSON
        pt::ptree response;
        response.put("success", true);
        response.put("attestation_id", bytes_to_hex(attestation.id));
        response.put("timestamp", attestation.timestamp);
        
        // Type
        std::string type_str;
        switch (attestation.type) {
            case Attestation::Type::TRANSACTION:
                type_str = "transaction";
                break;
            case Attestation::Type::BATCH:
                type_str = "batch";
                break;
            case Attestation::Type::EPOCH:
                type_str = "epoch";
                break;
            case Attestation::Type::NODE_REGISTRATION:
                type_str = "node_registration";
                break;
            case Attestation::Type::KEY_ROTATION:
                type_str = "key_rotation";
                break;
            case Attestation::Type::CUSTOM:
                type_str = "custom";
                break;
            default:
                type_str = "unknown";
        }
        response.put("type", type_str);
        
        // Entity IDs
        pt::ptree entity_ids_array;
        for (const auto& entity_id : attestation.entity_ids) {
            pt::ptree id_node;
            id_node.put("", bytes_to_hex(entity_id));
            entity_ids_array.push_back(std::make_pair("", id_node));
        }
        response.add_child("entity_ids", entity_ids_array);
        
        // Merkle root (if present)
        if (attestation.merkle_root.has_value()) {
            response.put("merkle_root", bytes_to_hex(attestation.merkle_root.value()));
        }
        
        // Gateway signature
        response.put("gateway_signature", bytes_to_hex(attestation.gateway_signature));
        
        // Quorum signatures
        pt::ptree quorum_sigs_array;
        for (const auto& [node_id, signature] : attestation.quorum_signatures) {
            pt::ptree sig_node;
            sig_node.put("node_id", bytes_to_hex(ByteVector(node_id.begin(), node_id.end())));
            sig_node.put("signature", bytes_to_hex(signature));
            quorum_sigs_array.push_back(std::make_pair("", sig_node));
        }
        response.add_child("quorum_signatures", quorum_sigs_array);
        
        // Chain ID (if present)
        if (attestation.chain_id.has_value()) {
            response.put("chain_id", attestation.chain_id.value());
        }
        
        // Metadata
        if (!attestation.metadata.empty()) {
            pt::ptree metadata_node;
            for (const auto& [key, value] : attestation.metadata) {
                metadata_node.put(key, value);
            }
            response.add_child("metadata", metadata_node);
        }
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
        res.result(http::status::ok);
        
    } catch (const std::exception& e) {
        // Bad request
        res.result(http::status::bad_request);
        
        pt::ptree response;
        response.put("success", false);
        response.put("error", "Invalid request: " + std::string(e.what()));
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
    }
}

void HTTPServer::HTTPSession::handle_attestation_list(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    try {
        // Parse query parameters
        std::string query = req.target().to_string();
        std::string::size_type pos = query.find('?');
        
        std::string type_filter;
        std::string entity_id_filter;
        if (pos != std::string::npos) {
            std::string params = query.substr(pos + 1);
            std::vector<std::string> pairs;
            
            // Split by &
            size_t start = 0, end = 0;
            while ((end = params.find('&', start)) != std::string::npos) {
                pairs.push_back(params.substr(start, end - start));
                start = end + 1;
            }
            pairs.push_back(params.substr(start));
            
            // Parse each parameter
            for (const auto& pair : pairs) {
                size_t eq_pos = pair.find('=');
                if (eq_pos != std::string::npos) {
                    std::string key = pair.substr(0, eq_pos);
                    std::string value = pair.substr(eq_pos + 1);
                    
                    if (key == "type") {
                        type_filter = value;
                    } else if (key == "entity_id") {
                        entity_id_filter = value;
                    }
                }
            }
        }
        
        // Get attestations
        std::vector<Attestation> attestations;
        
        if (!type_filter.empty()) {
            Attestation::Type type;
            if (type_filter == "transaction") {
                type = Attestation::Type::TRANSACTION;
            } else if (type_filter == "batch") {
                type = Attestation::Type::BATCH;
            } else if (type_filter == "epoch") {
                type = Attestation::Type::EPOCH;
            } else if (type_filter == "node_registration") {
                type = Attestation::Type::NODE_REGISTRATION;
            } else if (type_filter == "key_rotation") {
                type = Attestation::Type::KEY_ROTATION;
            } else if (type_filter == "custom") {
                type = Attestation::Type::CUSTOM;
            } else {
                // Invalid type
                res.result(http::status::bad_request);
                
                pt::ptree response;
                response.put("success", false);
                response.put("error", "Invalid type filter: " + type_filter);
                
                std::ostringstream oss;
                pt::write_json(oss, response);
                res.body() = oss.str();
                return;
            }
            
            // Implement attestation filtering by type
            auto result = gateway_->get_all_attestations();
            if (result.is_ok()) {
                auto all_attestations = result.value();
                
                // Filter by type
                std::copy_if(all_attestations.begin(), all_attestations.end(), 
                            std::back_inserter(attestations), 
                            [type](const Attestation& att) { return att.type == type; });
            } else {
                // Error retrieving attestations
                res.result(http::status::internal_server_error);
                
                pt::ptree response;
                response.put("success", false);
                response.put("error", "Failed to retrieve attestations: " + result.error_message());
                
                std::ostringstream oss;
                pt::write_json(oss, response);
                res.body() = oss.str();
                return;
            }
        } else if (!entity_id_filter.empty()) {
            // Filter by entity ID
            ByteVector entity_id = hex_to_bytes(entity_id_filter);
            
            // Implement attestation filtering by entity ID
            auto result = gateway_->get_all_attestations();
            if (result.is_ok()) {
                auto all_attestations = result.value();
                
                // Filter by entity ID
                std::copy_if(all_attestations.begin(), all_attestations.end(), 
                            std::back_inserter(attestations), 
                            [&entity_id](const Attestation& att) {
                                return std::find(att.entity_ids.begin(), att.entity_ids.end(), entity_id) != att.entity_ids.end();
                            });
            } else {
                // Error retrieving attestations
                res.result(http::status::internal_server_error);
                
                pt::ptree response;
                response.put("success", false);
                response.put("error", "Failed to retrieve attestations: " + result.error_message());
                
                std::ostringstream oss;
                pt::write_json(oss, response);
                res.body() = oss.str();
                return;
            }
        } else {
            // Get all attestations
            auto result = gateway_->get_all_attestations();
            if (result.is_ok()) {
                attestations = result.value();
            } else {
                // Error retrieving attestations
                res.result(http::status::internal_server_error);
                
                pt::ptree response;
                response.put("success", false);
                response.put("error", "Failed to retrieve attestations: " + result.error_message());
                
                std::ostringstream oss;
                pt::write_json(oss, response);
                res.body() = oss.str();
                return;
            }
        }
        
        // Create response JSON
        pt::ptree response;
        response.put("success", true);
        response.put("count", attestations.size());
        
        pt::ptree att_array;
        for (const auto& att : attestations) {
            pt::ptree att_node;
            
            att_node.put("id", bytes_to_hex(att.id));
            att_node.put("timestamp", att.timestamp);
            
            // Type
            std::string type_str;
            switch (att.type) {
                case Attestation::Type::TRANSACTION:
                    type_str = "transaction";
                    break;
                case Attestation::Type::BATCH:
                    type_str = "batch";
                    break;
                case Attestation::Type::EPOCH:
                    type_str = "epoch";
                    break;
                case Attestation::Type::NODE_REGISTRATION:
                    type_str = "node_registration";
                    break;
                case Attestation::Type::KEY_ROTATION:
                    type_str = "key_rotation";
                    break;
                case Attestation::Type::CUSTOM:
                    type_str = "custom";
                    break;
                default:
                    type_str = "unknown";
            }
            att_node.put("type", type_str);
            
            // Entity count
            att_node.put("entity_count", att.entity_ids.size());
            
            // Has Merkle root
            att_node.put("has_merkle_root", att.merkle_root.has_value());
            
            // Quorum signatures count
            att_node.put("quorum_signatures", att.quorum_signatures.size());
            
            att_array.push_back(std::make_pair("", att_node));
        }
        
        response.add_child("attestations", att_array);
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
        res.result(http::status::ok);
        
    } catch (const std::exception& e) {
        // Bad request
        res.result(http::status::bad_request);
        
        pt::ptree response;
        response.put("success", false);
        response.put("error", "Invalid request: " + std::string(e.what()));
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
    }
}

void HTTPServer::HTTPSession::handle_keypair_generate(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    try {
        // Generate a new Dilithium keypair for UI use
        auto result = gateway_->generate_ui_keypair();
        if (result.is_err()) {
            // Error generating keypair
            res.result(http::status::internal_server_error);
            
            pt::ptree response;
            response.put("success", false);
            response.put("error", "Failed to generate keypair: " + result.error_message());
            
            std::ostringstream oss;
            pt::write_json(oss, response);
            res.body() = oss.str();
            return;
        }
        
        auto [public_key, secret_key] = result.value();
        
        // Create response JSON
        pt::ptree response;
        response.put("success", true);
        response.put("public_key", bytes_to_hex(public_key));
        response.put("secret_key", bytes_to_hex(secret_key));
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
        res.result(http::status::ok);
        
    } catch (const std::exception& e) {
        // Bad request
        res.result(http::status::internal_server_error);
        
        pt::ptree response;
        response.put("success", false);
        response.put("error", "Failed to generate keypair: " + std::string(e.what()));
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
    }
}

void HTTPServer::HTTPSession::handle_verify_intent(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    try {
        // Parse request JSON
        std::istringstream iss(req.body());
        pt::ptree request;
        pt::read_json(iss, request);
        
        // Extract transaction details
        Transaction tx;
        
        // Transaction ID (generate new if not provided)
        if (request.count("id") > 0) {
            std::string id_hex = request.get<std::string>("id");
            tx.id = hex_to_bytes(id_hex);
        } else {
            tx.id = Transaction::generate_id();
        }
        
        // Chain ID
        tx.chain_id = request.get<uint32_t>("chain_id");
        
        // Timestamp (use current time if not provided)
        if (request.count("timestamp") > 0) {
            tx.timestamp = request.get<uint64_t>("timestamp");
        } else {
            tx.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
        }
        
        // Sender information
        tx.sender_address = hex_to_bytes(request.get<std::string>("sender_address"));
        tx.sender_public_key = hex_to_bytes(request.get<std::string>("sender_public_key"));
        
        // Transaction data
        tx.data = hex_to_bytes(request.get<std::string>("data"));
        
        // User signature
        ByteVector user_signature = hex_to_bytes(request.get<std::string>("signature"));
        
        // Verify intent
        auto result = gateway_->verify_transaction_intent(tx, user_signature);
        if (result.is_err()) {
            // Error verifying intent
            res.result(http::status::internal_server_error);
            
            pt::ptree response;
            response.put("success", false);
            response.put("error", "Failed to verify intent: " + result.error_message());
            response.put("id", bytes_to_hex(tx.id));
            
            std::ostringstream oss;
            pt::write_json(oss, response);
            res.body() = oss.str();
            return;
        }
        
        auto validation_info = result.value();
        
        // Create response JSON
        pt::ptree response;
        response.put("success", validation_info.result == SecureGateway::ValidationResult::VALID);
        response.put("message", validation_info.message);
        response.put("transaction_id", bytes_to_hex(validation_info.transaction_id));
        
        // Add validation result
        std::string result_str;
        switch (validation_info.result) {
            case SecureGateway::ValidationResult::VALID:
                result_str = "valid";
                break;
            case SecureGateway::ValidationResult::INVALID_SIGNATURE:
                result_str = "invalid_signature";
                break;
            case SecureGateway::ValidationResult::INVALID_FORMAT:
                result_str = "invalid_format";
                break;
            case SecureGateway::ValidationResult::INVALID_CHAIN:
                result_str = "invalid_chain";
                break;
            case SecureGateway::ValidationResult::INVALID_SENDER:
                result_str = "invalid_sender";
                break;
            case SecureGateway::ValidationResult::REJECTED_BY_QUORUM:
                result_str = "rejected_by_quorum";
                break;
            case SecureGateway::ValidationResult::INTERNAL_ERROR:
                result_str = "internal_error";
                break;
            default:
                result_str = "unknown";
        }
        response.put("result", result_str);
        
        if (validation_info.attestation_id.has_value()) {
            response.put("attestation_id", bytes_to_hex(validation_info.attestation_id.value()));
        }
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
        res.result(http::status::ok);
        
    } catch (const pt::ptree_error& e) {
        // Invalid JSON or missing required field
        res.result(http::status::bad_request);
        
        pt::ptree response;
        response.put("success", false);
        response.put("error", "Invalid request format: " + std::string(e.what()));
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
    }
}

void HTTPServer::HTTPSession::handle_metrics(http::request<http::string_body>& req, http::response<http::string_body>& res) {
    try {
        // Get metrics
        auto metrics = gateway_->get_metrics();
        
        // Create response JSON
        pt::ptree response;
        response.put("success", true);
        
        // Transaction metrics
        response.put("pending_transactions", metrics.pending_transactions);
        response.put("processing_transactions", metrics.processing_transactions);
        response.put("completed_transactions", metrics.completed_transactions);
        response.put("failed_transactions", metrics.failed_transactions);
        response.put("total_attestations", metrics.total_attestations);
        
        // Node metrics
        response.put("active_nodes", metrics.active_nodes);
        response.put("total_nodes", metrics.total_nodes);
        
        // Performance metrics
        response.put("average_processing_time_ms", metrics.average_processing_time_ms);
        
        // Epoch info
        auto epoch_time_t = std::chrono::system_clock::to_time_t(metrics.last_epoch_time);
        std::stringstream epoch_time_ss;
        epoch_time_ss << std::put_time(std::gmtime(&epoch_time_t), "%Y-%m-%dT%H:%M:%SZ");
        response.put("last_epoch_time", epoch_time_ss.str());
        
        if (!metrics.last_batch_root.empty()) {
            response.put("last_batch_root", bytes_to_hex(metrics.last_batch_root));
        }
        
        // System uptime
        auto now = std::chrono::steady_clock::now();
        static auto start_time = now;
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        response.put("uptime_seconds", uptime);
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
        res.result(http::status::ok);
        
    } catch (const std::exception& e) {
        // Internal server error
        res.result(http::status::internal_server_error);
        
        pt::ptree response;
        response.put("success", false);
        response.put("error", "Failed to get metrics: " + std::string(e.what()));
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        res.body() = oss.str();
    }
}

std::string HTTPServer::HTTPSession::bytes_to_hex(const ByteVector& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (const auto& byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return ss.str();
}

ByteVector HTTPServer::HTTPSession::hex_to_bytes(const std::string& hex) {
    ByteVector bytes;
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }
    
    return bytes;
}

// WebSocketSession implementation
HTTPServer::WebSocketSession::WebSocketSession(tcp::socket&& socket, std::shared_ptr<SecureGateway> gateway)
    : ws_(std::move(socket)), gateway_(gateway) {
}

void HTTPServer::WebSocketSession::start() {
    // Set suggested timeout settings for the websocket
    ws_.set_option(
        websocket::stream_base::timeout::suggested(
            beast::role_type::server));
    
    // Set a decorator to change the Server of the handshake
    ws_.set_option(websocket::stream_base::decorator(
        [](websocket::response_type& res) {
            res.set(http::field::server,
                "FinalDeFi-SecureGateway/0.2.0");
        }));
    
    // Accept the websocket handshake
    do_accept();
}

void HTTPServer::WebSocketSession::do_accept() {
    // Accept the WebSocket handshake
    ws_.async_accept(
        beast::bind_front_handler(
            [self = shared_from_this()](beast::error_code ec) {
                if (ec) {
                    SecureLogger::instance().error("WebSocket accept error: " + ec.message());
                    return;
                }
                
                // Read a message
                self->do_read();
            }));
}

void HTTPServer::WebSocketSession::do_read() {
    // Clear the buffer
    buffer_.consume(buffer_.size());
    
    // Read a message
    ws_.async_read(
        buffer_,
        beast::bind_front_handler(
            [self = shared_from_this()](beast::error_code ec, std::size_t bytes_transferred) {
                if (ec) {
                    if (ec != websocket::error::closed) {
                        SecureLogger::instance().error("WebSocket read error: " + ec.message());
                    }
                    return;
                }
                
                // Save the message
                self->message_ = beast::buffers_to_string(self->buffer_.data());
                
                // Process the message
                self->process_message(self->message_);
                
                // Read another message
                self->do_read();
            }));
}

void HTTPServer::WebSocketSession::process_message(const std::string& message) {
    try {
        // Parse the message as JSON
        std::istringstream iss(message);
        pt::ptree request;
        pt::read_json(iss, request);
        
        // Get the action
        std::string action = request.get<std::string>("action");
        
        // Prepare response
        pt::ptree response;
        response.put("success", true);
        
        if (action == "subscribe") {
            // Subscribe to events
            std::string event_type = request.get<std::string>("event_type");
            
            // Add subscription logic here
            response.put("message", "Subscribed to " + event_type);
            
        } else if (action == "unsubscribe") {
            // Unsubscribe from events
            std::string event_type = request.get<std::string>("event_type");
            
            // Add unsubscription logic here
            response.put("message", "Unsubscribed from " + event_type);
            
        } else if (action == "ping") {
            // Simple ping-pong
            response.put("message", "pong");
            
        } else {
            // Unknown action
            response.put("success", false);
            response.put("error", "Unknown action: " + action);
        }
        
        // Send response
        std::ostringstream oss;
        pt::write_json(oss, response);
        do_write(oss.str());
        
    } catch (const pt::ptree_error& e) {
        // Invalid JSON or missing required field
        pt::ptree response;
        response.put("success", false);
        response.put("error", "Invalid request format: " + std::string(e.what()));
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        do_write(oss.str());
    } catch (const std::exception& e) {
        // Other error
        pt::ptree response;
        response.put("success", false);
        response.put("error", "Error processing request: " + std::string(e.what()));
        
        std::ostringstream oss;
        pt::write_json(oss, response);
        do_write(oss.str());
    }
}

void HTTPServer::WebSocketSession::do_write(const std::string& message) {
    // Send the message
    ws_.async_write(
        net::buffer(message),
        beast::bind_front_handler(
            [self = shared_from_this()](beast::error_code ec, std::size_t bytes_transferred) {
                if (ec) {
                    SecureLogger::instance().error("WebSocket write error: " + ec.message());
                    return;
                }
            }));
}

} // namespace secure_gateway
} // namespace finaldefi