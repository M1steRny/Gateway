#pragma once

#include "types.hpp"
#include "constants.hpp"
#include "KyberEncryption.hpp"
#include "DilithiumSignature.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <memory>

namespace finaldefi {
namespace sdk {

/**
 * @brief Class implementing post-quantum secure networking
 */
class PQNetworking {
public:
    struct SSLContext {
        SSL_CTX* ctx;
        std::shared_ptr<KyberEncryption> kyber;
        std::shared_ptr<DilithiumSignature> dilithium;
    };
    
    // Constructor
    PQNetworking();
    
    // Destructor
    ~PQNetworking();
    
    // Initialize SSL with PQ algorithms
    Result<void> initialize_ssl();
    
    // Create a PQ-secured connection
    Result<SSL*> create_connection(const std::string& host, int port);
    
    // Send data over PQ-secured connection
    Result<void> send_data(SSL* ssl, const ByteVector& data);
    
    // Receive data over PQ-secured connection
    Result<ByteVector> receive_data(SSL* ssl);
    
    // Close a PQ-secured connection
    void close_connection(SSL* ssl);
    
private:
    // Perform post-quantum handshake
    Result<void> perform_pq_handshake(SSL* ssl);
    
    // Rotate encryption and signature keys
    void rotate_keys();
    
    // Clean up SSL resources
    void cleanup_ssl();
    
    SSL_CTX* ssl_ctx_ = nullptr;
    std::shared_ptr<KyberEncryption> kyber_;
    std::shared_ptr<DilithiumSignature> dilithium_;
    
    std::pair<ByteVector, ByteVector> kyber_keypair_;
    std::pair<ByteVector, ByteVector> dilithium_keypair_;
    
    std::mutex key_mutex_;
    std::thread key_rotation_thread_;
    std::atomic<bool> running_{true};
};

} // namespace sdk
} // namespace finaldefi