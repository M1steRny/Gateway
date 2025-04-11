#pragma once

#include "types.hpp"
#include "constants.hpp"
#include <oqs/oqs.h>

namespace finaldefi {
namespace sdk {

/**
 * @brief Class implementing Kyber1024 post-quantum key encapsulation
 */
class KyberEncryption {
public:
    // Constructor
    KyberEncryption();
    
    // Destructor
    ~KyberEncryption();
    
    // Initialize the Kyber KEM
    Result<void> initialize();
    
    // Generate a key pair
    Result<std::pair<ByteVector, ByteVector>> generate_keypair();
    
    // Encapsulate a shared secret (single encapsulation)
    Result<std::pair<ByteVector, ByteVector>> encapsulate(const ByteVector& public_key);
    
    // Double encapsulation for enhanced security
    Result<std::pair<std::pair<ByteVector, ByteVector>, ByteVector>> double_encapsulate(const ByteVector& public_key);
    
    // Decapsulate a shared secret (single decapsulation)
    Result<ByteVector> decapsulate(const ByteVector& ciphertext, const ByteVector& secret_key);
    
    // Double decapsulate a shared secret
    Result<ByteVector> double_decapsulate(
        const ByteVector& ciphertext1, 
        const ByteVector& ciphertext2, 
        const ByteVector& secret_key);
    
    // Encrypt data using Kyber-derived key
    Result<ByteVector> encrypt_data(const ByteVector& data, const ByteVector& shared_secret);
    
    // Decrypt data using Kyber-derived key
    Result<ByteVector> decrypt_data(const ByteVector& ciphertext, const ByteVector& shared_secret);
    
    // Get metrics
    size_t get_keypairs_generated() const { return keypairs_generated_; }
    size_t get_encryptions_performed() const { return encryptions_performed_; }
    
private:
    // Clean up resources
    void cleanup_kyber_objects();
    
    OQS_KEM* kem_ = nullptr;
    
    // Metrics
    std::atomic<size_t> keypairs_generated_{0};
    std::atomic<size_t> encryptions_performed_{0};
};

} // namespace sdk
} // namespace finaldefi