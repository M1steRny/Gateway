#pragma once

#include "types.hpp"
#include "constants.hpp"
#include <oqs/oqs.h>

namespace finaldefi {
namespace sdk {

/**
 * @brief Class implementing Dilithium3 post-quantum signatures
 */
class DilithiumSignature {
public:
    // Constructor
    DilithiumSignature();
    
    // Destructor
    ~DilithiumSignature();
    
    // Initialize the Dilithium signature scheme
    Result<void> initialize();
    
    // Generate a signature key pair
    Result<std::pair<ByteVector, ByteVector>> generate_keypair();
    
    // Sign a message
    Result<ByteVector> sign(const ByteVector& message, const ByteVector& secret_key);
    
    // Verify a signature
    Result<bool> verify(const ByteVector& message, const ByteVector& signature, const ByteVector& public_key);
    
    // Get metrics
    size_t get_keypairs_generated() const { return keypairs_generated_; }
    size_t get_signatures_performed() const { return signatures_performed_; }
    
private:
    // Clean up resources
    void cleanup_dilithium_objects();
    
    OQS_SIG* sig_ = nullptr;
    
    // Metrics
    std::atomic<size_t> keypairs_generated_{0};
    std::atomic<size_t> signatures_performed_{0};
};

} // namespace sdk
} // namespace finaldefi