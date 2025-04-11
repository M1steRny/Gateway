#pragma once

#include <string>
#include <chrono>
#include <cstdint>
#include <array>

namespace finaldefi {
namespace sdk {

/**
 * @brief Constants for the FinalDeFi SDK
 */
namespace constants {
    // Cryptographic constants
    constexpr size_t KYBER1024_PUBLIC_KEY_SIZE = 1568;  // Kyber1024 public key size
    constexpr size_t KYBER1024_SECRET_KEY_SIZE = 3168;  // Kyber1024 secret key size
    constexpr size_t KYBER1024_CIPHERTEXT_SIZE = 1568;  // Kyber1024 ciphertext size
    constexpr size_t KYBER1024_SHARED_SECRET_SIZE = 32; // Kyber1024 shared secret size
    
    constexpr size_t DILITHIUM3_PUBLIC_KEY_SIZE = 1952;  // Dilithium3 public key size
    constexpr size_t DILITHIUM3_SECRET_KEY_SIZE = 4000;  // Dilithium3 secret key size
    constexpr size_t DILITHIUM3_SIGNATURE_SIZE = 3293;   // Dilithium3 signature size
    
    constexpr size_t NODE_ID_SIZE = 32;
    constexpr size_t QUORUM_THRESHOLD = 2; // 2/3 nodes needed
    constexpr size_t QUORUM_TOTAL = 3;     // Total parts of the threshold
    
    // Timing constants
    constexpr auto KEY_ROTATION_INTERVAL = std::chrono::hours(1); // Keys rotate every hour
    constexpr auto NODE_HEARTBEAT_INTERVAL = std::chrono::seconds(5); // Node heartbeat interval
    constexpr auto CONNECTION_TIMEOUT = std::chrono::seconds(30);
    constexpr auto CIRCUIT_BREAKER_RESET_TIMEOUT = std::chrono::seconds(60);
    constexpr auto EPOCH_INTERVAL = std::chrono::minutes(10); // Epoch processing interval
    constexpr auto NODE_REGISTRY_SYNC_INTERVAL = std::chrono::minutes(30); // Registry sync interval
    
    // Size constants
    constexpr auto MAX_MESSAGE_SIZE = 1024 * 1024 * 10; // 10 MB
    constexpr auto DEFAULT_THREAD_POOL_SIZE = 32;
    constexpr auto CIRCUIT_BREAKER_THRESHOLD = 5;
    constexpr auto MAX_CONNECTION_RETRIES = 3;
    constexpr auto MERKLE_TREE_DEPTH = 20; // Supports up to 2^20 transactions per epoch
    constexpr auto TRANSACTION_BUFFER_SIZE = 10000; // Maximum transactions in buffer
    
    // Path constants
    const std::string SECRET_FILE_PATH = "/secrets/node_secrets.bin";
    const std::string REGISTRY_FILE_PATH = "/secrets/registry.bin";
    const std::string LOG_PATH = "/var/log/finaldefi/";
    const std::string TRANSACTION_STORE_PATH = "/var/lib/finaldefi/transactions/";
    const std::string ATTESTATION_STORE_PATH = "/var/lib/finaldefi/attestations/";
    
    // Node registration fingerprint hash key
    const uint8_t NODE_FINGERPRINT_KEY[32] = {
        0x4f, 0x70, 0x65, 0x6e, 0x51, 0x75, 0x61, 0x6e, 0x74, 0x75, 0x6d, 0x53, 
        0x65, 0x63, 0x75, 0x72, 0x65, 0x47, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 
        0x46, 0x69, 0x6e, 0x61, 0x6c, 0x44, 0x65, 0x46, 0x69
    };
}

} // namespace sdk
} // namespace finaldefi