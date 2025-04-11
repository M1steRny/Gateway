#pragma once

#include <string>

namespace finaldefi {
namespace sdk {

/**
 * @brief Error codes for the FinalDeFi SDK
 */
enum class ErrorCode {
    SUCCESS = 0,
    INVALID_PARAMETER,
    MEMORY_ALLOCATION_FAILED,
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
    SIGNATURE_FAILED,
    VERIFICATION_FAILED,
    THRESHOLD_SHARES_INSUFFICIENT,
    QUORUM_NOT_REACHED,
    COMMUNICATION_FAILED,
    INTERNAL_ERROR,
    PQ_LIBRARY_ERROR,
    KEY_ROTATION_ERROR,
    NODE_VALIDATION_FAILED,
    INTEGRITY_CHECK_FAILED,
    COMPRESSION_FAILED,
    DECOMPRESSION_FAILED,
    FILE_IO_ERROR,
    NETWORK_ERROR,
    SSL_ERROR,
    CIRCUIT_OPEN,
    CONNECTION_TIMEOUT,
    MESSAGE_TOO_LARGE,
    THREAD_POOL_ERROR,
    TRANSACTION_VALIDATION_FAILED,
    NODE_REGISTRATION_FAILED,
    ATTESTATION_GENERATION_FAILED,
    MERKLE_TREE_ERROR,
    FINALCHAIN_SUBMISSION_FAILED,
    STORAGE_ERROR,
    NODE_NOT_FOUND,
    NODE_ALREADY_EXISTS,
    NODE_UNREACHABLE,
    NODE_INCOMPATIBLE_VERSION,
    NODE_UNTRUSTED,
    SCHEDULER_ERROR,
    TASK_EXECUTION_FAILED
};

/**
 * @brief Convert error code to string
 */
inline std::string ErrorCodeToString(ErrorCode error) {
    switch (error) {
        case ErrorCode::SUCCESS: return "Success";
        case ErrorCode::INVALID_PARAMETER: return "Invalid parameter";
        case ErrorCode::MEMORY_ALLOCATION_FAILED: return "Memory allocation failed";
        case ErrorCode::ENCRYPTION_FAILED: return "Encryption failed";
        case ErrorCode::DECRYPTION_FAILED: return "Decryption failed";
        case ErrorCode::SIGNATURE_FAILED: return "Signature failed";
        case ErrorCode::VERIFICATION_FAILED: return "Verification failed";
        case ErrorCode::THRESHOLD_SHARES_INSUFFICIENT: return "Insufficient threshold shares";
        case ErrorCode::QUORUM_NOT_REACHED: return "Quorum not reached";
        case ErrorCode::COMMUNICATION_FAILED: return "Communication failed";
        case ErrorCode::INTERNAL_ERROR: return "Internal error";
        case ErrorCode::PQ_LIBRARY_ERROR: return "Post-quantum library error";
        case ErrorCode::KEY_ROTATION_ERROR: return "Key rotation error";
        case ErrorCode::NODE_VALIDATION_FAILED: return "Node validation failed";
        case ErrorCode::INTEGRITY_CHECK_FAILED: return "Integrity check failed";
        case ErrorCode::COMPRESSION_FAILED: return "Compression failed";
        case ErrorCode::DECOMPRESSION_FAILED: return "Decompression failed";
        case ErrorCode::FILE_IO_ERROR: return "File I/O error";
        case ErrorCode::NETWORK_ERROR: return "Network error";
        case ErrorCode::SSL_ERROR: return "SSL error";
        case ErrorCode::CIRCUIT_OPEN: return "Circuit breaker open";
        case ErrorCode::CONNECTION_TIMEOUT: return "Connection timeout";
        case ErrorCode::MESSAGE_TOO_LARGE: return "Message too large";
        case ErrorCode::THREAD_POOL_ERROR: return "Thread pool error";
        case ErrorCode::TRANSACTION_VALIDATION_FAILED: return "Transaction validation failed";
        case ErrorCode::NODE_REGISTRATION_FAILED: return "Node registration failed";
        case ErrorCode::ATTESTATION_GENERATION_FAILED: return "Attestation generation failed";
        case ErrorCode::MERKLE_TREE_ERROR: return "Merkle tree error";
        case ErrorCode::FINALCHAIN_SUBMISSION_FAILED: return "FinalChain submission failed";
        case ErrorCode::STORAGE_ERROR: return "Storage error";
        case ErrorCode::NODE_NOT_FOUND: return "Node not found";
        case ErrorCode::NODE_ALREADY_EXISTS: return "Node already exists";
        case ErrorCode::NODE_UNREACHABLE: return "Node unreachable";
        case ErrorCode::NODE_INCOMPATIBLE_VERSION: return "Node incompatible version";
        case ErrorCode::NODE_UNTRUSTED: return "Node untrusted";
        case ErrorCode::SCHEDULER_ERROR: return "Scheduler error";
        case ErrorCode::TASK_EXECUTION_FAILED: return "Task execution failed";
        default: return "Unknown error";
    }
}

} // namespace sdk
} // namespace finaldefi