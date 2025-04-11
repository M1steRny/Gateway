#include "finaldefi/sdk/FinalChainSubmitter.hpp"
#include "finaldefi/sdk/SecureLogger.hpp"
#include "finaldefi/sdk/MessageCompression.hpp"
#include <chrono>
#include <thread>
#include <vector>
#include <random>
#include <algorithm>

namespace finaldefi {
namespace sdk {

// Constructor
FinalChainSubmitter::FinalChainSubmitter(const std::string& finalchain_url)
    : finalchain_url_(finalchain_url), 
      circuit_breaker_(constants::CIRCUIT_BREAKER_THRESHOLD, constants::CIRCUIT_BREAKER_RESET_TIMEOUT) {
    
    // Initialize networking components
    networking_ = std::make_unique<PQNetworking>();
    auto init_result = networking_->initialize_ssl();
    if (init_result.is_err()) {
        SecureLogger::instance().error("Failed to initialize PQNetworking for FinalChainSubmitter: " + 
                                init_result.error_message());
        throw std::runtime_error("Failed to initialize FinalChainSubmitter");
    }
    
    SecureLogger::instance().info("FinalChainSubmitter initialized for URL: " + finalchain_url_);
}

// Submit an attestation to FinalChain
Result<ByteVector> FinalChainSubmitter::submit_attestation(const Attestation& attestation) {
    try {
        // Serialize the attestation
        ByteVector serialized = attestation.serialize();
        
        // Apply exponential backoff retry strategy for resilience
        const size_t MAX_RETRIES = 5;
        std::vector<std::chrono::milliseconds> backoffs = {
            std::chrono::milliseconds(100),
            std::chrono::milliseconds(500),
            std::chrono::milliseconds(1000),
            std::chrono::milliseconds(3000),
            std::chrono::milliseconds(5000)
        };
        
        // Create random jitter to prevent thundering herd
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> jitter(-50, 50);
        
        // Execute with circuit breaker protection and retries
        for (size_t attempt = 0; attempt < MAX_RETRIES; attempt++) {
            auto result = circuit_breaker_.execute<ByteVector>([&]() {
                // Create connection to FinalChain
                auto conn_result = networking_->create_connection(finalchain_url_, 443);
                if (conn_result.is_err()) {
                    SecureLogger::instance().warning("FinalChain connection error (attempt " + 
                                              std::to_string(attempt+1) + "/" + 
                                              std::to_string(MAX_RETRIES) + "): " + 
                                              conn_result.error_message());
                    return conn_result.error();
                }
                
                SSL* ssl = conn_result.value();
                
                // Prepare submission request
                ByteVector request;
                
                // Add request type (1 byte)
                request.push_back(0x01); // 0x01 for attestation submission
                
                // Add attestation ID for idempotency
                uint16_t id_size = static_cast<uint16_t>(attestation.id.size());
                request.push_back((id_size >> 8) & 0xFF);
                request.push_back(id_size & 0xFF);
                request.insert(request.end(), attestation.id.begin(), attestation.id.end());
                
                // Add serialized attestation
                request.insert(request.end(), serialized.begin(), serialized.end());
                
                // Compress the request
                auto compression_result = MessageCompression::compress(request);
                if (compression_result.is_err()) {
                    networking_->close_connection(ssl);
                    SecureLogger::instance().error("Failed to compress attestation data: " + 
                                           compression_result.error_message());
                    return compression_result.error();
                }
                
                ByteVector compressed_request = compression_result.value();
                
                // Send compressed request
                auto send_result = networking_->send_data(ssl, compressed_request);
                if (send_result.is_err()) {
                    networking_->close_connection(ssl);
                    SecureLogger::instance().warning("Failed to send attestation to FinalChain (attempt " + 
                                              std::to_string(attempt+1) + "/" + 
                                              std::to_string(MAX_RETRIES) + "): " + 
                                              send_result.error_message());
                    return send_result.error();
                }
                
                // Set receive timeout for reliability
                struct timeval timeout;
                timeout.tv_sec = 15;
                timeout.tv_usec = 0;
                SSL_set_socket_read_timeout(ssl, &timeout);
                
                // Receive response
                auto recv_result = networking_->receive_data(ssl);
                
                networking_->close_connection(ssl);
                
                if (recv_result.is_err()) {
                    SecureLogger::instance().warning("Failed to receive response from FinalChain (attempt " + 
                                              std::to_string(attempt+1) + "/" + 
                                              std::to_string(MAX_RETRIES) + "): " + 
                                              recv_result.error_message());
                    return recv_result.error();
                }
                
                auto response = recv_result.value();
                
                // Decompress response if necessary
                ByteVector decompressed_response;
                if (response[0] == 0x01) { // Compressed response
                    auto decompress_result = MessageCompression::decompress(
                        ByteVector(response.begin() + 1, response.end()));
                    
                    if (decompress_result.is_err()) {
                        SecureLogger::instance().error("Failed to decompress FinalChain response: " + 
                                               decompress_result.error_message());
                        return decompress_result.error();
                    }
                    
                    decompressed_response = decompress_result.value();
                } else {
                    decompressed_response = response;
                }
                
                // Parse response
                if (decompressed_response.size() < 1) {
                    SecureLogger::instance().error("Invalid FinalChain response size");
                    return ErrorCode::INVALID_PARAMETER;
                }
                
                uint8_t status = decompressed_response[0];
                
                if (status != 0x00) {
                    // Error status
                    std::string error_message = "FinalChain submission error: " + std::to_string(status);
                    
                    // Extract error message if available
                    if (decompressed_response.size() > 2) {
                        uint8_t msg_len = decompressed_response[1];
                        if (decompressed_response.size() >= 2 + msg_len) {
                            std::string msg(decompressed_response.begin() + 2, 
                                          decompressed_response.begin() + 2 + msg_len);
                            error_message += " - " + msg;
                        }
                    }
                    
                    SecureLogger::instance().error(error_message);
                    return ErrorCode::FINALCHAIN_SUBMISSION_FAILED;
                }
                
                if (decompressed_response.size() < 33) { // 1 byte status + 32 bytes hash
                    SecureLogger::instance().error("Invalid FinalChain response format");
                    return ErrorCode::INVALID_PARAMETER;
                }
                
                // Extract transaction hash
                ByteVector tx_hash(decompressed_response.begin() + 1, decompressed_response.begin() + 33);
                
                SecureLogger::instance().info("Attestation submitted to FinalChain successfully");
                
                // Register success with circuit breaker
                circuit_breaker_.record_success();
                
                return tx_hash;
            });
            
            // If successful, return the result
            if (result.is_ok()) {
                return result;
            }
            
            // If permanent error or final attempt, return the error
            if (result.error() != ErrorCode::NETWORK_ERROR && 
                result.error() != ErrorCode::CONNECTION_TIMEOUT &&
                result.error() != ErrorCode::COMMUNICATION_FAILED) {
                
                return result;
            }
            
            // Add jitter to backoff to prevent thundering herd
            if (attempt < MAX_RETRIES - 1) {
                auto backoff = backoffs[attempt];
                auto jittered_backoff = backoff + std::chrono::milliseconds(jitter(gen));
                
                SecureLogger::instance().debug("Retrying FinalChain submission in " + 
                                       std::to_string(jittered_backoff.count()) + "ms");
                                       
                std::this_thread::sleep_for(jittered_backoff);
            }
        }
        
        // All attempts failed
        SecureLogger::instance().error("All attempts to submit attestation to FinalChain failed");
        return ErrorCode::FINALCHAIN_SUBMISSION_FAILED;
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during FinalChain submission: " + std::string(e.what()));
        circuit_breaker_.record_failure(e.what());
        return ErrorCode::FINALCHAIN_SUBMISSION_FAILED;
    }
}

// Check an attestation's inclusion on FinalChain
Result<bool> FinalChainSubmitter::check_attestation_inclusion(const ByteVector& attestation_id, const ByteVector& tx_hash) {
    try {
        // Execute with circuit breaker protection
        return circuit_breaker_.execute<bool>([&]() {
            // Create connection to FinalChain
            auto conn_result = networking_->create_connection(finalchain_url_, 443);
            if (conn_result.is_err()) {
                SecureLogger::instance().warning("FinalChain connection error during verification: " + 
                                          conn_result.error_message());
                return conn_result.error();
            }
            
            SSL* ssl = conn_result.value();
            
            // Prepare verification request
            ByteVector request;
            
            // Add request type (1 byte)
            request.push_back(0x02); // 0x02 for attestation verification
            
            // Add attestation ID
            uint16_t id_size = static_cast<uint16_t>(attestation_id.size());
            request.push_back((id_size >> 8) & 0xFF);
            request.push_back(id_size & 0xFF);
            request.insert(request.end(), attestation_id.begin(), attestation_id.end());
            
            // Add transaction hash
            uint16_t hash_size = static_cast<uint16_t>(tx_hash.size());
            request.push_back((hash_size >> 8) & 0xFF);
            request.push_back(hash_size & 0xFF);
            request.insert(request.end(), tx_hash.begin(), tx_hash.end());
            
            // Compress the request
            auto compression_result = MessageCompression::compress(request);
            if (compression_result.is_err()) {
                networking_->close_connection(ssl);
                SecureLogger::instance().error("Failed to compress verification request: " + 
                                       compression_result.error_message());
                return compression_result.error();
            }
            
            ByteVector compressed_request = compression_result.value();
            
            // Send compressed request
            auto send_result = networking_->send_data(ssl, compressed_request);
            if (send_result.is_err()) {
                networking_->close_connection(ssl);
                SecureLogger::instance().warning("Failed to send verification request to FinalChain: " + 
                                          send_result.error_message());
                return send_result.error();
            }
            
            // Set receive timeout for reliability
            struct timeval timeout;
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;
            SSL_set_socket_read_timeout(ssl, &timeout);
            
            // Receive response
            auto recv_result = networking_->receive_data(ssl);
            
            networking_->close_connection(ssl);
            
            if (recv_result.is_err()) {
                SecureLogger::instance().warning("Failed to receive verification response from FinalChain: " + 
                                          recv_result.error_message());
                return recv_result.error();
            }
            
            auto response = recv_result.value();
            
            // Decompress response if necessary
            ByteVector decompressed_response;
            if (response[0] == 0x01) { // Compressed response
                auto decompress_result = MessageCompression::decompress(
                    ByteVector(response.begin() + 1, response.end()));
                
                if (decompress_result.is_err()) {
                    SecureLogger::instance().error("Failed to decompress FinalChain verification response: " + 
                                           decompress_result.error_message());
                    return decompress_result.error();
                }
                
                decompressed_response = decompress_result.value();
            } else {
                decompressed_response = response;
            }
            
            // Parse response
            if (decompressed_response.size() < 1) {
                SecureLogger::instance().error("Invalid FinalChain verification response size");
                return ErrorCode::INVALID_PARAMETER;
            }
            
            uint8_t status = decompressed_response[0];
            
            if (status == 0x00) {
                // Success - attestation is included
                SecureLogger::instance().debug("Attestation verified and included in FinalChain");
                
                // Register success with circuit breaker
                circuit_breaker_.record_success();
                
                return true;
            } else if (status == 0x01) {
                // Attestation not included yet
                SecureLogger::instance().debug("Attestation not yet included in FinalChain");
                
                // Register success with circuit breaker (this is a valid response)
                circuit_breaker_.record_success();
                
                return false;
            } else {
                // Error status
                std::string error_message = "FinalChain verification error: " + std::to_string(status);
                
                // Extract error message if available
                if (decompressed_response.size() > 2) {
                    uint8_t msg_len = decompressed_response[1];
                    if (decompressed_response.size() >= 2 + msg_len) {
                        std::string msg(decompressed_response.begin() + 2, 
                                      decompressed_response.begin() + 2 + msg_len);
                        error_message += " - " + msg;
                    }
                }
                
                SecureLogger::instance().error(error_message);
                return ErrorCode::FINALCHAIN_SUBMISSION_FAILED;
            }
        });
        
    } catch (const std::exception& e) {
        SecureLogger::instance().error("Exception during FinalChain verification: " + std::string(e.what()));
        circuit_breaker_.record_failure(e.what());
        return ErrorCode::FINALCHAIN_SUBMISSION_FAILED;
    }
}

} // namespace sdk
} // namespace finaldefi