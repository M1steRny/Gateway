#pragma once

#include "types.hpp"
#include "constants.hpp"
#include "AttestationStore.hpp"
#include "CircuitBreaker.hpp"
#include "PQNetworking.hpp"

namespace finaldefi {
namespace sdk {

/**
 * @brief FinalChain submission client for publishing attestations
 */
class FinalChainSubmitter {
public:
    // Constructor
    FinalChainSubmitter(const std::string& finalchain_url);
    
    // Submit an attestation to FinalChain
    Result<ByteVector> submit_attestation(const Attestation& attestation);
    
    // Check an attestation's inclusion on FinalChain
    Result<bool> check_attestation_inclusion(const ByteVector& attestation_id, const ByteVector& tx_hash);
    
private:
    std::string finalchain_url_;
    std::unique_ptr<PQNetworking> networking_;
    CircuitBreaker circuit_breaker_;
};

} // namespace sdk
} // namespace finaldefi