#pragma once

#include "types.hpp"
#include "constants.hpp"

namespace finaldefi {
namespace sdk {

/**
 * @brief Class implementing threshold cryptography with post-quantum lattice security
 */
class ThresholdCrypto {
public:
    // Constructor
    ThresholdCrypto() = default;
    
    // Generate a set of threshold keys with required parts to reconstruct
    Result<std::pair<ByteVector, std::vector<ByteVector>>> generate_threshold_keys(size_t threshold, size_t total);
    
    // Combine threshold shares to reconstruct the original key
    Result<ByteVector> combine_threshold_shares(const std::vector<ByteVector>& shares, size_t threshold, size_t total);
    
private:
    // PQ-compatible threshold sharing (using matrix-based approach)
    Result<std::vector<ByteVector>> generate_pq_threshold_shares(const ByteVector& secret, size_t threshold, size_t total);
    
    // PQ-compatible threshold secret reconstruction
    Result<ByteVector> reconstruct_pq_threshold_secret(const std::vector<ByteVector>& shares, size_t threshold);
};

} // namespace sdk
} // namespace finaldefi