#pragma once

#include "types.hpp"
#include <zlib.h>

namespace finaldefi {
namespace sdk {

/**
 * @brief Message compression utility for reducing bandwidth usage
 */
class MessageCompression {
public:
    // Compress data using zlib
    static Result<ByteVector> compress(const ByteVector& data, int level = Z_BEST_COMPRESSION);
    
    // Decompress data using zlib
    static Result<ByteVector> decompress(const ByteVector& compressed_data);
};

} // namespace sdk
} // namespace finaldefi