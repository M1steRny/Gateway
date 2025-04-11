#include "finaldefi/sdk/MessageCompression.hpp"
#include "finaldefi/sdk/SecureLogger.hpp"
#include <cstring>

namespace finaldefi {
namespace sdk {

// Compress data using zlib
Result<ByteVector> MessageCompression::compress(const ByteVector& data, int level) {
    if (data.empty()) {
        return ByteVector();
    }
    
    // Initialize zlib stream
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    
    if (deflateInit(&stream, level) != Z_OK) {
        SecureLogger::instance().error("Failed to initialize zlib deflate");
        return ErrorCode::COMPRESSION_FAILED;
    }
    
    // Set input data
    stream.avail_in = static_cast<uInt>(data.size());
    stream.next_in = const_cast<Bytef*>(data.data());
    
    // Calculate upper bound for output buffer
    uLong dest_len = compressBound(static_cast<uLong>(data.size()));
    ByteVector compressed(dest_len);
    
    // Set output buffer
    stream.avail_out = static_cast<uInt>(compressed.size());
    stream.next_out = compressed.data();
    
    // Compress data
    int result = deflate(&stream, Z_FINISH);
    
    // Clean up
    int status = deflateEnd(&stream);
    
    if (result != Z_STREAM_END || status != Z_OK) {
        SecureLogger::instance().error("Failed to compress data: " + std::to_string(result) +
                                ", deflateEnd status: " + std::to_string(status));
        return ErrorCode::COMPRESSION_FAILED;
    }
    
    // Resize buffer to actual compressed size
    compressed.resize(dest_len - stream.avail_out);
    
    SecureLogger::instance().debug("Compressed data from " + std::to_string(data.size()) + 
                           " to " + std::to_string(compressed.size()) + " bytes");
    
    return compressed;
}

// Decompress data using zlib
Result<ByteVector> MessageCompression::decompress(const ByteVector& compressed_data) {
    if (compressed_data.empty()) {
        return ByteVector();
    }
    
    // Initialize zlib stream
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    
    if (inflateInit(&stream) != Z_OK) {
        SecureLogger::instance().error("Failed to initialize zlib inflate");
        return ErrorCode::DECOMPRESSION_FAILED;
    }
    
    // Set input data
    stream.avail_in = static_cast<uInt>(compressed_data.size());
    stream.next_in = const_cast<Bytef*>(compressed_data.data());
    
    // Prepare output buffer (start with 2x input size)
    ByteVector decompressed(compressed_data.size() * 2);
    size_t total_out = 0;
    
    int status = Z_OK;
    bool done = false;
    
    // Decompress in chunks until stream end or error
    while (!done) {
        // Set output buffer
        stream.avail_out = static_cast<uInt>(decompressed.size() - total_out);
        stream.next_out = decompressed.data() + total_out;
        
        // Decompress
        status = inflate(&stream, Z_NO_FLUSH);
        
        if (status == Z_STREAM_END) {
            done = true;
        } else if (status != Z_OK) {
            inflateEnd(&stream);
            SecureLogger::instance().error("Failed to decompress data: " + std::to_string(status));
            return ErrorCode::DECOMPRESSION_FAILED;
        }
        
        // Update total_out from stream
        total_out = stream.total_out;
        
        // If we've used all output space, increase buffer size
        if (stream.avail_out == 0 && !done) {
            decompressed.resize(decompressed.size() * 2);
        }
    }
    
    // Clean up
    inflateEnd(&stream);
    
    // Resize buffer to actual decompressed size
    decompressed.resize(total_out);
    
    SecureLogger::instance().debug("Decompressed data from " + std::to_string(compressed_data.size()) + 
                           " to " + std::to_string(decompressed.size()) + " bytes");
    
    return decompressed;
}

} // namespace sdk
} // namespace finaldefi