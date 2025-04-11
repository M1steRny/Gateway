/**
 * @file MessageCompression.cpp
 * @brief Implementation of message compression utilities
 */

 #include "finaldefi/sdk/MessageCompression.hpp"
 #include "finaldefi/sdk/SecureLogger.hpp"
 #include <zlib.h>
 #include <stdexcept>
 #include <cstring>
 
 namespace finaldefi {
 namespace sdk {
 
 Result<ByteVector> MessageCompression::compress(const ByteVector& data, int level) {
     if (data.empty()) {
         return ByteVector();
     }
     
     try {
         // Initialize zlib stream
         z_stream stream;
         memset(&stream, 0, sizeof(stream));
         
         if (deflateInit2(&stream, level, Z_DEFLATED, 15 + 16, 9, Z_DEFAULT_STRATEGY) != Z_OK) {
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
         deflateEnd(&stream);
         
         if (result != Z_STREAM_END) {
             SecureLogger::instance().error("Failed to compress data: " + std::to_string(result));
             return ErrorCode::COMPRESSION_FAILED;
         }
         
         // Resize buffer to actual compressed size
         compressed.resize(dest_len - stream.avail_out);
         
         // Log compression stats
         double compression_ratio = 100.0 - ((double)compressed.size() / data.size() * 100.0);
         SecureLogger::instance().debug("Compressed " + std::to_string(data.size()) + 
                                   " bytes to " + std::to_string(compressed.size()) + 
                                   " bytes (" + std::to_string(compression_ratio) + "% reduction)");
         
         return compressed;
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception during compression: " + std::string(e.what()));
         return ErrorCode::COMPRESSION_FAILED;
     }
 }
 
 Result<ByteVector> MessageCompression::decompress(const ByteVector& compressed_data) {
     if (compressed_data.empty()) {
         return ByteVector();
     }
     
     try {
         // Initialize zlib stream
         z_stream stream;
         memset(&stream, 0, sizeof(stream));
         
         if (inflateInit2(&stream, 15 + 16) != Z_OK) {
             SecureLogger::instance().error("Failed to initialize zlib inflate");
             return ErrorCode::DECOMPRESSION_FAILED;
         }
         
         // Set input data
         stream.avail_in = static_cast<uInt>(compressed_data.size());
         stream.next_in = const_cast<Bytef*>(compressed_data.data());
         
         // Prepare output buffer (start with 2x input size)
         ByteVector decompressed(compressed_data.size() * 2);
         size_t total_out = 0;
         bool done = false;
         
         while (!done) {
             // Check if we need to expand the output buffer
             if (total_out >= decompressed.size()) {
                 // Double the buffer size
                 decompressed.resize(decompressed.size() * 2);
             }
             
             // Set output buffer
             stream.avail_out = static_cast<uInt>(decompressed.size() - total_out);
             stream.next_out = decompressed.data() + total_out;
             
             // Decompress
             int result = inflate(&stream, Z_SYNC_FLUSH);
             
             if (result == Z_STREAM_END) {
                 // Decompression complete
                 done = true;
             } else if (result != Z_OK) {
                 // Decompression error
                 inflateEnd(&stream);
                 SecureLogger::instance().error("Failed to decompress data: " + std::to_string(result));
                 return ErrorCode::DECOMPRESSION_FAILED;
             }
             
             total_out = decompressed.size() - stream.avail_out;
             
             // If output buffer is full but there's still input, continue the loop
             if (stream.avail_out == 0 && stream.avail_in > 0) {
                 continue;
             }
         }
         
         // Finalize
         inflateEnd(&stream);
         
         // Resize buffer to actual decompressed size
         decompressed.resize(total_out);
         
         SecureLogger::instance().debug("Decompressed " + std::to_string(compressed_data.size()) + 
                                   " bytes to " + std::to_string(decompressed.size()) + " bytes");
         
         return decompressed;
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception during decompression: " + std::string(e.what()));
         return ErrorCode::DECOMPRESSION_FAILED;
     }
 }
 
 } // namespace sdk
 } // namespace finaldefi