#include "finaldefi/sdk/DilithiumSignature.hpp"
#include "finaldefi/sdk/SecureLogger.hpp"
#include <oqs/oqs.h>

namespace finaldefi {
namespace sdk {

DilithiumSignature::DilithiumSignature() : sig_(nullptr) {
}

DilithiumSignature::~DilithiumSignature() {
    cleanup_dilithium_objects();
}

Result<void> DilithiumSignature::initialize() {
    cleanup_dilithium_objects();
    
    sig_ = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig_ == nullptr) {
        SecureLogger::instance().error("Failed to initialize Dilithium3 signature");
        return ErrorCode::PQ_LIBRARY_ERROR;
    }
    
    SecureLogger::instance().debug("Dilithium3 signature initialized");
    return ErrorCode::SUCCESS;
}

Result<std::pair<ByteVector, ByteVector>> DilithiumSignature::generate_keypair() {
    if (!sig_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    ByteVector public_key(constants::DILITHIUM3_PUBLIC_KEY_SIZE);
    ByteVector secret_key(constants::DILITHIUM3_SECRET_KEY_SIZE);
    
    OQS_STATUS status = OQS_SIG_keypair(sig_, public_key.data(), secret_key.data());
    if (status != OQS_SUCCESS) {
        SecureLogger::instance().error("Failed to generate Dilithium3 keypair");
        return ErrorCode::PQ_LIBRARY_ERROR;
    }
    
    SecureLogger::instance().debug("Dilithium3 keypair generated");
    keypairs_generated_++;
    
    return std::make_pair(std::move(public_key), std::move(secret_key));
}

Result<ByteVector> DilithiumSignature::sign(const ByteVector& message, const ByteVector& secret_key) {
    if (!sig_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    if (secret_key.size() != constants::DILITHIUM3_SECRET_KEY_SIZE) {
        SecureLogger::instance().error("Invalid Dilithium3 secret key size");
        return ErrorCode::INVALID_PARAMETER;
    }
    
    ByteVector signature(constants::DILITHIUM3_SIGNATURE_SIZE);
    size_t signature_len;
    
    OQS_STATUS status = OQS_SIG_sign(sig_, signature.data(), &signature_len, 
                                    message.data(), message.size(), secret_key.data());
    
    if (status != OQS_SUCCESS) {
        SecureLogger::instance().error("Failed to sign message with Dilithium3");
        return ErrorCode::SIGNATURE_FAILED;
    }
    
    // Resize the signature to the actual length
    signature.resize(signature_len);
    
    SecureLogger::instance().debug("Message signed with Dilithium3");
    signatures_performed_++;
    
    return signature;
}

Result<bool> DilithiumSignature::verify(const ByteVector& message, const ByteVector& signature, const ByteVector& public_key) {
    if (!sig_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    if (public_key.size() != constants::DILITHIUM3_PUBLIC_KEY_SIZE) {
        SecureLogger::instance().error("Invalid Dilithium3 public key size");
        return ErrorCode::INVALID_PARAMETER;
    }
    
    OQS_STATUS status = OQS_SIG_verify(sig_, message.data(), message.size(), 
                                     signature.data(), signature.size(), public_key.data());
    
    bool is_valid = (status == OQS_SUCCESS);
    
    if (is_valid) {
        SecureLogger::instance().debug("Dilithium3 signature verified successfully");
    } else {
        SecureLogger::instance().warning("Dilithium3 signature verification failed");
    }
    
    return is_valid;
}

void DilithiumSignature::cleanup_dilithium_objects() {
    if (sig_) {
        OQS_SIG_free(sig_);
        sig_ = nullptr;
    }
}

} // namespace sdk
} // namespace finaldefi