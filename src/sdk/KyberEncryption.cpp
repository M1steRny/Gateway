#include "finaldefi/sdk/KyberEncryption.hpp"
#include "finaldefi/sdk/SecureLogger.hpp"
#include <sodium.h>
#include <chrono>

namespace finaldefi {
namespace sdk {

KyberEncryption::KyberEncryption() : kem_(nullptr) {
}

KyberEncryption::~KyberEncryption() {
    cleanup_kyber_objects();
}

Result<void> KyberEncryption::initialize() {
    cleanup_kyber_objects();
    
    kem_ = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (kem_ == nullptr) {
        SecureLogger::instance().error("Failed to initialize Kyber1024 KEM");
        return ErrorCode::PQ_LIBRARY_ERROR;
    }
    
    SecureLogger::instance().debug("Kyber1024 KEM initialized");
    return ErrorCode::SUCCESS;
}

Result<std::pair<ByteVector, ByteVector>> KyberEncryption::generate_keypair() {
    if (!kem_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    ByteVector public_key(constants::KYBER1024_PUBLIC_KEY_SIZE);
    ByteVector secret_key(constants::KYBER1024_SECRET_KEY_SIZE);
    
    OQS_STATUS status = OQS_KEM_keypair(kem_, public_key.data(), secret_key.data());
    if (status != OQS_SUCCESS) {
        SecureLogger::instance().error("Failed to generate Kyber1024 keypair");
        return ErrorCode::PQ_LIBRARY_ERROR;
    }
    
    SecureLogger::instance().debug("Kyber1024 keypair generated");
    keypairs_generated_++;
    
    return std::make_pair(std::move(public_key), std::move(secret_key));
}

Result<std::pair<ByteVector, ByteVector>> KyberEncryption::encapsulate(const ByteVector& public_key) {
    if (!kem_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    if (public_key.size() != constants::KYBER1024_PUBLIC_KEY_SIZE) {
        SecureLogger::instance().error("Invalid Kyber1024 public key size: " + std::to_string(public_key.size()));
        return ErrorCode::INVALID_PARAMETER;
    }
    
    ByteVector ciphertext(constants::KYBER1024_CIPHERTEXT_SIZE);
    ByteVector shared_secret(constants::KYBER1024_SHARED_SECRET_SIZE);
    
    OQS_STATUS status = OQS_KEM_encaps(kem_, ciphertext.data(), shared_secret.data(), public_key.data());
    if (status != OQS_SUCCESS) {
        SecureLogger::instance().error("Failed to encapsulate Kyber1024 shared secret");
        return ErrorCode::ENCRYPTION_FAILED;
    }
    
    encryptions_performed_++;
    return std::make_pair(std::move(ciphertext), std::move(shared_secret));
}

Result<std::pair<std::pair<ByteVector, ByteVector>, ByteVector>> KyberEncryption::double_encapsulate(const ByteVector& public_key) {
    // First encapsulation
    auto encaps1_result = encapsulate(public_key);
    if (encaps1_result.is_err()) {
        return encaps1_result.error();
    }
    
    auto [ciphertext1, shared_secret1] = encaps1_result.value();
    
    // Second encapsulation
    auto encaps2_result = encapsulate(public_key);
    if (encaps2_result.is_err()) {
        return encaps2_result.error();
    }
    
    auto [ciphertext2, shared_secret2] = encaps2_result.value();
    
    // Combine the shared secrets for enhanced security
    ByteVector combined_secret(shared_secret1.size());
    for (size_t i = 0; i < shared_secret1.size(); i++) {
        combined_secret[i] = shared_secret1[i] ^ shared_secret2[i];
    }
    
    SecureLogger::instance().debug("Kyber1024 double encapsulation completed");
    return std::make_pair(std::make_pair(std::move(ciphertext1), std::move(ciphertext2)), std::move(combined_secret));
}

Result<ByteVector> KyberEncryption::decapsulate(const ByteVector& ciphertext, const ByteVector& secret_key) {
    if (!kem_) {
        auto init_result = initialize();
        if (init_result.is_err()) {
            return init_result.error();
        }
    }
    
    if (ciphertext.size() != constants::KYBER1024_CIPHERTEXT_SIZE || 
        secret_key.size() != constants::KYBER1024_SECRET_KEY_SIZE) {
        SecureLogger::instance().error("Invalid Kyber1024 ciphertext or secret key size");
        return ErrorCode::INVALID_PARAMETER;
    }
    
    ByteVector shared_secret(constants::KYBER1024_SHARED_SECRET_SIZE);
    
    OQS_STATUS status = OQS_KEM_decaps(kem_, shared_secret.data(), ciphertext.data(), secret_key.data());
    if (status != OQS_SUCCESS) {
        SecureLogger::instance().error("Failed to decapsulate Kyber1024 shared secret");
        return ErrorCode::DECRYPTION_FAILED;
    }
    
    return shared_secret;
}

Result<ByteVector> KyberEncryption::double_decapsulate(const ByteVector& ciphertext1, const ByteVector& ciphertext2, const ByteVector& secret_key) {
    // First decapsulation
    auto decaps1_result = decapsulate(ciphertext1, secret_key);
    if (decaps1_result.is_err()) {
        return decaps1_result.error();
    }
    
    auto shared_secret1 = decaps1_result.value();
    
    // Second decapsulation
    auto decaps2_result = decapsulate(ciphertext2, secret_key);
    if (decaps2_result.is_err()) {
        return decaps2_result.error();
    }
    
    auto shared_secret2 = decaps2_result.value();
    
    // Combine the shared secrets (must match the combination in double_encapsulate)
    ByteVector combined_secret(shared_secret1.size());
    for (size_t i = 0; i < shared_secret1.size(); i++) {
        combined_secret[i] = shared_secret1[i] ^ shared_secret2[i];
    }
    
    SecureLogger::instance().debug("Kyber1024 double decapsulation completed");
    return combined_secret;
}

Result<ByteVector> KyberEncryption::encrypt_data(const ByteVector& data, const ByteVector& shared_secret) {
    if (shared_secret.size() != constants::KYBER1024_SHARED_SECRET_SIZE) {
        SecureLogger::instance().error("Invalid Kyber1024 shared secret size");
        return ErrorCode::INVALID_PARAMETER;
    }
    
    // Derive a symmetric key using the shared secret
    std::array<uint8_t, crypto_secretbox_KEYBYTES> symmetric_key;
    crypto_kdf_derive_from_key(symmetric_key.data(), symmetric_key.size(), 1, "encrypt", shared_secret.data());
    
    // Generate a random nonce
    std::array<uint8_t, crypto_secretbox_NONCEBYTES> nonce;
    randombytes_buf(nonce.data(), nonce.size());
    
    // Allocate space for the ciphertext (including nonce and authentication tag)
    ByteVector ciphertext(nonce.size() + data.size() + crypto_secretbox_MACBYTES);
    
    // Copy the nonce to the beginning of the ciphertext
    std::copy(nonce.begin(), nonce.end(), ciphertext.begin());
    
    // Encrypt the data
    int result = crypto_secretbox_easy(
        ciphertext.data() + nonce.size(),
        data.data(),
        data.size(),
        nonce.data(),
        symmetric_key.data()
    );
    
    // Clear sensitive material immediately
    sodium_memzero(symmetric_key.data(), symmetric_key.size());
    
    if (result != 0) {
        SecureLogger::instance().error("Failed to encrypt data with derived symmetric key");
        return ErrorCode::ENCRYPTION_FAILED;
    }
    
    SecureLogger::instance().debug("Data encrypted with Kyber1024-derived key");
    return ciphertext;
}

Result<ByteVector> KyberEncryption::decrypt_data(const ByteVector& ciphertext, const ByteVector& shared_secret) {
    if (shared_secret.size() != constants::KYBER1024_SHARED_SECRET_SIZE || 
        ciphertext.size() <= crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        SecureLogger::instance().error("Invalid Kyber1024 shared secret or ciphertext size");
        return ErrorCode::INVALID_PARAMETER;
    }
    
    // Derive the symmetric key from the shared secret
    std::array<uint8_t, crypto_secretbox_KEYBYTES> symmetric_key;
    crypto_kdf_derive_from_key(symmetric_key.data(), symmetric_key.size(), 1, "encrypt", shared_secret.data());
    
    // Extract the nonce from the ciphertext
    std::array<uint8_t, crypto_secretbox_NONCEBYTES> nonce;
    std::copy(ciphertext.begin(), ciphertext.begin() + nonce.size(), nonce.begin());
    
    // Allocate space for the plaintext
    size_t plaintext_size = ciphertext.size() - nonce.size() - crypto_secretbox_MACBYTES;
    ByteVector plaintext(plaintext_size);
    
    // Decrypt the data
    int result = crypto_secretbox_open_easy(
        plaintext.data(),
        ciphertext.data() + nonce.size(),
        ciphertext.size() - nonce.size(),
        nonce.data(),
        symmetric_key.data()
    );
    
    // Clear sensitive material immediately
    sodium_memzero(symmetric_key.data(), symmetric_key.size());
    
    if (result != 0) {
        SecureLogger::instance().error("Failed to decrypt data with derived symmetric key");
        return ErrorCode::DECRYPTION_FAILED;
    }
    
    SecureLogger::instance().debug("Data decrypted with Kyber1024-derived key");
    return plaintext;
}

void KyberEncryption::cleanup_kyber_objects() {
    if (kem_) {
        OQS_KEM_free(kem_);
        kem_ = nullptr;
    }
}

} // namespace sdk
} // namespace finaldefi