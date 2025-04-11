/**
 * @file AttestationStore.cpp
 * @brief Implementation of the attestation store for persisting and retrieving attestations
 */

 #include "finaldefi/sdk/AttestationStore.hpp"
 #include "finaldefi/sdk/SecureLogger.hpp"
 #include <filesystem>
 #include <fstream>
 #include <iostream>
 #include <iomanip>
 #include <sstream>
 #include <sodium.h>
 
 namespace finaldefi {
 namespace sdk {
 
 Attestation::Type string_to_attestation_type(const std::string& type_str) {
     if (type_str == "transaction") return Attestation::Type::TRANSACTION;
     if (type_str == "batch") return Attestation::Type::BATCH;
     if (type_str == "epoch") return Attestation::Type::EPOCH;
     if (type_str == "node_registration") return Attestation::Type::NODE_REGISTRATION;
     if (type_str == "key_rotation") return Attestation::Type::KEY_ROTATION;
     return Attestation::Type::CUSTOM;
 }
 
 std::string attestation_type_to_string(Attestation::Type type) {
     switch (type) {
         case Attestation::Type::TRANSACTION: return "transaction";
         case Attestation::Type::BATCH: return "batch";
         case Attestation::Type::EPOCH: return "epoch";
         case Attestation::Type::NODE_REGISTRATION: return "node_registration";
         case Attestation::Type::KEY_ROTATION: return "key_rotation";
         case Attestation::Type::CUSTOM: return "custom";
         default: return "unknown";
     }
 }
 
 ByteVector Attestation::serialize() const {
     ByteVector result;
     
     // ID
     uint16_t id_size = static_cast<uint16_t>(id.size());
     result.push_back((id_size >> 8) & 0xFF);
     result.push_back(id_size & 0xFF);
     result.insert(result.end(), id.begin(), id.end());
     
     // Timestamp
     for (int i = 7; i >= 0; i--) {
         result.push_back((timestamp >> (i * 8)) & 0xFF);
     }
     
     // Type
     result.push_back(static_cast<uint8_t>(type));
     
     // Entity IDs
     uint16_t entity_count = static_cast<uint16_t>(entity_ids.size());
     result.push_back((entity_count >> 8) & 0xFF);
     result.push_back(entity_count & 0xFF);
     
     for (const auto& entity_id : entity_ids) {
         uint16_t entity_id_size = static_cast<uint16_t>(entity_id.size());
         result.push_back((entity_id_size >> 8) & 0xFF);
         result.push_back(entity_id_size & 0xFF);
         result.insert(result.end(), entity_id.begin(), entity_id.end());
     }
     
     // Merkle root (optional)
     result.push_back(merkle_root.has_value() ? 1 : 0);
     if (merkle_root.has_value()) {
         uint16_t root_size = static_cast<uint16_t>(merkle_root.value().size());
         result.push_back((root_size >> 8) & 0xFF);
         result.push_back(root_size & 0xFF);
         result.insert(result.end(), merkle_root.value().begin(), merkle_root.value().end());
     }
     
     // Gateway signature
     uint16_t gateway_sig_size = static_cast<uint16_t>(gateway_signature.size());
     result.push_back((gateway_sig_size >> 8) & 0xFF);
     result.push_back(gateway_sig_size & 0xFF);
     result.insert(result.end(), gateway_signature.begin(), gateway_signature.end());
     
     // Quorum signatures
     uint16_t quorum_sig_count = static_cast<uint16_t>(quorum_signatures.size());
     result.push_back((quorum_sig_count >> 8) & 0xFF);
     result.push_back(quorum_sig_count & 0xFF);
     
     for (const auto& [node_id, signature] : quorum_signatures) {
         // Node ID
         result.insert(result.end(), node_id.begin(), node_id.end());
         
         // Signature
         uint16_t sig_size = static_cast<uint16_t>(signature.size());
         result.push_back((sig_size >> 8) & 0xFF);
         result.push_back(sig_size & 0xFF);
         result.insert(result.end(), signature.begin(), signature.end());
     }
     
     // Chain ID (optional)
     result.push_back(chain_id.has_value() ? 1 : 0);
     if (chain_id.has_value()) {
         uint32_t chain = chain_id.value();
         result.push_back((chain >> 24) & 0xFF);
         result.push_back((chain >> 16) & 0xFF);
         result.push_back((chain >> 8) & 0xFF);
         result.push_back(chain & 0xFF);
     }
     
     // Metadata
     uint16_t metadata_count = static_cast<uint16_t>(metadata.size());
     result.push_back((metadata_count >> 8) & 0xFF);
     result.push_back(metadata_count & 0xFF);
     
     for (const auto& [key, value] : metadata) {
         // Key
         uint16_t key_size = static_cast<uint16_t>(key.size());
         result.push_back((key_size >> 8) & 0xFF);
         result.push_back(key_size & 0xFF);
         result.insert(result.end(), key.begin(), key.end());
         
         // Value
         uint16_t value_size = static_cast<uint16_t>(value.size());
         result.push_back((value_size >> 8) & 0xFF);
         result.push_back(value_size & 0xFF);
         result.insert(result.end(), value.begin(), value.end());
     }
     
     return result;
 }
 
 Result<Attestation> Attestation::deserialize(const ByteVector& data) {
     if (data.size() < 2) {
         return ErrorCode::INVALID_PARAMETER;
     }
     
     Attestation attestation;
     size_t pos = 0;
     
     // ID
     uint16_t id_size = (data[pos] << 8) | data[pos + 1];
     pos += 2;
     
     if (pos + id_size > data.size()) return ErrorCode::INVALID_PARAMETER;
     attestation.id.assign(data.begin() + pos, data.begin() + pos + id_size);
     pos += id_size;
     
     // Timestamp
     if (pos + 8 > data.size()) return ErrorCode::INVALID_PARAMETER;
     attestation.timestamp = 0;
     for (int i = 0; i < 8; i++) {
         attestation.timestamp = (attestation.timestamp << 8) | data[pos + i];
     }
     pos += 8;
     
     // Type
     if (pos + 1 > data.size()) return ErrorCode::INVALID_PARAMETER;
     attestation.type = static_cast<Type>(data[pos]);
     pos += 1;
     
     // Entity IDs
     if (pos + 2 > data.size()) return ErrorCode::INVALID_PARAMETER;
     uint16_t entity_count = (data[pos] << 8) | data[pos + 1];
     pos += 2;
     
     for (uint16_t i = 0; i < entity_count; i++) {
         if (pos + 2 > data.size()) return ErrorCode::INVALID_PARAMETER;
         uint16_t entity_id_size = (data[pos] << 8) | data[pos + 1];
         pos += 2;
         
         if (pos + entity_id_size > data.size()) return ErrorCode::INVALID_PARAMETER;
         ByteVector entity_id(data.begin() + pos, data.begin() + pos + entity_id_size);
         attestation.entity_ids.push_back(entity_id);
         pos += entity_id_size;
     }
     
     // Merkle root (optional)
     if (pos + 1 > data.size()) return ErrorCode::INVALID_PARAMETER;
     bool has_merkle_root = (data[pos] == 1);
     pos += 1;
     
     if (has_merkle_root) {
         if (pos + 2 > data.size()) return ErrorCode::INVALID_PARAMETER;
         uint16_t root_size = (data[pos] << 8) | data[pos + 1];
         pos += 2;
         
         if (pos + root_size > data.size()) return ErrorCode::INVALID_PARAMETER;
         ByteVector root(data.begin() + pos, data.begin() + pos + root_size);
         attestation.merkle_root = root;
         pos += root_size;
     }
     
     // Gateway signature
     if (pos + 2 > data.size()) return ErrorCode::INVALID_PARAMETER;
     uint16_t gateway_sig_size = (data[pos] << 8) | data[pos + 1];
     pos += 2;
     
     if (pos + gateway_sig_size > data.size()) return ErrorCode::INVALID_PARAMETER;
     attestation.gateway_signature.assign(data.begin() + pos, data.begin() + pos + gateway_sig_size);
     pos += gateway_sig_size;
     
     // Quorum signatures
     if (pos + 2 > data.size()) return ErrorCode::INVALID_PARAMETER;
     uint16_t quorum_sig_count = (data[pos] << 8) | data[pos + 1];
     pos += 2;
     
     for (uint16_t i = 0; i < quorum_sig_count; i++) {
         // Node ID
         if (pos + constants::NODE_ID_SIZE > data.size()) return ErrorCode::INVALID_PARAMETER;
         NodeId node_id;
         std::copy(data.begin() + pos, data.begin() + pos + constants::NODE_ID_SIZE, node_id.begin());
         pos += constants::NODE_ID_SIZE;
         
         // Signature
         if (pos + 2 > data.size()) return ErrorCode::INVALID_PARAMETER;
         uint16_t sig_size = (data[pos] << 8) | data[pos + 1];
         pos += 2;
         
         if (pos + sig_size > data.size()) return ErrorCode::INVALID_PARAMETER;
         ByteVector signature(data.begin() + pos, data.begin() + pos + sig_size);
         pos += sig_size;
         
         attestation.quorum_signatures.push_back(std::make_pair(node_id, signature));
     }
     
     // Chain ID (optional)
     if (pos + 1 > data.size()) return ErrorCode::INVALID_PARAMETER;
     bool has_chain_id = (data[pos] == 1);
     pos += 1;
     
     if (has_chain_id) {
         if (pos + 4 > data.size()) return ErrorCode::INVALID_PARAMETER;
         uint32_t chain = (data[pos] << 24) | (data[pos + 1] << 16) | 
                         (data[pos + 2] << 8) | data[pos + 3];
         attestation.chain_id = chain;
         pos += 4;
     }
     
     // Metadata
     if (pos + 2 > data.size()) return ErrorCode::INVALID_PARAMETER;
     uint16_t metadata_count = (data[pos] << 8) | data[pos + 1];
     pos += 2;
     
     for (uint16_t i = 0; i < metadata_count; i++) {
         // Key
         if (pos + 2 > data.size()) return ErrorCode::INVALID_PARAMETER;
         uint16_t key_size = (data[pos] << 8) | data[pos + 1];
         pos += 2;
         
         if (pos + key_size > data.size()) return ErrorCode::INVALID_PARAMETER;
         std::string key(data.begin() + pos, data.begin() + pos + key_size);
         pos += key_size;
         
         // Value
         if (pos + 2 > data.size()) return ErrorCode::INVALID_PARAMETER;
         uint16_t value_size = (data[pos] << 8) | data[pos + 1];
         pos += 2;
         
         if (pos + value_size > data.size()) return ErrorCode::INVALID_PARAMETER;
         std::string value(data.begin() + pos, data.begin() + pos + value_size);
         pos += value_size;
         
         attestation.metadata[key] = value;
     }
     
     return attestation;
 }
 
 ByteVector Attestation::generate_id() {
     ByteVector id(32);
     randombytes_buf(id.data(), id.size());
     return id;
 }
 
 ByteVector Attestation::calculate_hash() const {
     ByteVector data_to_hash;
     
     // Include all relevant fields
     data_to_hash.insert(data_to_hash.end(), id.begin(), id.end());
     
     for (int i = 7; i >= 0; i--) {
         data_to_hash.push_back((timestamp >> (i * 8)) & 0xFF);
     }
     
     data_to_hash.push_back(static_cast<uint8_t>(type));
     
     for (const auto& entity_id : entity_ids) {
         data_to_hash.insert(data_to_hash.end(), entity_id.begin(), entity_id.end());
     }
     
     if (merkle_root.has_value()) {
         data_to_hash.insert(data_to_hash.end(), merkle_root.value().begin(), merkle_root.value().end());
     }
     
     if (chain_id.has_value()) {
         uint32_t chain = chain_id.value();
         data_to_hash.push_back((chain >> 24) & 0xFF);
         data_to_hash.push_back((chain >> 16) & 0xFF);
         data_to_hash.push_back((chain >> 8) & 0xFF);
         data_to_hash.push_back(chain & 0xFF);
     }
     
     // Calculate hash
     ByteVector hash(crypto_generichash_BYTES);
     crypto_generichash(hash.data(), hash.size(), data_to_hash.data(), data_to_hash.size(), nullptr, 0);
     
     return hash;
 }
 
 AttestationStore::AttestationStore(const std::string& store_path) 
     : store_path_(store_path) {
     // Create directories if they don't exist
     std::filesystem::create_directories(store_path_);
 }
 
 Result<void> AttestationStore::store_attestation(const Attestation& attestation) {
     std::string att_id_hex = bytes_to_hex(attestation.id);
     std::string filename = store_path_ + "/" + att_id_hex + ".att";
     
     try {
         // Serialize the attestation
         ByteVector serialized = attestation.serialize();
         
         // Write to file
         std::ofstream file(filename, std::ios::binary);
         if (!file) {
             SecureLogger::instance().error("Failed to open attestation file for writing: " + filename);
             return ErrorCode::FILE_IO_ERROR;
         }
         
         file.write(reinterpret_cast<const char*>(serialized.data()), serialized.size());
         file.close();
         
         SecureLogger::instance().debug("Stored attestation: " + att_id_hex);
         return ErrorCode::SUCCESS;
         
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception during attestation storage: " + std::string(e.what()));
         return ErrorCode::STORAGE_ERROR;
     }
 }
 
 Result<Attestation> AttestationStore::load_attestation(const ByteVector& att_id) {
     std::string att_id_hex = bytes_to_hex(att_id);
     std::string filename = store_path_ + "/" + att_id_hex + ".att";
     
     try {
         // Check if file exists
         if (!std::filesystem::exists(filename)) {
             SecureLogger::instance().error("Attestation file not found: " + filename);
             return ErrorCode::NODE_NOT_FOUND;
         }
         
         // Open file
         std::ifstream file(filename, std::ios::binary | std::ios::ate);
         if (!file) {
             SecureLogger::instance().error("Failed to open attestation file for reading: " + filename);
             return ErrorCode::FILE_IO_ERROR;
         }
         
         // Get file size
         size_t size = file.tellg();
         file.seekg(0, std::ios::beg);
         
         // Read file
         ByteVector serialized(size);
         if (!file.read(reinterpret_cast<char*>(serialized.data()), size)) {
             SecureLogger::instance().error("Failed to read attestation file: " + filename);
             return ErrorCode::FILE_IO_ERROR;
         }
         
         file.close();
         
         // Deserialize the attestation
         auto att_result = Attestation::deserialize(serialized);
         if (att_result.is_err()) {
             SecureLogger::instance().error("Failed to deserialize attestation: " + 
                                    ErrorCodeToString(att_result.error()));
             return att_result.error();
         }
         
         SecureLogger::instance().debug("Loaded attestation: " + att_id_hex);
         return att_result;
         
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception during attestation loading: " + std::string(e.what()));
         return ErrorCode::STORAGE_ERROR;
     }
 }
 
 Result<void> AttestationStore::update_attestation(const Attestation& attestation) {
     // Simply overwrite the existing attestation
     return store_attestation(attestation);
 }
 
 Result<void> AttestationStore::delete_attestation(const ByteVector& att_id) {
     std::string att_id_hex = bytes_to_hex(att_id);
     std::string filename = store_path_ + "/" + att_id_hex + ".att";
     
     try {
         // Check if file exists
         if (!std::filesystem::exists(filename)) {
             SecureLogger::instance().error("Attestation file not found for deletion: " + filename);
             return ErrorCode::NODE_NOT_FOUND;
         }
         
         // Delete file
         if (!std::filesystem::remove(filename)) {
             SecureLogger::instance().error("Failed to delete attestation file: " + filename);
             return ErrorCode::FILE_IO_ERROR;
         }
         
         SecureLogger::instance().debug("Deleted attestation: " + att_id_hex);
         return ErrorCode::SUCCESS;
         
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception during attestation deletion: " + std::string(e.what()));
         return ErrorCode::STORAGE_ERROR;
     }
 }
 
 Result<std::vector<Attestation>> AttestationStore::get_all_attestations() {
     try {
         std::vector<Attestation> attestations;
         
         for (const auto& entry : std::filesystem::directory_iterator(store_path_)) {
             if (entry.is_regular_file() && entry.path().extension() == ".att") {
                 // Get attestation ID from filename
                 std::string filename = entry.path().filename().string();
                 std::string att_id_hex = filename.substr(0, filename.size() - 4); // Remove '.att'
                 ByteVector att_id = hex_to_bytes(att_id_hex);
                 
                 // Load the attestation
                 auto att_result = load_attestation(att_id);
                 if (att_result.is_ok()) {
                     attestations.push_back(att_result.value());
                 }
             }
         }
         
         SecureLogger::instance().debug("Loaded " + std::to_string(attestations.size()) + " attestations");
         return attestations;
         
     } catch (const std::exception& e) {
         SecureLogger::instance().error("Exception during attestation listing: " + std::string(e.what()));
         return ErrorCode::STORAGE_ERROR;
     }
 }
 
 Result<std::vector<Attestation>> AttestationStore::get_attestations_by_type(Attestation::Type type) {
     auto all_att_result = get_all_attestations();
     if (all_att_result.is_err()) {
         return all_att_result.error();
     }
     
     std::vector<Attestation> all_attestations = all_att_result.value();
     std::vector<Attestation> filtered_attestations;
     
     std::copy_if(all_attestations.begin(), all_attestations.end(), 
                 std::back_inserter(filtered_attestations),
                 [type](const Attestation& att) { return att.type == type; });
     
     return filtered_attestations;
 }
 
 Result<std::vector<Attestation>> AttestationStore::get_attestations_by_entity_id(const ByteVector& entity_id) {
     auto all_att_result = get_all_attestations();
     if (all_att_result.is_err()) {
         return all_att_result.error();
     }
     
     std::vector<Attestation> all_attestations = all_att_result.value();
     std::vector<Attestation> filtered_attestations;
     
     std::copy_if(all_attestations.begin(), all_attestations.end(), 
                 std::back_inserter(filtered_attestations),
                 [&entity_id](const Attestation& att) {
                     return std::find(att.entity_ids.begin(), att.entity_ids.end(), entity_id) != att.entity_ids.end();
                 });
     
     return filtered_attestations;
 }
 
 std::string AttestationStore::bytes_to_hex(const ByteVector& bytes) {
     std::stringstream ss;
     ss << std::hex << std::setfill('0');
     
     for (const auto& byte : bytes) {
         ss << std::setw(2) << static_cast<int>(byte);
     }
     
     return ss.str();
 }
 
 ByteVector AttestationStore::hex_to_bytes(const std::string& hex) {
     ByteVector bytes;
     
     for (size_t i = 0; i < hex.length(); i += 2) {
         std::string byte_str = hex.substr(i, 2);
         uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
         bytes.push_back(byte);
     }
     
     return bytes;
 }
 
 } // namespace sdk
 } // namespace finaldefi