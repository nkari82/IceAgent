#pragma once

#include <asio.hpp>
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <array>
#include <cstring>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <zlib.h> // For CRC32
#include <unordered_map>
#include <iostream>

// -------------------- ENUMS / CONSTANTS --------------------

// STUN Message Types (RFC 5389)
enum class StunMessageType : uint16_t {
    BINDING_REQUEST = 0x0001,
    BINDING_RESPONSE_SUCCESS = 0x0101,
    BINDING_RESPONSE_ERROR = 0x0111,
    BINDING_INDICATION = 0x0011, //
    ALLOCATE = 0x0003,
    ALLOCATE_RESPONSE_SUCCESS = 0x0103,
    ALLOCATE_RESPONSE_ERROR = 0x0113,
    // 추가 STUN/TURN 메시지 타입
};

// STUN Attribute Types (RFC 5389)
enum class StunAttributeType : uint16_t {
    MAPPED_ADDRESS = 0x0001,
    XOR_MAPPED_ADDRESS = 0x0020,
    USERNAME = 0x0006,
    MESSAGE_INTEGRITY = 0x0008,
    FINGERPRINT = 0x8028,
    ICE_CONTROLLING = 0x8029,
    ICE_CONTROLLED = 0x802A,
    USE_CANDIDATE = 0x802B, //
    REALM = 0x0014,
    NONCE = 0x0015,
    REQUESTED_TRANSPORT = 0x0019,
    RELAYED_ADDRESS = 0x0016, // RFC 5766
    REFRESH = 0x802C,
    // 기타 속성 타입
};

// STUN Magic Cookie (RFC 5389)
constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// Helper functions for byte order conversions
inline uint16_t htons_custom(uint16_t hostshort) {
    return htons(hostshort);
}

inline uint16_t ntohs_custom(uint16_t netshort) {
    return ntohs(netshort);
}

inline uint32_t htonl_custom(uint32_t hostlong) {
    return htonl(hostlong);
}

inline uint32_t ntohl_custom(uint32_t netlong) {
    return ntohl(netlong);
}

inline uint64_t htonll_custom(uint64_t hostlonglong) {
    // Convert host byte order to network byte order (big endian)
    // Since htonll is not standard, implement manually
    uint64_t net = 0;
    for(int i = 0; i < 8; ++i){
        net = (net << 8) | ((hostlonglong >> (56 - 8*i)) & 0xFF);
    }
    return net;
}

inline uint64_t ntohll_custom(uint64_t netlonglong) {
    // Convert network byte order to host byte order (big endian)
    // Implement manually
    uint64_t host = 0;
    for(int i = 0; i < 8; ++i){
        host = (host << 8) | ((netlonglong >> (56 - 8*i)) & 0xFF);
    }
    return host;
}

// -------------------- STUN MESSAGE --------------------
class StunMessage {
public:
    // Constructors
    StunMessage() : type_(StunMessageType::BINDING_REQUEST), message_length_(0) {
        transaction_id_.fill(0);
    }

    StunMessage(StunMessageType type, const std::vector<uint8_t>& transaction_id)
        : type_(type), message_length_(0)
    {
        if(transaction_id.size() != 12){
            throw std::invalid_argument("Transaction ID must be 12 bytes");
        }
        std::copy(transaction_id.begin(), transaction_id.end(), transaction_id_.begin());
    }

    // Static method to generate a random transaction ID
    static std::vector<uint8_t> generate_transaction_id(){
        std::vector<uint8_t> txn_id(12);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for(auto &byte : txn_id){
            byte = static_cast<uint8_t>(dis(gen));
        }
        return txn_id;
    }

    // Add attribute
    void add_attribute(StunAttributeType attr_type, const std::vector<uint8_t>& value){
        attributes_.emplace_back(Attribute{attr_type, value});
    }

    // Overloaded methods for specific attributes
    void add_attribute(StunAttributeType attr_type, const std::string& value){
        std::vector<uint8_t> data(value.begin(), value.end());
        add_attribute(attr_type, data);
    }

    void add_attribute(StunAttributeType attr_type, const uint32_t value){
        std::vector<uint8_t> data(4);
        uint32_t network_order = htonl_custom(value);
        std::memcpy(data.data(), &network_order, 4);
        add_attribute(attr_type, data);
    }

    void add_attribute(StunAttributeType attr_type, const uint64_t value){
        std::vector<uint8_t> data(8);
        uint64_t network_order = htonll_custom(value);
        std::memcpy(data.data(), &network_order, 8);
        add_attribute(attr_type, data);
    }

    void add_fingerprint(){
        // Calculate CRC32 over the entire message up to this point
        std::vector<uint8_t> data = serialize_without_fingerprint();
        uint32_t crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, data.data(), data.size());
        uint32_t fingerprint = crc ^ 0x5354554E; // XOR with 0x5354554E

        // Add FINGERPRINT attribute
        add_attribute(StunAttributeType::FINGERPRINT, fingerprint);
    }

    void add_message_integrity(const std::string& key){
        // Serialize the message up to MESSAGE-INTEGRITY attribute
        std::vector<uint8_t> data = serialize_for_integrity();

        // Compute HMAC-SHA1
        unsigned int len = 0;
        unsigned char* hmac_result = HMAC(EVP_sha1(),
                                         key.data(),
                                         static_cast<int>(key.size()),
                                         data.data(),
                                         data.size(),
                                         NULL,
                                         &len);
        if(!hmac_result){
            throw std::runtime_error("HMAC computation failed");
        }

        // Truncate to first 20 bytes as per RFC 5389
        std::vector<uint8_t> hmac_vec(hmac_result, hmac_result + len);
        add_attribute(StunAttributeType::MESSAGE_INTEGRITY, hmac_vec);
    }

    // Serialize the entire message
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buffer;

        // Header: Type (2 bytes), Length (2 bytes), Magic Cookie (4 bytes), Transaction ID (12 bytes)
        uint16_t type_network = htons_custom(static_cast<uint16_t>(type_));
        buffer.push_back(static_cast<uint8_t>(type_network >> 8));
        buffer.push_back(static_cast<uint8_t>(type_network & 0xFF));

        // Calculate total message length (attributes only)
        uint16_t message_length = 0;
        for(const auto& attr : attributes_){
            message_length += 4; // Type (2 bytes) + Length (2 bytes)
            message_length += attr.value.size();
            // Padding to 4-byte boundary
            if(attr.value.size() % 4 != 0){
                message_length += 4 - (attr.value.size() % 4);
            }
        }

        uint16_t length_network = htons_custom(message_length);
        buffer.push_back(static_cast<uint8_t>(length_network >> 8));
        buffer.push_back(static_cast<uint8_t>(length_network & 0xFF));

        // Magic Cookie
        buffer.push_back((STUN_MAGIC_COOKIE >> 24) & 0xFF);
        buffer.push_back((STUN_MAGIC_COOKIE >> 16) & 0xFF);
        buffer.push_back((STUN_MAGIC_COOKIE >> 8) & 0xFF);
        buffer.push_back(STUN_MAGIC_COOKIE & 0xFF);

        // Transaction ID
        buffer.insert(buffer.end(), transaction_id_.begin(), transaction_id_.end());

        // Attributes
        for(const auto& attr : attributes_){
            uint16_t attr_type_network = htons_custom(static_cast<uint16_t>(attr.type));
            buffer.push_back(static_cast<uint8_t>(attr_type_network >> 8));
            buffer.push_back(static_cast<uint8_t>(attr_type_network & 0xFF));

            uint16_t attr_length_network = htons_custom(static_cast<uint16_t>(attr.value.size()));
            buffer.push_back(static_cast<uint8_t>(attr_length_network >> 8));
            buffer.push_back(static_cast<uint8_t>(attr_length_network & 0xFF));

            buffer.insert(buffer.end(), attr.value.begin(), attr.value.end());

            // Padding to 4-byte boundary
            if(attr.value.size() % 4 != 0){
                buffer.insert(buffer.end(), 4 - (attr.value.size() % 4), 0);
            }
        }

        return buffer;
    }

    // Parse a raw buffer into a StunMessage
    static StunMessage parse(const std::vector<uint8_t>& data){
        if(data.size() < 20){
            throw std::invalid_argument("STUN message too short");
        }

        StunMessage msg;

        // Parse header
        msg.type_ = static_cast<StunMessageType>((data[0] << 8) | data[1]);
        msg.message_length_ = (data[2] << 8) | data[3];
        uint32_t magic_cookie = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
        if(magic_cookie != STUN_MAGIC_COOKIE){
            throw std::invalid_argument("Invalid STUN magic cookie");
        }

        // Transaction ID
        std::copy(data.begin() + 8, data.begin() + 20, msg.transaction_id_.begin());

        // Parse attributes
        size_t offset = 20;
        while(offset + 4 <= data.size() && offset < 20 + msg.message_length_){
            uint16_t attr_type = (data[offset] << 8) | data[offset + 1];
            uint16_t attr_length = (data[offset + 2] << 8) | data[offset + 3];
            offset += 4;

            if(offset + attr_length > data.size()){
                throw std::invalid_argument("STUN attribute length exceeds message size");
            }

            std::vector<uint8_t> attr_value(data.begin() + offset, data.begin() + offset + attr_length);
            msg.attributes_.emplace_back(Attribute{static_cast<StunAttributeType>(attr_type), attr_value});
            offset += attr_length;

            // Skip padding
            if(attr_length % 4 != 0){
                offset += 4 - (attr_length % 4);
            }
        }

        return msg;
    }

    // Getters
    StunMessageType get_type() const { return type_; }
    std::vector<uint8_t> get_transaction_id() const { return std::vector<uint8_t>(transaction_id_.begin(), transaction_id_.end()); }

    // Check if attribute exists
    bool has_attribute(StunAttributeType attr_type) const {
        return std::any_of(attributes_.begin(), attributes_.end(),
                           [&](const Attribute& attr){ return attr.type == attr_type; });
    }

    // Get attribute as string
    std::string get_attribute_as_string(StunAttributeType attr_type) const {
        for(const auto& attr : attributes_){
            if(attr.type == attr_type){
                return std::string(attr.value.begin(), attr.value.end());
            }
        }
        throw std::invalid_argument("Attribute not found");
    }

    // Get attribute as MAPPED_ADDRESS
    asio::ip::udp::endpoint get_attribute_as_mapped_address(StunAttributeType attr_type) const {
        for(const auto& attr : attributes_){
            if(attr.type == attr_type){
                if(attr.value.size() < 8){
                    throw std::invalid_argument("MAPPED_ADDRESS attribute too short");
                }
                uint8_t family = attr.value[1];
                uint16_t port = (attr.value[2] << 8) | attr.value[3];
                if(family == 0x01){ // IPv4
                    if(attr.value.size() < 8){
                        throw std::invalid_argument("MAPPED_ADDRESS IPv4 attribute too short");
                    }
                    asio::ip::address_v4::bytes_type bytes;
                    std::copy(attr.value.begin() + 4, attr.value.begin() + 8, bytes.begin());
                    asio::ip::address_v4 addr(bytes);
                    return asio::ip::udp::endpoint(addr, port);
                }
                else if(family == 0x02){ // IPv6
                    if(attr.value.size() < 20){
                        throw std::invalid_argument("MAPPED_ADDRESS IPv6 attribute too short");
                    }
                    asio::ip::address_v6::bytes_type bytes;
                    std::copy(attr.value.begin() + 4, attr.value.begin() + 20, bytes.begin());
                    asio::ip::address_v6 addr(bytes);
                    return asio::ip::udp::endpoint(addr, port);
                }
                else{
                    throw std::invalid_argument("Unsupported address family in MAPPED_ADDRESS");
                }
            }
        }
        throw std::invalid_argument("MAPPED_ADDRESS attribute not found");
    }

    // Get attribute as XOR-MAPPED_ADDRESS
    asio::ip::udp::endpoint get_attribute_as_xor_mapped_address(StunAttributeType attr_type, const asio::ip::udp::endpoint& request_endpoint) const {
        for(const auto& attr : attributes_){
            if(attr.type == attr_type){
                if(attr.value.size() < 8){
                    throw std::invalid_argument("XOR_MAPPED_ADDRESS attribute too short");
                }
                uint8_t family = attr.value[1];
                uint16_t xport = (attr.value[2] << 8) | attr.value[3];
                uint16_t port = xport ^ (STUN_MAGIC_COOKIE >> 16);
                if(family == 0x01){ // IPv4
                    if(attr.value.size() < 8){
                        throw std::invalid_argument("XOR_MAPPED_ADDRESS IPv4 attribute too short");
                    }
                    std::array<uint8_t, 4> bytes;
                    for(int i = 0; i < 4; ++i){
                        bytes[i] = attr.value[4 + i] ^ ((STUN_MAGIC_COOKIE >> (24 - 8*i)) & 0xFF);
                    }
                    asio::ip::address_v4::bytes_type addr_bytes;
                    std::copy(bytes.begin(), bytes.end(), addr_bytes.begin());
                    asio::ip::address_v4 addr(addr_bytes);
                    return asio::ip::udp::endpoint(addr, port);
                }
                else if(family == 0x02){ // IPv6
                    if(attr.value.size() < 20){
                        throw std::invalid_argument("XOR_MAPPED_ADDRESS IPv6 attribute too short");
                    }
                    asio::ip::address_v6::bytes_type bytes;
                    // XOR the first 4 bytes with magic cookie
                    for(int i = 0; i < 4; ++i){
                        bytes[i] = attr.value[4 + i] ^ ((STUN_MAGIC_COOKIE >> (24 - 8*i)) & 0xFF);
                    }
                    // XOR the rest with transaction ID
                    auto txn_id = get_transaction_id();
                    for(int i = 4; i < 16; ++i){
                        bytes[i] = attr.value[4 + i] ^ txn_id[i - 4];
                    }
                    asio::ip::address_v6 addr(bytes);
                    return asio::ip::udp::endpoint(addr, port);
                }
                else{
                    throw std::invalid_argument("Unsupported address family in XOR_MAPPED_ADDRESS");
                }
            }
        }
        throw std::invalid_argument("XOR_MAPPED_ADDRESS attribute not found");
    }

    // Get attribute as uint32 (e.g., PRIORITY)
    uint32_t get_attribute_as_uint32(StunAttributeType attr_type) const {
        for(const auto& attr : attributes_){
            if(attr.type == attr_type){
                if(attr.value.size() < 4){
                    throw std::invalid_argument("Attribute value too short for uint32");
                }
                uint32_t val = (attr.value[0] << 24) | (attr.value[1] << 16) | (attr.value[2] << 8) | attr.value[3];
                return ntohl_custom(val);
            }
        }
        throw std::invalid_argument("Attribute not found for uint32");
    }

    // Get attribute as uint64 (e.g., ICE_CONTROLLING, ICE_CONTROLLED)
    uint64_t get_attribute_as_uint64(StunAttributeType attr_type) const {
        for(const auto& attr : attributes_){
            if(attr.type == attr_type){
                if(attr.value.size() < 8){
                    throw std::invalid_argument("Attribute value too short for uint64");
                }
                uint64_t val = 0;
                for(int i = 0; i < 8; ++i){
                    val = (val << 8) | attr.value[i];
                }
                return ntohll_custom(val);
            }
        }
        throw std::invalid_argument("Attribute not found for uint64");
    }

    // Verify MESSAGE-INTEGRITY
    bool verify_message_integrity(const std::string& key) const {
        // Find MESSAGE-INTEGRITY attribute
        auto it = std::find_if(attributes_.begin(), attributes_.end(),
                               [&](const Attribute& attr){ return attr.type == StunAttributeType::MESSAGE_INTEGRITY; });
        if(it == attributes_.end()){
            return false;
        }

        // Serialize message up to MESSAGE-INTEGRITY attribute
        size_t mi_index = std::distance(attributes_.begin(), it);
        std::vector<Attribute> attrs_up_to_mi(attributes_.begin(), it);
        StunMessage msg_copy;
        msg_copy.type_ = type_;
        msg_copy.transaction_id_ = transaction_id_;
        msg_copy.attributes_ = attrs_up_to_mi;
        std::vector<uint8_t> data = msg_copy.serialize();

        // Compute HMAC-SHA1
        unsigned int len = 0;
        unsigned char* hmac_result = HMAC(EVP_sha1(),
                                         key.data(),
                                         static_cast<int>(key.size()),
                                         data.data(),
                                         data.size(),
                                         NULL,
                                         &len);
        if(!hmac_result){
            return false;
        }

        // Compare with MESSAGE-INTEGRITY value (first 20 bytes of HMAC-SHA1)
        if(it->value.size() < 20){
            return false;
        }

        return std::equal(it->value.begin(), it->value.begin() + 20, hmac_result);
    }

    // Verify FINGERPRINT
    bool verify_fingerprint() const {
        // Find FINGERPRINT attribute
        auto it = std::find_if(attributes_.begin(), attributes_.end(),
                               [&](const Attribute& attr){ return attr.type == StunAttributeType::FINGERPRINT; });
        if(it == attributes_.end()){
            return false;
        }

        if(it->value.size() != 4){
            return false;
        }

        // Serialize message up to FINGERPRINT attribute
        size_t fp_index = std::distance(attributes_.begin(), it);
        std::vector<Attribute> attrs_up_to_fp(attributes_.begin(), it);
        StunMessage msg_copy;
        msg_copy.type_ = type_;
        msg_copy.transaction_id_ = transaction_id_;
        msg_copy.attributes_ = attrs_up_to_fp;
        std::vector<uint8_t> data = msg_copy.serialize();

        // Compute CRC32
        uint32_t crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, data.data(), data.size());
        uint32_t fingerprint = crc ^ 0x5354554E; // XOR with 0x5354554E

        // Extract fingerprint from attribute
        uint32_t recv_fingerprint = 0;
        for(int i = 0; i < 4; ++i){
            recv_fingerprint = (recv_fingerprint << 8) | it->value[i];
        }

        return fingerprint == recv_fingerprint;
    }

private:
    // Internal representation of a STUN attribute
    struct Attribute {
        StunAttributeType type;
        std::vector<uint8_t> value;
    };

    StunMessageType type_;
    uint16_t message_length_;
    std::array<uint8_t, 12> transaction_id_;
    std::vector<Attribute> attributes_;

    // Serialize message without FINGERPRINT (used internally)
    std::vector<uint8_t> serialize_without_fingerprint() const {
        std::vector<uint8_t> buffer;

        // Header: Type (2 bytes), Length (2 bytes), Magic Cookie (4 bytes), Transaction ID (12 bytes)
        uint16_t type_network = htons_custom(static_cast<uint16_t>(type_));
        buffer.push_back(static_cast<uint8_t>(type_network >> 8));
        buffer.push_back(static_cast<uint8_t>(type_network & 0xFF));

        // Calculate total message length (attributes only)
        uint16_t message_length = 0;
        for(const auto& attr : attributes_){
            message_length += 4; // Type (2 bytes) + Length (2 bytes)
            message_length += attr.value.size();
            // Padding to 4-byte boundary
            if(attr.value.size() % 4 != 0){
                message_length += 4 - (attr.value.size() % 4);
            }
        }

        uint16_t length_network = htons_custom(message_length);
        buffer.push_back(static_cast<uint8_t>(length_network >> 8));
        buffer.push_back(static_cast<uint8_t>(length_network & 0xFF));

        // Magic Cookie
        buffer.push_back((STUN_MAGIC_COOKIE >> 24) & 0xFF);
        buffer.push_back((STUN_MAGIC_COOKIE >> 16) & 0xFF);
        buffer.push_back((STUN_MAGIC_COOKIE >> 8) & 0xFF);
        buffer.push_back(STUN_MAGIC_COOKIE & 0xFF);

        // Transaction ID
        buffer.insert(buffer.end(), transaction_id_.begin(), transaction_id_.end());

        // Attributes
        for(const auto& attr : attributes_){
            if(attr.type == StunAttributeType::FINGERPRINT){
                continue; // Exclude FINGERPRINT
            }
            if(attr.type == StunAttributeType::MESSAGE_INTEGRITY){
                continue; // Exclude MESSAGE-INTEGRITY for HMAC calculation
            }
            uint16_t attr_type_network = htons_custom(static_cast<uint16_t>(attr.type));
            buffer.push_back(static_cast<uint8_t>(attr_type_network >> 8));
            buffer.push_back(static_cast<uint8_t>(attr_type_network & 0xFF));

            uint16_t attr_length_network = htons_custom(static_cast<uint16_t>(attr.value.size()));
            buffer.push_back(static_cast<uint8_t>(attr_length_network >> 8));
            buffer.push_back(static_cast<uint8_t>(attr_length_network & 0xFF));

            buffer.insert(buffer.end(), attr.value.begin(), attr.value.end());

            // Padding to 4-byte boundary
            if(attr.value.size() % 4 != 0){
                buffer.insert(buffer.end(), 4 - (attr.value.size() % 4), 0);
            }
        }

        return buffer;
    }

    // Serialize message up to MESSAGE-INTEGRITY (used for HMAC)
    std::vector<uint8_t> serialize_for_integrity() const {
        std::vector<uint8_t> buffer;

        // Header: Type (2 bytes), Length (2 bytes), Magic Cookie (4 bytes), Transaction ID (12 bytes)
        uint16_t type_network = htons_custom(static_cast<uint16_t>(type_));
        buffer.push_back(static_cast<uint8_t>(type_network >> 8));
        buffer.push_back(static_cast<uint8_t>(type_network & 0xFF));

        // Calculate total message length (attributes only, excluding MESSAGE-INTEGRITY and beyond)
        uint16_t message_length = 0;
        for(const auto& attr : attributes_){
            if(attr.type == StunAttributeType::MESSAGE_INTEGRITY){
                break; // Stop before MESSAGE-INTEGRITY
            }
            message_length += 4; // Type (2 bytes) + Length (2 bytes)
            message_length += attr.value.size();
            // Padding to 4-byte boundary
            if(attr.value.size() % 4 != 0){
                message_length += 4 - (attr.value.size() % 4);
            }
        }

        uint16_t length_network = htons_custom(message_length);
        buffer.push_back(static_cast<uint8_t>(length_network >> 8));
        buffer.push_back(static_cast<uint8_t>(length_network & 0xFF));

        // Magic Cookie
        buffer.push_back((STUN_MAGIC_COOKIE >> 24) & 0xFF);
        buffer.push_back((STUN_MAGIC_COOKIE >> 16) & 0xFF);
        buffer.push_back((STUN_MAGIC_COOKIE >> 8) & 0xFF);
        buffer.push_back(STUN_MAGIC_COOKIE & 0xFF);

        // Transaction ID
        buffer.insert(buffer.end(), transaction_id_.begin(), transaction_id_.end());

        // Attributes up to MESSAGE-INTEGRITY
        for(const auto& attr : attributes_){
            if(attr.type == StunAttributeType::MESSAGE_INTEGRITY){
                break;
            }
            uint16_t attr_type_network = htons_custom(static_cast<uint16_t>(attr.type));
            buffer.push_back(static_cast<uint8_t>(attr_type_network >> 8));
            buffer.push_back(static_cast<uint8_t>(attr_type_network & 0xFF));

            uint16_t attr_length_network = htons_custom(static_cast<uint16_t>(attr.value.size()));
            buffer.push_back(static_cast<uint8_t>(attr_length_network >> 8));
            buffer.push_back(static_cast<uint8_t>(attr_length_network & 0xFF));

            buffer.insert(buffer.end(), attr.value.begin(), attr.value.end());

            // Padding to 4-byte boundary
            if(attr.value.size() % 4 != 0){
                buffer.insert(buffer.end(), 4 - (attr.value.size() % 4), 0);
            }
        }

        return buffer;
    }
};

// -------------------- EXAMPLE USAGE --------------------

// Below is an example of how to use the StunMessage class.
// This is for demonstration purposes and should be placed in your implementation files.

/*
#include "stun_message.hpp"

int main(){
    try{
        // Create a Binding Request
        StunMessage binding_request(StunMessageType::BINDING_REQUEST, StunMessage::generate_transaction_id());

        // Add attributes if needed
        binding_request.add_fingerprint();

        // Serialize the message
        std::vector<uint8_t> serialized = binding_request.serialize();

        // Print serialized message
        std::cout << "Serialized STUN Binding Request: ";
        for(auto byte : serialized){
            printf("%02X ", byte);
        }
        std::cout << std::endl;

        // Parse the message back
        StunMessage parsed = StunMessage::parse(serialized);

        // Verify FINGERPRINT
        if(parsed.verify_fingerprint()){
            std::cout << "Fingerprint verified successfully." << std::endl;
        }
        else{
            std::cout << "Fingerprint verification failed." << std::endl;
        }
    }
    catch(const std::exception& ex){
        std::cerr << "Exception: " << ex.what() << std::endl;
    }

    return 0;
}
*/

