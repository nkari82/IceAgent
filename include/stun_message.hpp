#pragma once

#include <algorithm>
#include <array>
#include <asio.hpp>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "crc32.hpp"
#include "hmac_sha1.hpp"

// -------------------- ENUMS / CONSTANTS --------------------
// 메시지 유형	             응답 필요	재시도 필요 	설명
// BINDING_REQUEST	         예	        예	            연결 테스트 및 IP/포트 확인 요청.
// BINDING_RESPONSE_SUCCESS	 아니오	    아니오	        성공 응답. 추가 작업 불필요.
// BINDING_RESPONSE_ERROR	 아니오	    조건부	        실패 응답. 오류에 따라 재시도 가능.
// BINDING_INDICATION	     아니오	    아니오	        상태 정보 전달. 단방향 메시지.

// STUN Message Types (RFC 5389)
enum class StunMessageType : uint16_t {
    BINDING_REQUEST = 0x0001,
    BINDING_RESPONSE_SUCCESS = 0x0101,
    BINDING_RESPONSE_ERROR = 0x0111,
    BINDING_INDICATION = 0x0011,
    ALLOCATE = 0x0003,
    ALLOCATE_RESPONSE_SUCCESS = 0x0103,
    ALLOCATE_RESPONSE_ERROR = 0x0113
    // 추가 STUN/TURN 메시지 타입
};

// STUN Attribute Types (RFC 5389)
enum class StunAttributeType : uint16_t {
    MAPPED_ADDRESS = 0x0001,
    XOR_MAPPED_ADDRESS = 0x0020,
    RESPONSE_ADDRESS = 0x0002,  // RFC3489
    CHANGE_REQUEST = 0x0003,    // RFC3489
    SOURCE_ADDRESS = 0x0004,    // RFC3489
    CHANGE_ADDRESS = 0x0005,    // RFC3489
    PRIORITY = 0x0024,
    USERNAME = 0x0006,
    MESSAGE_INTEGRITY = 0x0008,
    FINGERPRINT = 0x8028,
    ICE_CONTROLLING = 0x8029,
    ICE_CONTROLLED = 0x802A,
    USE_CANDIDATE = 0x802B,
    ERROR_CODE = 0x0009,
    REALM = 0x0014,
    NONCE = 0x0015,
    REQUESTED_TRANSPORT = 0x0019,
    RELAYED_ADDRESS = 0x0016,
    REFRESH = 0x802C
    // 기타 속성 타입
};

// STUN Error Codes (RFC 5389)
enum class StunErrorCode : uint16_t {
    NONE = 0,
    TRY_ALTERNATE = 300,         // Alternate server recommendation
    BAD_REQUEST = 400,           // Malformed request
    UNAUTHORIZED = 401,          // Invalid credentials
    FORBIDDEN = 403,             // Operation forbidden
    UNKNOWN_ATTRIBUTE = 420,     // Unsupported attribute in request
    ALLOCATION_MISMATCH = 437,   // TURN-specific error
    STALE_NONCE = 438,           // Nonce expired
    SERVER_ERROR = 500,          // Server encountered an error
    INSUFFICIENT_CAPACITY = 508  // Insufficient resources
};

// STUN Magic Cookie (RFC 5389)
constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// Helper functions for byte order conversions
inline uint16_t htons_custom(uint16_t hostshort) { return asio::detail::socket_ops::host_to_network_short(hostshort); }

inline uint16_t ntohs_custom(uint16_t netshort) { return asio::detail::socket_ops::network_to_host_short(netshort); }

inline uint32_t htonl_custom(uint32_t hostlong) { return asio::detail::socket_ops::host_to_network_long(hostlong); }

inline uint32_t ntohl_custom(uint32_t netlong) { return asio::detail::socket_ops::host_to_network_long(netlong); }

inline uint64_t htonll_custom(uint64_t hostlonglong) {
    uint64_t net = 0;
    for (int i = 0; i < 8; ++i) {
        net = (net << 8) | ((hostlonglong >> (56 - 8 * i)) & 0xFF);
    }
    return net;
}

inline uint64_t ntohll_custom(uint64_t netlonglong) {
    uint64_t host = 0;
    for (int i = 0; i < 8; ++i) {
        host = (host << 8) | ((netlonglong >> (56 - 8 * i)) & 0xFF);
    }
    return host;
}

inline bool IsStunMessage(const std::vector<uint8_t> &data) {
    if (data.size() < 20)
        return false;  // 최소 STUN 헤더 크기
    uint16_t type = (data[0] << 8) | data[1];
    return (type >= 0x0000 && type <= 0x3FFF);
}

inline std::string get_error_reason(StunErrorCode code) {
    switch (code) {
        case StunErrorCode::TRY_ALTERNATE:
            return "Try Alternate";
        case StunErrorCode::BAD_REQUEST:
            return "Bad Request";
        case StunErrorCode::UNAUTHORIZED:
            return "Unauthorized";
        case StunErrorCode::FORBIDDEN:
            return "Forbidden";
        case StunErrorCode::UNKNOWN_ATTRIBUTE:
            return "Unknown Attribute";
        case StunErrorCode::ALLOCATION_MISMATCH:
            return "Allocation Mismatch";
        case StunErrorCode::STALE_NONCE:
            return "Stale Nonce";
        case StunErrorCode::SERVER_ERROR:
            return "Server Error";
        case StunErrorCode::INSUFFICIENT_CAPACITY:
            return "Insufficient Capacity";
        default:
            return "Unknown Error";
    }
}

// -------------------- STUN MESSAGE --------------------
class StunMessage {
   public:
    struct Key {
        std::array<uint8_t, 12> data{0};
        struct Hasher {
            std::size_t operator()(const Key &key) const {
                std::size_t hash = 0;
                for (auto byte : key.data) {
                    hash ^= std::hash<uint8_t>{}(byte) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
                }
                return hash;
            }
        };

        // Static method to generate a random transaction ID
        static Key generate() {
            Key txn_id;
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            for (auto &byte : txn_id) {
                byte = static_cast<uint8_t>(dis(gen));
            }
            return txn_id;
        }

        bool operator==(const Key &other) const { return data == other.data; }

        inline std::array<uint8_t, 12>::iterator begin() { return data.begin(); }
        inline std::array<uint8_t, 12>::iterator end() { return data.end(); }
        inline std::array<uint8_t, 12>::const_iterator cbegin() const { return data.cbegin(); }
        inline std::array<uint8_t, 12>::const_iterator cend() const { return data.cend(); }
        size_t size() const { return data.size(); }
        uint8_t operator[](size_t i) const { return data[i]; }
    };

    // Constructors
    StunMessage() : type_(StunMessageType::BINDING_REQUEST), message_length_(0) {}

    StunMessage(StunMessageType type, const Key &transaction_id) : type_(type), message_length_(0) {
        std::copy(transaction_id.cbegin(), transaction_id.cend(), transaction_id_.begin());
    }

    // Add attribute
    void add_attribute(StunAttributeType attr_type, const std::vector<uint8_t> &value = {}) {
        attributes_.emplace_back(Attribute{attr_type, value});
    }

    // Overloaded methods for specific attributes
    void add_attribute(StunAttributeType attr_type, const std::string &value) {
        std::vector<uint8_t> data(value.begin(), value.end());
        add_attribute(attr_type, data);
    }

    void add_attribute(StunAttributeType attr_type, const uint32_t value) {
        std::vector<uint8_t> data(4);
        uint32_t network_order = htonl_custom(value);
        std::memcpy(data.data(), &network_order, 4);
        add_attribute(attr_type, data);
    }

    void add_attribute(StunAttributeType attr_type, const uint64_t value) {
        std::vector<uint8_t> data(8);
        uint64_t network_order = htonll_custom(value);
        std::memcpy(data.data(), &network_order, 8);
        add_attribute(attr_type, data);
    }

    // Add attribute (IPv4 or IPv6 endpoint)
    void add_attribute(StunAttributeType attr_type, const asio::ip::udp::endpoint &endpoint) {
        std::vector<uint8_t> data;
        if (endpoint.address().is_v4()) {
            data.resize(8);  // Family (1 byte) + Reserved (1 byte) + Port (2 bytes) + IPv4 (4 bytes)
            data[0] = 0;     // Reserved
            data[1] = 0x01;  // IPv4 family
            uint16_t port = htons_custom(endpoint.port());
            std::memcpy(&data[2], &port, sizeof(port));
            auto bytes = endpoint.address().to_v4().to_bytes();
            std::copy(bytes.begin(), bytes.end(), data.begin() + 4);
        } else if (endpoint.address().is_v6()) {
            data.resize(20);  // Family (1 byte) + Reserved (1 byte) + Port (2 bytes) + IPv6 (16 bytes)
            data[0] = 0;      // Reserved
            data[1] = 0x02;   // IPv6 family
            uint16_t port = htons_custom(endpoint.port());
            std::memcpy(&data[2], &port, sizeof(port));
            auto bytes = endpoint.address().to_v6().to_bytes();
            std::copy(bytes.begin(), bytes.end(), data.begin() + 4);
        } else {
            throw std::invalid_argument("Unsupported endpoint type");
        }
        add_attribute(attr_type, data);
    }

    void add_fingerprint() {
        // Calculate CRC32 over the entire message up to this point
        std::vector<uint8_t> data = serialize_without_specific_attributes(
            {StunAttributeType::FINGERPRINT, StunAttributeType::MESSAGE_INTEGRITY});
        uint32_t crc = CRC32::calculate(data);
        uint32_t fingerprint = crc ^ 0x5354554E;  // XOR with 0x5354554E

        // Add FINGERPRINT attribute
        add_attribute(StunAttributeType::FINGERPRINT, fingerprint);
    }

    void add_message_integrity(const std::string &key) {
        // Serialize the message up to MESSAGE-INTEGRITY attribute
        std::vector<uint8_t> data = serialize_without_specific_attributes({StunAttributeType::MESSAGE_INTEGRITY});

        // Truncate to first 20 bytes as per RFC 5389
        std::vector<uint8_t> hmac_vec = HmacSha1::calculate(key, data);
        add_attribute(StunAttributeType::MESSAGE_INTEGRITY, hmac_vec);
    }

    void add_error_code(StunErrorCode code, const std::string &reason = "") {
        // RFC 5389 Error-Code attribute structure
        // Error-Code: 32-bit value (Class: upper 3 bits, Number: lower 8 bits)
        uint16_t class_ = static_cast<uint16_t>(code) / 100;
        uint16_t number = static_cast<uint16_t>(code) % 100;

        std::vector<uint8_t> error_value(4);  // 4-byte structure: Reserved (1 byte) + Class (1 byte) + Number (1 byte)
        error_value[0] = 0;                   // Reserved
        error_value[1] = static_cast<uint8_t>(class_);
        error_value[2] = static_cast<uint8_t>(number);

        // Append the reason phrase as UTF-8 string
        std::string reason_phrase = reason.empty() ? get_error_reason(code) : reason;
        error_value.insert(error_value.end(), reason_phrase.begin(), reason_phrase.end());

        // Add padding to align to 4-byte boundary
        size_t padding = (4 - (error_value.size() % 4)) % 4;
        error_value.insert(error_value.end(), padding, 0);

        add_attribute(StunAttributeType::ERROR_CODE, error_value);
    }

    void add_response_address(const asio::ip::udp::endpoint &endpoint) {
        add_attribute(StunAttributeType::RESPONSE_ADDRESS, endpoint);
    }

    void add_change_request(bool change_ip, bool change_port) {
        uint32_t flags = 0;
        if (change_ip) {
            flags |= 0x04;  // Bit 2: Change IP
        }
        if (change_port) {
            flags |= 0x02;  // Bit 1: Change Port
        }
        add_attribute(StunAttributeType::CHANGE_REQUEST, flags);
    }

    void add_source_address(const asio::ip::udp::endpoint &endpoint) {
        add_attribute(StunAttributeType::SOURCE_ADDRESS, endpoint);
    }

    void add_change_address(const asio::ip::udp::endpoint &endpoint) {
        add_attribute(StunAttributeType::CHANGE_ADDRESS, endpoint);
    }

    std::optional<asio::ip::udp::endpoint> get_response_address() const {
        return get_attribute_as_mapped_address(StunAttributeType::RESPONSE_ADDRESS);
    }

    std::optional<std::pair<bool, bool>> get_change_request() const {
        auto val = get_attribute_as_uint32(StunAttributeType::CHANGE_REQUEST);
        if (val) {
            bool change_ip = (*val & 0x04) != 0;
            bool change_port = (*val & 0x02) != 0;
            return std::make_pair(change_ip, change_port);
        }
        return std::nullopt;  // 속성이 없는 경우
    }

    std::optional<asio::ip::udp::endpoint> get_source_address() const {
        return get_attribute_as_mapped_address(StunAttributeType::SOURCE_ADDRESS);
    }

    std::optional<asio::ip::udp::endpoint> get_change_address() const {
        return get_attribute_as_mapped_address(StunAttributeType::CHANGE_ADDRESS);
    }

    // Serialize the entire message
    std::vector<uint8_t> serialize() const { return serialize_without_specific_attributes({}); }

    // Parse a raw buffer into a StunMessage
    static StunMessage parse(const std::vector<uint8_t> &data) {
        if (data.size() < 20) {
            throw std::invalid_argument("STUN message too short");
        }

        StunMessage msg;

        // Parse header
        msg.type_ = static_cast<StunMessageType>((data[0] << 8) | data[1]);
        msg.message_length_ = (data[2] << 8) | data[3];
        uint32_t magic_cookie = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
        if (magic_cookie != STUN_MAGIC_COOKIE) {
            throw std::invalid_argument("Invalid STUN magic cookie");
        }

        // Transaction ID
        std::copy(data.begin() + 8, data.begin() + 20, msg.transaction_id_.begin());

        // Parse attributes
        size_t offset = 20;
        while (offset + 4 <= data.size() && offset < 20 + msg.message_length_) {
            uint16_t attr_type = (data[offset] << 8) | data[offset + 1];
            uint16_t attr_length = (data[offset + 2] << 8) | data[offset + 3];
            offset += 4;

            if (offset + attr_length > data.size()) {
                throw std::invalid_argument("STUN attribute length exceeds message size");
            }

            std::vector<uint8_t> attr_value(data.begin() + offset, data.begin() + offset + attr_length);
            msg.attributes_.emplace_back(Attribute{static_cast<StunAttributeType>(attr_type), attr_value});
            offset += attr_length;

            // Skip padding
            if (attr_length % 4 != 0) {
                offset += 4 - (attr_length % 4);
            }
        }

        return msg;
    }

    // Getters
    StunMessageType get_type() const { return type_; }
    const Key &get_transaction_id() const { return transaction_id_; }

    // Check if attribute exists
    bool has_attribute(StunAttributeType attr_type) const {
        return std::any_of(attributes_.begin(), attributes_.end(),
                           [&](const Attribute &attr) { return attr.type == attr_type; });
    }

    // Get attribute as string
    std::optional<std::string> get_attribute_as_string(StunAttributeType attr_type) const {
        for (const auto &attr : attributes_) {
            if (attr.type == attr_type) {
                return std::string(attr.value.begin(), attr.value.end());
            }
        }
        return std::nullopt;  // Attribute not found
    }

    // Get attribute as optional MAPPED_ADDRESS
    std::optional<asio::ip::udp::endpoint> get_attribute_as_mapped_address(StunAttributeType attr_type) const {
        for (const auto &attr : attributes_) {
            if (attr.type == attr_type) {
                if (attr.value.size() < 8) {
                    throw std::invalid_argument("MAPPED_ADDRESS attribute too short");
                }
                uint8_t family = attr.value[1];
                uint16_t port = ntohs_custom((attr.value[2] << 8) | attr.value[3]);
                if (family == 0x01) {  // IPv4
                    if (attr.value.size() < 8) {
                        throw std::invalid_argument("MAPPED_ADDRESS IPv4 attribute too short");
                    }
                    asio::ip::address_v4::bytes_type bytes;
                    std::copy(attr.value.begin() + 4, attr.value.begin() + 8, bytes.begin());
                    asio::ip::address_v4 addr(bytes);
                    return asio::ip::udp::endpoint(addr, port);
                } else if (family == 0x02) {  // IPv6
                    if (attr.value.size() < 20) {
                        throw std::invalid_argument("MAPPED_ADDRESS IPv6 attribute too short");
                    }
                    asio::ip::address_v6::bytes_type bytes;
                    std::copy(attr.value.begin() + 4, attr.value.begin() + 20, bytes.begin());
                    asio::ip::address_v6 addr(bytes);
                    return asio::ip::udp::endpoint(addr, port);
                } else {
                    throw std::invalid_argument("Unsupported address family in MAPPED_ADDRESS");
                }
            }
        }
        return std::nullopt;  // Attribute not found
    }

    // Get attribute as optional XOR-MAPPED_ADDRESS
    std::optional<asio::ip::udp::endpoint> get_attribute_as_xor_mapped_address(
        StunAttributeType attr_type, const asio::ip::udp::endpoint &request_endpoint) const {
        for (const auto &attr : attributes_) {
            if (attr.type == attr_type) {
                if (attr.value.size() < 8) {
                    throw std::invalid_argument("XOR_MAPPED_ADDRESS attribute too short");
                }
                uint8_t family = attr.value[1];
                uint16_t xport = ntohs_custom((attr.value[2] << 8) | attr.value[3]);
                uint16_t port = xport ^ (STUN_MAGIC_COOKIE >> 16);
                if (family == 0x01) {  // IPv4
                    if (attr.value.size() < 8) {
                        throw std::invalid_argument("XOR_MAPPED_ADDRESS IPv4 attribute too short");
                    }
                    std::array<uint8_t, 4> bytes;
                    for (int i = 0; i < 4; ++i) {
                        bytes[i] = attr.value[4 + i] ^ ((STUN_MAGIC_COOKIE >> (24 - 8 * i)) & 0xFF);
                    }
                    asio::ip::address_v4::bytes_type addr_bytes;
                    std::copy(bytes.begin(), bytes.end(), addr_bytes.begin());
                    asio::ip::address_v4 addr(addr_bytes);
                    return asio::ip::udp::endpoint(addr, port);
                } else if (family == 0x02) {  // IPv6
                    if (attr.value.size() < 20) {
                        throw std::invalid_argument("XOR_MAPPED_ADDRESS IPv6 attribute too short");
                    }
                    asio::ip::address_v6::bytes_type bytes;
                    for (int i = 0; i < 4; ++i) {
                        bytes[i] = attr.value[4 + i] ^ ((STUN_MAGIC_COOKIE >> (24 - 8 * i)) & 0xFF);
                    }
                    auto txn_id = get_transaction_id();
                    for (int i = 4; i < 16; ++i) {
                        bytes[i] = attr.value[4 + i] ^ txn_id[i - 4];
                    }
                    asio::ip::address_v6 addr(bytes);
                    return asio::ip::udp::endpoint(addr, port);
                } else {
                    throw std::invalid_argument("Unsupported address family in XOR_MAPPED_ADDRESS");
                }
            }
        }
        return std::nullopt;  // Attribute not found
    }

    // Get attribute as optional uint32
    std::optional<uint32_t> get_attribute_as_uint32(StunAttributeType attr_type) const {
        for (const auto &attr : attributes_) {
            if (attr.type == attr_type) {
                if (attr.value.size() < 4) {
                    throw std::invalid_argument("Attribute value too short for uint32");
                }
                uint32_t val = (attr.value[0] << 24) | (attr.value[1] << 16) | (attr.value[2] << 8) | attr.value[3];
                return ntohl_custom(val);
            }
        }
        return std::nullopt;  // Attribute not found
    }

    // Get attribute as optional uint64
    std::optional<uint64_t> get_attribute_as_uint64(StunAttributeType attr_type) const {
        for (const auto &attr : attributes_) {
            if (attr.type == attr_type) {
                if (attr.value.size() < 8) {
                    throw std::invalid_argument("Attribute value too short for uint64");
                }
                uint64_t val = 0;
                for (int i = 0; i < 8; ++i) {
                    val = (val << 8) | attr.value[i];
                }
                return ntohll_custom(val);
            }
        }
        return std::nullopt;  // Attribute not found
    }

    // Get Helpers
    std::optional<asio::ip::udp::endpoint> get_mapped_address() const {
        return get_attribute_as_mapped_address(StunAttributeType::MAPPED_ADDRESS);
    }

    std::optional<asio::ip::udp::endpoint> get_relayed_address() const {
        return get_attribute_as_mapped_address(StunAttributeType::RELAYED_ADDRESS);
    }

    std::optional<asio::ip::udp::endpoint> get_xor_mapped_address() const {
        return get_attribute_as_mapped_address(StunAttributeType::XOR_MAPPED_ADDRESS);
    }

    std::optional<std::pair<StunErrorCode, std::string>> get_error_code() const {
        // ERROR_CODE 속성을 검색
        for (const auto &attr : attributes_) {
            if (attr.type == StunAttributeType::ERROR_CODE) {
                // 속성 값의 길이가 최소 4바이트인지 확인
                if (attr.value.size() < 4) {
                    throw std::invalid_argument("ERROR-CODE attribute too short");
                }

                // Reserved (1 byte), Class (1 byte), Number (1 byte)
                uint8_t error_class = attr.value[1];
                uint8_t error_number = attr.value[2];
                uint16_t error_code = static_cast<uint16_t>(error_class) * 100 + error_number;

                // Reason Phrase (optional, UTF-8)
                std::string reason_phrase;
                if (attr.value.size() > 4) {
                    reason_phrase = std::string(attr.value.begin() + 4, attr.value.end());
                }

                return std::make_pair(static_cast<StunErrorCode>(error_code), reason_phrase);
            }
        }

        // ERROR-CODE 속성이 없는 경우 std::nullopt 반환
        return std::nullopt;
    }

    // Verify MESSAGE-INTEGRITY
    bool verify_message_integrity(const std::string &key) const {
        // Find MESSAGE-INTEGRITY attribute
        auto it = std::find_if(attributes_.begin(), attributes_.end(), [&](const Attribute &attr) {
            return attr.type == StunAttributeType::MESSAGE_INTEGRITY;
        });
        if (it == attributes_.end()) {
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
        std::vector<uint8_t> hmac_result = HmacSha1::calculate(key, data);

        // Compare with MESSAGE-INTEGRITY value (first 20 bytes of HMAC-SHA1)
        if (it->value.size() < 20) {
            return false;
        }

        return std::equal(it->value.begin(), it->value.begin() + 20, hmac_result.data());
    }

    // Verify FINGERPRINT
    bool verify_fingerprint() const {
        // Find FINGERPRINT attribute
        auto it = std::find_if(attributes_.begin(), attributes_.end(),
                               [&](const Attribute &attr) { return attr.type == StunAttributeType::FINGERPRINT; });
        if (it == attributes_.end()) {
            return false;
        }

        if (it->value.size() != 4) {
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
        uint32_t crc = CRC32::calculate(data);
        uint32_t fingerprint = crc ^ 0x5354554E;  // XOR with 0x5354554E

        // Extract fingerprint from attribute
        uint32_t recv_fingerprint = 0;
        for (int i = 0; i < 4; ++i) {
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
    Key transaction_id_;
    std::vector<Attribute> attributes_;

   private:
    void append_uint16(std::vector<uint8_t> &buffer, uint16_t value) const {
        buffer.push_back(static_cast<uint8_t>(value >> 8));
        buffer.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    // Helper method to append uint32 to buffer in network byte order
    void append_uint32(std::vector<uint8_t> &buffer, uint32_t value) const {
        buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        buffer.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    // Helper method to calculate total message length
    uint16_t calculate_message_length() const {
        uint16_t length = 0;
        for (const auto &attr : attributes_) {
            length += 4;  // Type (2 bytes) + Length (2 bytes)
            length += static_cast<uint16_t>(attr.value.size());
            // Padding to 4-byte boundary
            if (attr.value.size() % 4 != 0) {
                length += 4 - (attr.value.size() % 4);
            }
        }
        return length;
    }

    std::vector<uint8_t> serialize_without_specific_attributes(
        const std::vector<StunAttributeType> &excluded_attrs) const {
        std::vector<uint8_t> buffer;
        buffer.reserve(20 + attributes_.size() * 4);  // 예측된 크기로 예약

        // Header: Type (2 bytes), Length (2 bytes), Magic Cookie (4 bytes), Transaction ID (12 bytes)
        append_uint16(buffer, static_cast<uint16_t>(type_));
        // Calculate total message length (attributes only)
        uint16_t message_length = 0;
        for (const auto &attr : attributes_) {
            if (std::find(excluded_attrs.begin(), excluded_attrs.end(), attr.type) != excluded_attrs.end()) {
                continue;  // 제외된 속성은 직렬화하지 않음
            }
            message_length += 4;  // Type (2 bytes) + Length (2 bytes)
            message_length += static_cast<uint16_t>(attr.value.size());
            // Padding to 4-byte boundary
            if (attr.value.size() % 4 != 0) {
                message_length += 4 - (attr.value.size() % 4);
            }
        }
        append_uint16(buffer, message_length);

        // Magic Cookie
        append_uint32(buffer, STUN_MAGIC_COOKIE);

        // Transaction ID
        buffer.insert(buffer.end(), transaction_id_.data.begin(), transaction_id_.data.end());

        // Attributes
        for (const auto &attr : attributes_) {
            if (std::find(excluded_attrs.begin(), excluded_attrs.end(), attr.type) != excluded_attrs.end()) {
                continue;  // 제외된 속성은 직렬화하지 않음
            }
            append_uint16(buffer, static_cast<uint16_t>(attr.type));
            append_uint16(buffer, static_cast<uint16_t>(attr.value.size()));
            buffer.insert(buffer.end(), attr.value.begin(), attr.value.end());

            // Padding to 4-byte boundary
            if (attr.value.size() % 4 != 0) {
                buffer.insert(buffer.end(), 4 - (attr.value.size() % 4), 0);
            }
        }

        return buffer;
    }
};