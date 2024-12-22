// include/stun_message.hpp

#ifndef STUN_MESSAGE_HPP
#define STUN_MESSAGE_HPP

#include <vector>
#include <cstdint>
#include <stdexcept>
#include <random>
#include <unordered_map>
#include <cstring>
#include "hmac_sha1.hpp" // HMAC-SHA1 구현체
#include "crc32.hpp"      // CRC32 구현체

enum class StunMessageType : uint16_t {
    BINDING_REQUEST = 0x0001,
    BINDING_RESPONSE_SUCCESS = 0x0101,
    BINDING_RESPONSE_ERROR = 0x0111,
    BINDING_INDICATION = 0x0011
    // 추가적인 STUN 메시지 타입 정의
};

enum class StunAttributeType : uint16_t {
    UNKNOWN = 0xFFFF,
    USERNAME = 0x0006,
    MESSAGE_INTEGRITY = 0x0008,
    FINGERPRINT = 0x8028,
    USE_CANDIDATE = 0x0011,
    ICE_CONTROLLING = 0x8029,
    RELAYED_ADDRESS = 0x0021,
    MAPPED_ADDRESS = 0x0001,
    XOR_MAPPED_ADDRESS = 0x0020,
    ALTERNATE_SERVER = 0x8021,
    PRIORITY = 0x0024, // 추가됨
    ICE_CONTROLLED = 0x802A // 추가됨
    // 추가적인 STUN 속성 타입 정의
};

// 예시: PRIORITY 속성 추가
// binding_request.add_attribute(StunAttributeType::PRIORITY, serialize_uint32(pair.local_candidate.priority));
// binding_request.add_attribute(StunAttributeType::USERNAME, ice_attributes_.username_fragment);

class StunMessage {
public:
    StunMessage(StunMessageType type, const std::vector<uint8_t>& transaction_id);

    StunMessageType get_type() const;

    std::vector<uint8_t> get_transaction_id() const;

    void add_attribute(StunAttributeType attr_type, const std::vector<uint8_t>& value);

    void add_attribute(StunAttributeType attr_type, const std::string& value);

    void add_message_integrity(const std::string& key);

    void add_fingerprint();

    std::vector<uint8_t> serialize() const;

    std::vector<uint8_t> serialize_without_attributes(const std::vector<StunAttributeType>& exclude_attributes) const;

    static StunMessage parse(const std::vector<uint8_t>& data);

    bool verify_message_integrity(const std::string& key) const;

    bool verify_fingerprint() const;

    bool has_attribute(StunAttributeType attr_type) const;

    std::string get_attribute_as_string(StunAttributeType attr_type) const;

    std::vector<uint8_t> get_attribute_as_bytes(StunAttributeType attr_type) const;

    static std::vector<uint8_t> generate_transaction_id();
	
	asio::ip::udp::endpoint parse_xor_mapped_address(const std::vector<uint8_t>& xma) const;
	
private:
    StunMessageType type_;
    std::vector<uint8_t> transaction_id_;
    std::unordered_map<StunAttributeType, std::vector<uint8_t>> attributes_;

    void parse_attributes(const std::vector<uint8_t>& data);

    uint32_t calculate_fingerprint() const;
};

#endif // STUN_MESSAGE_HPP
