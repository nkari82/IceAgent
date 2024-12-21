// include/stun_message.hpp

#ifndef STUN_MESSAGE_HPP
#define STUN_MESSAGE_HPP

#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <stdexcept>
#include <random>
#include <algorithm>
#include "hmac_sha1.hpp" // HMAC-SHA1 구현체
#include "crc32.hpp"      // CRC32 구현체

enum StunMessageType {
    STUN_BINDING_REQUEST = 0x0001,
    STUN_BINDING_RESPONSE_SUCCESS = 0x0101,
    STUN_BINDING_RESPONSE_ERROR = 0x0111,
    STUN_BINDING_INDICATION = 0x0011
    // 추가적인 STUN 메시지 타입 정의
};

// Attribute Types
enum StunAttributeType {
	STUN_ATTR_USERNAME = 0x0006;
	STUN_ATTR_PASSWORD = 0x0007;
	STUN_ATTR_MESSAGE_INTEGRITY = 0x0008;
	STUN_ATTR_FINGERPRINT = 0x8028;
	STUN_ATTR_USE_CANDIDATE = 0x000C; // 0x0011
	STUN_ATTR_PRIORITY = 0x0024;
	STUN_ATTR_ICE_CONTROLLING = 0x802A; // 0x8029
	STUN_ATTR_ICE_CONTROLLED = 0x802B;
	STUN_ATTR_MAPPED_ADDRESS = 0x0001;
}

struct StunAttribute {
    uint16_t type;
    std::vector<uint8_t> value;
};

class StunMessage {
public:
    StunMessage(StunMessageType type, const std::vector<uint8_t>& transaction_id);
    StunMessageType get_type() const;
    std::vector<uint8_t> get_transaction_id() const;
    
    void add_attribute(StunAttributeType attr, const std::string& value);
    void add_attribute(StunAttributeType attr, const std::vector<uint8_t>& value);
    void add_message_integrity(const std::string& key);
    void add_fingerprint();
    
    std::vector<uint8_t> serialize() const;
    std::vector<uint8_t> serialize_without_attributes(const std::vector<std::string>& exclude_attributes) const;
    
    static StunMessage parse(const std::vector<uint8_t>& data);
    
    bool verify_message_integrity(const std::string& key) const;
    bool verify_fingerprint() const;
    
    bool has_attribute(StunAttributeType attr) const;
    std::string get_attribute(StunAttributeType attr) const;
    
    static std::vector<uint8_t> generate_transaction_id();
    
private:
    StunMessageType type_;
    std::vector<uint8_t> transaction_id_;
    std::unordered_map<uint16_t, std::vector<uint8_t>> attributes_;
    
    // Helper methods for parsing and serialization
    void parse_attributes(const std::vector<uint8_t>& data);
    std::vector<uint8_t> calculate_fingerprint() const;
};

#endif // STUN_MESSAGE_HPP
