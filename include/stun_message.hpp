// include/stun_message.hpp

#ifndef STUN_MESSAGE_HPP
#define STUN_MESSAGE_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <map>

// STUN 메시지 기본 헤더 크기
constexpr size_t STUN_HEADER_SIZE = 20;

// STUN 메시지 타입
constexpr uint16_t STUN_BINDING_REQUEST = 0x0001;
constexpr uint16_t STUN_BINDING_RESPONSE_SUCCESS = 0x0101;
constexpr uint16_t STUN_BINDING_INDICATION = 0x0111;

// Attribute Types
constexpr uint16_t STUN_ATTR_USERNAME = 0x0006;
constexpr uint16_t STUN_ATTR_PASSWORD = 0x0007;
constexpr uint16_t STUN_ATTR_MESSAGE_INTEGRITY = 0x0008;
constexpr uint16_t STUN_ATTR_FINGERPRINT = 0x8028;
constexpr uint16_t STUN_ATTR_USE_CANDIDATE = 0x000C;
constexpr uint16_t STUN_ATTR_PRIORITY = 0x0024;
constexpr uint16_t STUN_ATTR_ICE_CONTROLLING = 0x802A;
constexpr uint16_t STUN_ATTR_ICE_CONTROLLED = 0x802B;
constexpr uint16_t STUN_ATTR_MAPPED_ADDRESS = 0x0001;

struct StunAttribute {
    uint16_t type;
    std::vector<uint8_t> value;
};

class StunMessage {
public:
    StunMessage(uint16_t type, const std::vector<uint8_t>& transaction_id);
    StunMessage(uint16_t type, const std::vector<uint8_t>& transaction_id, const std::map<std::string, std::string>& attributes);

    void add_attribute(const std::string& name, const std::string& value);
    void add_attribute(const std::string& name, const std::vector<uint8_t>& value);
    void add_attribute(const std::string& name, uint32_t value);

    std::vector<uint8_t> serialize() const;
    std::vector<uint8_t> serialize_without_attributes(const std::vector<std::string>& exclude_attributes) const;
    std::vector<uint8_t> serialize_without_attribute(const std::string& exclude_attribute) const;

    static StunMessage parse(const std::vector<uint8_t>& data);

    bool verify_message_integrity(const std::string& password) const;
    bool verify_fingerprint() const;

    std::string get_attribute(const std::string& name) const;
    uint16_t get_type() const;
    std::vector<uint8_t> get_transaction_id() const;

private:
    uint16_t type_;
    std::vector<uint8_t> transaction_id_;
    std::vector<StunAttribute> attributes_;

    // Helper functions
    void parse_attributes(const std::vector<uint8_t>& data);
};

#endif // STUN_MESSAGE_HPP
