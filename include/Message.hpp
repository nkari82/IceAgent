// include/message.hpp

#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include <vector>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <memory>
#include <nlohmann/json.hpp>

// STUN Message Types
constexpr uint16_t STUN_BINDING_REQUEST = 0x0001;
constexpr uint16_t STUN_BINDING_RESPONSE_SUCCESS = 0x0101;
constexpr uint16_t STUN_BINDING_RESPONSE_ERROR = 0x0111;

// STUN Magic Cookie
constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// STUN Attribute Types
constexpr uint16_t STUN_ATTR_MAPPED_ADDRESS = 0x0001;
constexpr uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;
constexpr uint16_t STUN_ATTR_USERNAME = 0x0006;
constexpr uint16_t STUN_ATTR_MESSAGE_INTEGRITY = 0x0008;
constexpr uint16_t STUN_ATTR_FINGERPRINT = 0x8028;

// STUN Attribute Structure
struct StunAttribute {
    uint16_t type;
    std::vector<uint8_t> value;
};

// STUN Message Class
class Message {
public:
    Message(uint16_t type);
    Message(uint16_t type, const std::vector<uint8_t>& transaction_id);
    
    // Setters
    void set_type(uint16_t type);
    void set_transaction_id(const std::vector<uint8_t>& transaction_id);
    
    // Attribute Management
    void add_attribute(uint16_t type, const std::vector<uint8_t>& value);
    bool get_attribute(uint16_t type, StunAttribute& attr) const;
    
    // Serialization
    std::vector<uint8_t> serialize() const;
    
    // Parsing
    static std::unique_ptr<Message> parse(const std::vector<uint8_t>& data, size_t length);
    
    // Getters
    uint16_t get_type() const;
    std::vector<uint8_t> get_transaction_id() const;
    const std::vector<StunAttribute>& get_attributes() const;
    
private:
    uint16_t type_;
    uint16_t length_;
    std::vector<uint8_t> transaction_id_;
    std::vector<StunAttribute> attributes_;
    
    // Helper functions
    static void add_padding(std::vector<uint8_t>& data, size_t current_length);
};

#endif // MESSAGE_HPP
