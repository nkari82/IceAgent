// include/stun_message.hpp

#ifndef STUN_MESSAGE_HPP
#define STUN_MESSAGE_HPP

#include <vector>
#include <cstdint>
#include <asio.hpp>
#include <stdexcept>
#include <cstring>
#include <map>
#include <string>

enum StunMessageType {
    STUN_BINDING_REQUEST = 0x0001,
    STUN_BINDING_RESPONSE_SUCCESS = 0x0101,
    STUN_BINDING_RESPONSE_ERROR = 0x0111,
    // Additional methods can be defined here
};

enum StunAttributeType {
    STUN_ATTR_MAPPED_ADDRESS = 0x0001,
    STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020,
    STUN_ATTR_MESSAGE_INTEGRITY = 0x0008,
    STUN_ATTR_FINGERPRINT = 0x8028,
    // Additional attributes can be defined here
};

struct StunAttribute {
    uint16_t type;
    std::vector<uint8_t> value;
};

class StunMessage {
public:
    StunMessage() = default;
    StunMessage(uint16_t type, const std::vector<uint8_t>& transaction_id)
        : type_(type), transaction_id_(transaction_id) {
        if (transaction_id_.size() != 12) {
            throw std::invalid_argument("Transaction ID must be 12 bytes.");
        }
    }

    // Parse raw data into StunMessage
    static StunMessage parse(const std::vector<uint8_t>& data) {
        if (data.size() < 20) {
            throw std::invalid_argument("Data too short for STUN message.");
        }

        StunMessage msg;
        msg.type_ = (data[0] << 8) | data[1];
        msg.length_ = (data[2] << 8) | data[3];
        msg.magic_cookie_ = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
        if (msg.magic_cookie_ != 0x2112A442) {
            throw std::invalid_argument("Invalid Magic Cookie.");
        }
        msg.transaction_id_.assign(data.begin() + 8, data.begin() + 20);

        size_t offset = 20;
        while (offset + 4 <= data.size()) {
            uint16_t attr_type = (data[offset] << 8) | data[offset + 1];
            uint16_t attr_length = (data[offset + 2] << 8) | data[offset + 3];
            offset += 4;

            if (offset + attr_length > data.size()) {
                throw std::invalid_argument("Attribute length exceeds message size.");
            }

            StunAttribute attr;
            attr.type = attr_type;
            attr.value.assign(data.begin() + offset, data.begin() + offset + attr_length);
            msg.attributes_.push_back(attr);
            offset += attr_length;

            // Padding to 4-byte boundary
            if (attr_length % 4 != 0) {
                offset += (4 - (attr_length % 4));
            }
        }

        return msg;
    }

    // Serialize StunMessage into raw data
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data;
        data.reserve(20 + length_);

        // Type
        data.push_back(static_cast<uint8_t>((type_ >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>(type_ & 0xFF));

        // Length (to be filled later)
        data.push_back(0x00);
        data.push_back(0x00);

        // Magic Cookie
        data.push_back(0x21);
        data.push_back(0x12);
        data.push_back(0xA4);
        data.push_back(0x42);

        // Transaction ID
        data.insert(data.end(), transaction_id_.begin(), transaction_id_.end());

        // Attributes
        std::vector<uint8_t> attrs_data;
        for (const auto& attr : attributes_) {
            attrs_data.push_back(static_cast<uint8_t>((attr.type >> 8) & 0xFF));
            attrs_data.push_back(static_cast<uint8_t>(attr.type & 0xFF));
            attrs_data.push_back(static_cast<uint8_t>((attr.value.size() >> 8) & 0xFF));
            attrs_data.push_back(static_cast<uint8_t>(attr.value.size() & 0xFF));
            attrs_data.insert(attrs_data.end(), attr.value.begin(), attr.value.end());

            // Padding
            size_t padding = (4 - (attr.value.size() % 4)) % 4;
            for (size_t i = 0; i < padding; ++i) {
                attrs_data.push_back(0x00);
            }
        }

        // Update Length
        uint16_t total_length = static_cast<uint16_t>(attrs_data.size());
        data[2] = static_cast<uint8_t>((total_length >> 8) & 0xFF);
        data[3] = static_cast<uint8_t>(total_length & 0xFF);

        // Append attributes
        data.insert(data.end(), attrs_data.begin(), attrs_data.end());

        return data;
    }

    // Add attribute
    void add_attribute(uint16_t type, const std::vector<uint8_t>& value) {
        StunAttribute attr;
        attr.type = type;
        attr.value = value;
        attributes_.push_back(attr);
        length_ += 4 + value.size() + ((value.size() % 4) ? (4 - (value.size() % 4)) : 0);
    }

    bool has_attribute(const std::string& type) const {
        return std::any_of(attributes_.begin(), attributes_.end(),
                           [&](const StunAttribute& attr) { return attr.type == type; });
    }
	
    // Getters
    uint16_t get_type() const { return type_; }
    const std::vector<uint8_t>& get_transaction_id() const { return transaction_id_; }
    const std::vector<StunAttribute>& get_attributes() const { return attributes_; }
	std::vector<uint8_t> get_attribute(const std::string& type) const {
        auto it = std::find_if(attributes_.begin(), attributes_.end(),
                               [&](const StunAttribute& attr) { return attr.type == type; });
        if (it != attributes_.end()) {
            return it->value;
        }
        return {};
    }

    // Setters
    void set_type(uint16_t type) { type_ = type; }
    void set_transaction_id(const std::vector<uint8_t>& transaction_id) { 
        if (transaction_id.size() != 12) {
            throw std::invalid_argument("Transaction ID must be 12 bytes.");
        }
        transaction_id_ = transaction_id; 
    }

private:
    uint16_t type_;
    uint16_t length_;
    uint32_t magic_cookie_;
    std::vector<uint8_t> transaction_id_;
    std::vector<StunAttribute> attributes_;
};

#endif // STUN_MESSAGE_HPP

// Inside StunMessage class (가정: StunMessage는 RFC 5389를 기반으로 구현됨)

// Inside stun_message.hpp
struct StunAttribute {
    std::string type;
    std::string value;
};

// TEST
class StunMessage {
public:
    // Existing methods...
    
    // Add ICE-specific attribute
    void add_attribute(const std::string& type, const std::string& value) {
        attributes_.emplace_back(StunAttribute{type, value});
    }
    
    // Check if attribute exists
    bool has_attribute(const std::string& type) const {
        return std::any_of(attributes_.begin(), attributes_.end(),
                           [&](const StunAttribute& attr) { return attr.type == type; });
    }
    
    // Get attribute value
    std::string get_attribute(const std::string& type) const {
        auto it = std::find_if(attributes_.begin(), attributes_.end(),
                               [&](const StunAttribute& attr) { return attr.type == type; });
        if (it != attributes_.end()) {
            return it->value;
        }
        return "";
    }

    // 기존 parse 및 serialize 메서드 수정 필요
    // 예를 들어, PRIORITY, USE-CANDIDATE, etc. 처리
private:
    // Existing members...
    std::vector<StunAttribute> attributes_;
};