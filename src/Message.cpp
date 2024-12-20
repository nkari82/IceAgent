// src/message.cpp

#include "message.hpp"
#include <stdexcept>
#include <cstring>

// Constructor with type only
Message::Message(uint16_t type)
    : type_(type), length_(0), transaction_id_(12, 0) {}

// Constructor with type and transaction ID
Message::Message(uint16_t type, const std::vector<uint8_t>& transaction_id)
    : type_(type), length_(0), transaction_id_(transaction_id) {
    if (transaction_id.size() != 12) {
        throw std::invalid_argument("Transaction ID must be 12 bytes");
    }
}

// Setters
void Message::set_type(uint16_t type) {
    type_ = type;
}

void Message::set_transaction_id(const std::vector<uint8_t>& transaction_id) {
    if (transaction_id.size() != 12) {
        throw std::invalid_argument("Transaction ID must be 12 bytes");
    }
    transaction_id_ = transaction_id;
}

// Add Attribute
void Message::add_attribute(uint16_t type, const std::vector<uint8_t>& value) {
    StunAttribute attr;
    attr.type = type;
    attr.value = value;
    attributes_.push_back(attr);
    length_ += 4 + value.size();
    // Account for padding to 4-byte boundary
    if (value.size() % 4 != 0) {
        length_ += (4 - (value.size() % 4));
    }
}

// Get Attribute
bool Message::get_attribute(uint16_t type, StunAttribute& attr) const {
    for (const auto& a : attributes_) {
        if (a.type == type) {
            attr = a;
            return true;
        }
    }
    return false;
}

// Serialize Message
std::vector<uint8_t> Message::serialize() const {
    std::vector<uint8_t> data;
    data.resize(STUN_HEADER_SIZE, 0);
    
    // Message Type
    data[0] = (type_ >> 8) & 0xFF;
    data[1] = type_ & 0xFF;
    
    // Message Length (excluding header)
    uint16_t message_length = 0;
    for (const auto& attr : attributes_) {
        message_length += 4 + attr.value.size();
        if (attr.value.size() % 4 != 0) {
            message_length += (4 - (attr.value.size() % 4));
        }
    }
    data[2] = (message_length >> 8) & 0xFF;
    data[3] = message_length & 0xFF;
    
    // Magic Cookie
    data[4] = (STUN_MAGIC_COOKIE >> 24) & 0xFF;
    data[5] = (STUN_MAGIC_COOKIE >> 16) & 0xFF;
    data[6] = (STUN_MAGIC_COOKIE >> 8) & 0xFF;
    data[7] = STUN_MAGIC_COOKIE & 0xFF;
    
    // Transaction ID
    std::memcpy(&data[8], transaction_id_.data(), 12);
    
    // Add Attributes
    for (const auto& attr : attributes_) {
        // Attribute Type
        data.push_back((attr.type >> 8) & 0xFF);
        data.push_back(attr.type & 0xFF);
        
        // Attribute Length
        data.push_back((attr.value.size() >> 8) & 0xFF);
        data.push_back(attr.value.size() & 0xFF);
        
        // Attribute Value
        data.insert(data.end(), attr.value.begin(), attr.value.end());
        
        // Padding to 4-byte boundary
        size_t padding = (4 - (attr.value.size() % 4)) % 4;
        for (size_t i = 0; i < padding; ++i) {
            data.push_back(0x00);
        }
    }
    
    return data;
}

// Parse Message from received data
std::unique_ptr<Message> Message::parse(const std::vector<uint8_t>& data, size_t length) {
    if (length < STUN_HEADER_SIZE) {
        throw std::runtime_error("STUN message too short");
    }

    uint16_t type = (data[0] << 8) | data[1];
    uint16_t msg_length = (data[2] << 8) | data[3];
    
    if (length < STUN_HEADER_SIZE + msg_length) {
        throw std::runtime_error("STUN message length mismatch");
    }

    std::vector<uint8_t> transaction_id(data.begin() + 8, data.begin() + 20);
    auto message = std::make_unique<Message>(type, transaction_id);
    
    size_t offset = STUN_HEADER_SIZE;
    while (offset + 4 <= STUN_HEADER_SIZE + msg_length) {
        uint16_t attr_type = (data[offset] << 8) | data[offset + 1];
        uint16_t attr_length = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        
        if (offset + attr_length > STUN_HEADER_SIZE + msg_length) {
            throw std::runtime_error("STUN attribute length mismatch");
        }
        
        std::vector<uint8_t> attr_value(data.begin() + offset, data.begin() + offset + attr_length);
        message->add_attribute(attr_type, attr_value);
        offset += attr_length;
        
        // Skip padding
        size_t padding = (4 - (attr_length % 4)) % 4;
        offset += padding;
    }
    
    return message;
}

// Set Username
void StunClient::set_username(const std::string& username) {
    username_ = username;
}

// Set Message Integrity (Placeholder Implementation)
void StunClient::set_message_integrity(const std::string& password) {
    password_ = password;
    // Real implementation requires HMAC-SHA1 over the message with the password as key
    // This would typically be done after the message is serialized up to the MESSAGE-INTEGRITY attribute
}

// Set Fingerprint
void StunClient::set_fingerprint() {
    // Real implementation requires CRC32 over the entire message up to the FINGERPRINT attribute
    // Here, we'll add a placeholder value (not functional)
    // Typically, you would calculate CRC32 and set it as the FINGERPRINT attribute
}

