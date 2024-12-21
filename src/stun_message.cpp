// src/stun_message.cpp

#include "stun_message.hpp"

// Constructor
StunMessage::StunMessage(StunMessageType type, const std::vector<uint8_t>& transaction_id)
    : type_(type), transaction_id_(transaction_id) {
    if (transaction_id_.size() != 12) {
        throw std::invalid_argument("Transaction ID must be 12 bytes.");
    }
}

// Getters
StunMessageType StunMessage::get_type() const {
    return type_;
}

std::vector<uint8_t> StunMessage::get_transaction_id() const {
    return transaction_id_;
}

// Add attribute (string value)
void StunMessage::add_attribute(StunAttributeType attr, const std::string& value) {
    attributes_[attr] = std::vector<uint8_t>(value.begin(), value.end());
}

// Add attribute (binary value)
void StunMessage::add_attribute(StunAttributeType attr, const std::vector<uint8_t>& value) {
    attributes_[attr] = value;
}

// Add MESSAGE-INTEGRITY attribute
void StunMessage::add_message_integrity(const std::string& key) {
    // Serialize message without MESSAGE-INTEGRITY and FINGERPRINT
    std::vector<uint8_t> serialized = serialize_without_attributes({ "MESSAGE-INTEGRITY", "FINGERPRINT" });
    std::vector<uint8_t> hmac = HmacSha1::calculate(key, serialized);
    add_attribute("MESSAGE-INTEGRITY", hmac);
}

// Add FINGERPRINT attribute
void StunMessage::add_fingerprint() {
    // Serialize message without FINGERPRINT
    std::vector<uint8_t> serialized = serialize_without_attributes({ "FINGERPRINT" });
    uint32_t crc = CRC32::calculate(serialized);
    // Convert CRC to big-endian byte order
    std::vector<uint8_t> fingerprint = {
        static_cast<uint8_t>((crc >> 24) & 0xFF),
        static_cast<uint8_t>((crc >> 16) & 0xFF),
        static_cast<uint8_t>((crc >> 8) & 0xFF),
        static_cast<uint8_t>(crc & 0xFF)
    };
    add_attribute("FINGERPRINT", fingerprint);
}

// Serialize the STUN message
std::vector<uint8_t> StunMessage::serialize() const {
    std::vector<uint8_t> data;
    // Message Type
    uint16_t type = static_cast<uint16_t>(type_);
    data.push_back((type >> 8) & 0xFF);
    data.push_back(type & 0xFF);
    // Message Length (to be calculated)
    std::vector<uint8_t> attributes_data;
    for (const auto& [attr_type, value] : attributes_) {
        // Attribute Type (simple mapping; should be expanded)
        
		switch(attr_type) {
			case STUN_ATTR_USERNAME:
			case STUN_ATTR_PASSWORD:
			case STUN_ATTR_MESSAGE_INTEGRITY:
			case STUN_ATTR_FINGERPRINT:
			case STUN_ATTR_USE_CANDIDATE:
			case STUN_ATTR_ICE_CONTROLLING: break;
			default:
				// Unknown attribute; skip or handle accordingly
				continue;
		}
        attributes_data.push_back((attr_type >> 8) & 0xFF);
        attributes_data.push_back(attr_type & 0xFF);
        // Attribute Length
        uint16_t attr_length = static_cast<uint16_t>(value.size());
        attributes_data.push_back((attr_length >> 8) & 0xFF);
        attributes_data.push_back(attr_length & 0xFF);
        // Attribute Value
        attributes_data.insert(attributes_data.end(), value.begin(), value.end());
        // Padding to 4-byte boundary
        while (attributes_data.size() % 4 != 0) {
            attributes_data.push_back(0x00);
        }
    }
    // Set Message Length
    uint16_t message_length = static_cast<uint16_t>(attributes_data.size());
    data.push_back((message_length >> 8) & 0xFF);
    data.push_back(message_length & 0xFF);
    // Transaction ID
    data.insert(data.end(), transaction_id_.begin(), transaction_id_.end());
    // Attributes
    data.insert(data.end(), attributes_data.begin(), attributes_data.end());
    return data;
}

// Serialize without certain attributes
std::vector<uint8_t> StunMessage::serialize_without_attributes(const std::vector<std::string>& exclude_attributes) const {
    std::vector<uint8_t> data;
    // Message Type
    uint16_t type = static_cast<uint16_t>(type_);
    data.push_back((type >> 8) & 0xFF);
    data.push_back(type & 0xFF);
    // Placeholder for Message Length
    data.push_back(0x00);
    data.push_back(0x00);
    // Transaction ID
    data.insert(data.end(), transaction_id_.begin(), transaction_id_.end());
    // Attributes
    std::vector<uint8_t> attributes_data;
    for (const auto& [attr_type, value] : attributes_) {
        if (std::find(exclude_attributes.begin(), exclude_attributes.end(), name) != exclude_attributes.end()) {
            continue; // Skip excluded attributes
        }
        // Attribute Type (simple mapping; should be expanded)
		switch(attr_type) {
			case STUN_ATTR_USERNAME:
			case STUN_ATTR_PASSWORD:
			case STUN_ATTR_MESSAGE_INTEGRITY:
			case STUN_ATTR_FINGERPRINT:
			case STUN_ATTR_USE_CANDIDATE:
			case STUN_ATTR_ICE_CONTROLLING: break;
			default:
				// Unknown attribute; skip or handle accordingly
				continue;
		}
		
        attributes_data.push_back((attr_type >> 8) & 0xFF);
        attributes_data.push_back(attr_type & 0xFF);
        // Attribute Length
        uint16_t attr_length = static_cast<uint16_t>(value.size());
        attributes_data.push_back((attr_length >> 8) & 0xFF);
        attributes_data.push_back(attr_length & 0xFF);
        // Attribute Value
        attributes_data.insert(attributes_data.end(), value.begin(), value.end());
        // Padding to 4-byte boundary
        while (attributes_data.size() % 4 != 0) {
            attributes_data.push_back(0x00);
        }
    }
    // Set Message Length
    uint16_t message_length = static_cast<uint16_t>(attributes_data.size());
    data[2] = (message_length >> 8) & 0xFF;
    data[3] = message_length & 0xFF;
    // Attributes
    data.insert(data.end(), attributes_data.begin(), attributes_data.end());
    return data;
}

// Parse a STUN message from raw data
StunMessage StunMessage::parse(const std::vector<uint8_t>& data) {
    if (data.size() < 20) { // Minimum STUN header size
        throw std::invalid_argument("STUN message too short.");
    }
    
    // Parse Message Type
    uint16_t type = (data[0] << 8) | data[1];
    StunMessageType msg_type;
    switch (type) {
        case STUN_BINDING_REQUEST:
            msg_type = STUN_BINDING_REQUEST;
            break;
        case STUN_BINDING_RESPONSE_SUCCESS:
            msg_type = STUN_BINDING_RESPONSE_SUCCESS;
            break;
        case STUN_BINDING_RESPONSE_ERROR:
            msg_type = STUN_BINDING_RESPONSE_ERROR;
            break;
        case STUN_BINDING_INDICATION:
            msg_type = STUN_BINDING_INDICATION;
            break;
        default:
            throw std::invalid_argument("Unsupported STUN message type.");
    }
    
    // Parse Message Length
    uint16_t length = (data[2] << 8) | data[3];
    if (data.size() < 20 + length) {
        throw std::invalid_argument("STUN message length mismatch.");
    }
    
    // Parse Transaction ID
    std::vector<uint8_t> transaction_id(data.begin() + 4, data.begin() + 16);
    
    // Create StunMessage instance
    StunMessage msg(msg_type, transaction_id);
    
    // Parse Attributes
    std::vector<uint8_t> attr_data(data.begin() + 16, data.begin() + 20 + length);
    msg.parse_attributes(attr_data);
    
    return msg;
}

// Parse attributes from raw data
void StunMessage::parse_attributes(const std::vector<uint8_t>& data) {
    size_t pos = 0;
    while (pos + 4 <= data.size()) { // At least type and length
        uint16_t attr_type = (data[pos] << 8) | data[pos + 1];
        uint16_t attr_length = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        if (pos + attr_length > data.size()) {
            throw std::invalid_argument("STUN attribute length mismatch.");
        }
        std::vector<uint8_t> value(data.begin() + pos, data.begin() + pos + attr_length);
        pos += attr_length;
        // Padding to 4-byte boundary
        while (pos % 4 != 0 && pos < data.size()) {
            pos++;
        }
        attributes_[attr_type] = value;
    }
}

// Verify MESSAGE-INTEGRITY
bool StunMessage::verify_message_integrity(const std::string& key) const {
    if (!has_attribute("MESSAGE-INTEGRITY")) {
        return false;
    }
    std::vector<uint8_t> received_hmac = attributes_.at("MESSAGE-INTEGRITY");
    
    // Serialize without MESSAGE-INTEGRITY and FINGERPRINT
    std::vector<uint8_t> serialized = serialize_without_attributes({ "MESSAGE-INTEGRITY", "FINGERPRINT" });
    
    // Calculate expected HMAC
    std::vector<uint8_t> expected_hmac = HmacSha1::calculate(key, serialized);
    
    return received_hmac == expected_hmac;
}

// Verify FINGERPRINT
bool StunMessage::verify_fingerprint() const {
    if (!has_attribute("FINGERPRINT")) {
        return false;
    }
    std::vector<uint8_t> received_crc = attributes_.at("FINGERPRINT");
    if (received_crc.size() != 4) {
        return false;
    }
    
    // Serialize without FINGERPRINT
    std::vector<uint8_t> serialized = serialize_without_attributes({ "FINGERPRINT" });
    
    // Calculate expected CRC32
    uint32_t expected_crc = CRC32::calculate(serialized);
    
    // Convert received CRC to uint32_t
    uint32_t received_crc_val = 0;
    for(int i = 0; i < 4; ++i) {
        received_crc_val = (received_crc_val << 8) | received_crc[i];
    }
    
    // FINGERPRINT는 CRC32 XOR 0x5354554E
    uint32_t calculated_crc = expected_crc ^ 0x5354554E;
    
    return received_crc_val == calculated_crc;
}

// Check if attribute exists
bool StunMessage::has_attribute(StunAttributeType attr) const {
    return attributes_.find(attr) != attributes_.end();
}

// Get attribute value as string (assuming UTF-8 or ASCII)
std::string StunMessage::get_attribute(StunAttributeType attr) const {
    if (!has_attribute(attr)) {
        return "";
    }
    return std::string(attributes_.at(attr).begin(), attributes_.at(attr).end());
}

// Generate a random transaction ID
std::vector<uint8_t> StunMessage::generate_transaction_id() {
    std::vector<uint8_t> txn_id(12);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for(auto& byte : txn_id) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    return txn_id;
}
