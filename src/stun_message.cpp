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

// Add attribute (byte vector value)
void StunMessage::add_attribute(StunAttributeType attr_type, const std::vector<uint8_t>& value) {
    attributes_[attr_type] = value;
}

// Add attribute (string value)
void StunMessage::add_attribute(StunAttributeType attr_type, const std::string& value) {
    std::vector<uint8_t> bytes(value.begin(), value.end());
    add_attribute(attr_type, bytes);
}

// Add MESSAGE-INTEGRITY attribute
void StunMessage::add_message_integrity(const std::string& key) {
    // Serialize without MESSAGE-INTEGRITY and FINGERPRINT
    std::vector<StunAttributeType> exclude_attrs = { StunAttributeType::MESSAGE_INTEGRITY, StunAttributeType::FINGERPRINT };
    std::vector<uint8_t> serialized = serialize_without_attributes(exclude_attrs);
    std::vector<uint8_t> hmac = HmacSha1::calculate(key, serialized);
    add_attribute(StunAttributeType::MESSAGE_INTEGRITY, hmac);
}

// Add FINGERPRINT attribute
void StunMessage::add_fingerprint() {
    // Calculate fingerprint based on the message without FINGERPRINT
    std::vector<StunAttributeType> exclude_attrs = { StunAttributeType::FINGERPRINT };
    std::vector<uint8_t> serialized = serialize_without_attributes(exclude_attrs);
    uint32_t crc = CRC32::calculate(serialized) ^ 0x5354554E;
    // Convert CRC to big-endian byte order
    std::vector<uint8_t> fingerprint = {
        static_cast<uint8_t>((crc >> 24) & 0xFF),
        static_cast<uint8_t>((crc >> 16) & 0xFF),
        static_cast<uint8_t>((crc >> 8) & 0xFF),
        static_cast<uint8_t>(crc & 0xFF)
    };
    add_attribute(StunAttributeType::FINGERPRINT, fingerprint);
}

// Serialize the STUN message
std::vector<uint8_t> StunMessage::serialize() const {
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
        // Attribute Type
        uint16_t type = static_cast<uint16_t>(attr_type);
        attributes_data.push_back((type >> 8) & 0xFF);
        attributes_data.push_back(type & 0xFF);
        // Attribute Length
        uint16_t length = static_cast<uint16_t>(value.size());
        attributes_data.push_back((length >> 8) & 0xFF);
        attributes_data.push_back(length & 0xFF);
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
    // Append Attributes
    data.insert(data.end(), attributes_data.begin(), attributes_data.end());
    return data;
}

// Serialize without certain attributes
std::vector<uint8_t> StunMessage::serialize_without_attributes(const std::vector<StunAttributeType>& exclude_attributes) const {
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
        if (std::find(exclude_attributes.begin(), exclude_attributes.end(), attr_type) != exclude_attributes.end()) {
            continue; // Skip excluded attributes
        }
        // Attribute Type
        uint16_t type = static_cast<uint16_t>(attr_type);
        attributes_data.push_back((type >> 8) & 0xFF);
        attributes_data.push_back(type & 0xFF);
        // Attribute Length
        uint16_t length = static_cast<uint16_t>(value.size());
        attributes_data.push_back((length >> 8) & 0xFF);
        attributes_data.push_back(length & 0xFF);
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
    // Append Attributes
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
        case static_cast<uint16_t>(StunMessageType::BINDING_REQUEST):
            msg_type = StunMessageType::BINDING_REQUEST;
            break;
        case static_cast<uint16_t>(StunMessageType::BINDING_RESPONSE_SUCCESS):
            msg_type = StunMessageType::BINDING_RESPONSE_SUCCESS;
            break;
        case static_cast<uint16_t>(StunMessageType::BINDING_RESPONSE_ERROR):
            msg_type = StunMessageType::BINDING_RESPONSE_ERROR;
            break;
        case static_cast<uint16_t>(StunMessageType::BINDING_INDICATION):
            msg_type = StunMessageType::BINDING_INDICATION;
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
        // Map attribute type to enum
        StunAttributeType stype;
        switch (attr_type) {
            case 0x0001:
                stype = StunAttributeType::MAPPED_ADDRESS;
                break;
            case 0x0020:
                stype = StunAttributeType::XOR_MAPPED_ADDRESS;
                break;
            case 0x0006:
                stype = StunAttributeType::USERNAME;
                break;
            case 0x0008:
                stype = StunAttributeType::MESSAGE_INTEGRITY;
                break;
            case 0x8028:
                stype = StunAttributeType::FINGERPRINT;
                break;
            case 0x0011:
                stype = StunAttributeType::USE_CANDIDATE;
                break;
            case 0x8029:
                stype = StunAttributeType::ICE_CONTROLLING;
                break;
            case 0x0021:
                stype = StunAttributeType::RELAYED_ADDRESS;
                break;
            // 추가적인 속성 타입 처리
            default:
                stype = StunAttributeType::UNKNOWN;
                break;
        }
        if (stype != StunAttributeType::UNKNOWN) {
            attributes_[stype] = value;
        }
        // Unknown attributes can be handled or ignored as needed
    }
}

// Verify MESSAGE-INTEGRITY
bool StunMessage::verify_message_integrity(const std::string& key) const {
    if (!has_attribute(StunAttributeType::MESSAGE_INTEGRITY)) {
        return false;
    }
    std::vector<uint8_t> received_hmac = attributes_.at(StunAttributeType::MESSAGE_INTEGRITY);
    
    // Serialize without MESSAGE-INTEGRITY and FINGERPRINT
    std::vector<StunAttributeType> exclude_attrs = { StunAttributeType::MESSAGE_INTEGRITY, StunAttributeType::FINGERPRINT };
    std::vector<uint8_t> serialized = serialize_without_attributes(exclude_attrs);
    
    // Calculate expected HMAC
    std::vector<uint8_t> expected_hmac = HmacSha1::calculate(key, serialized);
    
    return received_hmac == expected_hmac;
}

// Verify FINGERPRINT
bool StunMessage::verify_fingerprint() const {
    if (!has_attribute(StunAttributeType::FINGERPRINT)) {
        return false;
    }
    std::vector<uint8_t> received_crc = attributes_.at(StunAttributeType::FINGERPRINT);
    if (received_crc.size() != 4) {
        return false;
    }
    
    // Serialize without FINGERPRINT
    std::vector<StunAttributeType> exclude_attrs = { StunAttributeType::FINGERPRINT };
    std::vector<uint8_t> serialized = serialize_without_attributes(exclude_attrs);
    
    // Calculate expected CRC32
    uint32_t expected_crc = CRC32::calculate(serialized) ^ 0x5354554E;
    
    // Convert received CRC to uint32_t
    uint32_t received_crc_val = 0;
    for(int i = 0; i < 4; ++i) {
        received_crc_val = (received_crc_val << 8) | received_crc[i];
    }
    
    return received_crc_val == expected_crc;
}

// Check if attribute exists
bool StunMessage::has_attribute(StunAttributeType attr_type) const {
    return attributes_.find(attr_type) != attributes_.end();
}

// Get attribute value as string
std::string StunMessage::get_attribute_as_string(StunAttributeType attr_type) const {
    if (!has_attribute(attr_type)) {
        return "";
    }
    return std::string(attributes_.at(attr_type).begin(), attributes_.at(attr_type).end());
}

// Get attribute value as byte vector
std::vector<uint8_t> StunMessage::get_attribute_as_bytes(StunAttributeType attr_type) const {
    if (!has_attribute(attr_type)) {
        return {};
    }
    return attributes_.at(attr_type);
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

// Calculate FINGERPRINT CRC32
uint32_t StunMessage::calculate_fingerprint() const {
    // Serialize without FINGERPRINT
    std::vector<StunAttributeType> exclude_attrs = { StunAttributeType::FINGERPRINT };
    std::vector<uint8_t> serialized = serialize_without_attributes(exclude_attrs);
    // Calculate CRC32 and XOR with 0x5354554E
    return CRC32::calculate(serialized) ^ 0x5354554E;
}

// Parse XOR-MAPPED-ADDRESS with IPv6 support
asio::ip::udp::endpoint StunMessage::parse_xor_mapped_address(const std::vector<uint8_t>& xma) const {
	if (xma.size() < 8) { // 최소 XOR-MAPPED-ADDRESS 크기
		throw std::invalid_argument("Invalid XOR-MAPPED-ADDRESS attribute size.");
	}
	if (xma.size() < 20 && xma[1] == 0x02) { // IPv6 크기 검증
		throw std::invalid_argument("Invalid XOR-MAPPED-ADDRESS attribute size for IPv6.");
	}

	uint8_t family = xma[1];
	uint16_t x_port = (xma[2] << 8) | xma[3];
	uint16_t port_unxored = x_port ^ (static_cast<uint16_t>((transaction_id_[2] << 8) | transaction_id_[3]));

	uint8_t xor_magic_cookie[4] = {0x21, 0x12, 0xA4, 0x42};
	uint8_t x_address[16] = {0};
	if (xma.size() >= 8) {
		std::copy(xma.begin() + 4, xma.begin() + std::min<size_t>(xma.size(), 20), x_address);
	}

	if (family == 0x01) { // IPv4
		uint8_t addr_bytes[4];
		for (int i = 0; i < 4; ++i) {
			addr_bytes[i] = x_address[i] ^ xor_magic_cookie[i];
		}

		asio::ip::address_v4::bytes_type ipv4_bytes;
		std::copy(addr_bytes, addr_bytes + 4, ipv4_bytes.begin());
		asio::ip::address_v4 addr(ipv4_bytes);
		asio::ip::udp::endpoint endpoint(addr, port_unxored);
		return endpoint;
	} else if (family == 0x02) { // IPv6
		std::vector<uint8_t> cookie_and_txnid;
		cookie_and_txnid.insert(cookie_and_txnid.end(), xor_magic_cookie, xor_magic_cookie + 4);
		cookie_and_txnid.insert(cookie_and_txnid.end(), transaction_id_.begin(), transaction_id_.end());

		std::vector<uint8_t> addr_bytes(16);
		for (int i = 0; i < 16; ++i) {
			addr_bytes[i] = x_address[i] ^ cookie_and_txnid[i % 16];
		}

		asio::ip::address_v6::bytes_type ipv6_bytes;
		std::copy(addr_bytes.begin(), addr_bytes.end(), ipv6_bytes.begin());
		asio::ip::address_v6 addr(ipv6_bytes);
		asio::ip::udp::endpoint endpoint(addr, port_unxored);
		return endpoint;
	} else {
		throw std::runtime_error("Unknown address family in XOR-MAPPED-ADDRESS.");
	}
}