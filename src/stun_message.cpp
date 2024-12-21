// src/stun_message.cpp

#include "stun_message.hpp"
#include "hmac_sha1.hpp"
#include "crc32.hpp"
#include <stdexcept>
#include <cstring>
#include <arpa/inet.h> // For htons, ntohs

StunMessage::StunMessage(uint16_t type, const std::vector<uint8_t>& transaction_id)
    : type_(type), transaction_id_(transaction_id) {
    if (transaction_id_.size() != 12) {
        throw std::invalid_argument("Transaction ID must be 12 bytes.");
    }
}

StunMessage::StunMessage(uint16_t type, const std::vector<uint8_t>& transaction_id, const std::map<std::string, std::string>& attributes)
    : type_(type), transaction_id_(transaction_id) {
    for (const auto& [name, value] : attributes) {
        add_attribute(name, value);
    }
}

void StunMessage::add_attribute(const std::string& name, const std::string& value) {
    StunAttribute attr;
    if (name == "USERNAME") {
        attr.type = STUN_ATTR_USERNAME;
        attr.value.assign(value.begin(), value.end());
    }
    else if (name == "PASSWORD") {
        attr.type = STUN_ATTR_PASSWORD;
        attr.value.assign(value.begin(), value.end());
    }
    else if (name == "USE-CANDIDATE") {
        attr.type = STUN_ATTR_USE_CANDIDATE;
        attr.value = {}; // No value
    }
    else if (name == "PRIORITY") {
        attr.type = STUN_ATTR_PRIORITY;
        uint32_t priority = std::stoul(value);
        uint32_t priority_net = htonl(priority);
        uint8_t* p = reinterpret_cast<uint8_t*>(&priority_net);
        attr.value.assign(p, p + sizeof(uint32_t));
    }
    else if (name == "ICE-CONTROLLING") {
        attr.type = STUN_ATTR_ICE_CONTROLLING;
        uint32_t tie_breaker = std::stoul(value);
        uint32_t tb_net = htonl(tie_breaker);
        uint8_t* p = reinterpret_cast<uint8_t*>(&tb_net);
        attr.value.assign(p, p + sizeof(uint32_t));
    }
    else if (name == "ICE-CONTROLLED") {
        attr.type = STUN_ATTR_ICE_CONTROLLED;
        uint32_t tie_breaker = std::stoul(value);
        uint32_t tb_net = htonl(tie_breaker);
        uint8_t* p = reinterpret_cast<uint8_t*>(&tb_net);
        attr.value.assign(p, p + sizeof(uint32_t));
    }
    else {
        // Unsupported attribute
        return;
    }
    attributes_.push_back(attr);
}

void StunMessage::add_attribute(const std::string& name, const std::vector<uint8_t>& value) {
    StunAttribute attr;
    if (name == "MESSAGE-INTEGRITY") {
        attr.type = STUN_ATTR_MESSAGE_INTEGRITY;
        attr.value = value;
    }
    else if (name == "FINGERPRINT") {
        attr.type = STUN_ATTR_FINGERPRINT;
        uint32_t fingerprint = *(reinterpret_cast<const uint32_t*>(value.data()));
        uint32_t fp_net = htonl(fingerprint);
        uint8_t* p = reinterpret_cast<uint8_t*>(&fp_net);
        attr.value.assign(p, p + sizeof(uint32_t));
    }
    else if (name == "MAPPED-ADDRESS") {
        attr.type = STUN_ATTR_MAPPED_ADDRESS;
        attr.value = value;
    }
    else {
        // Unsupported attribute
        return;
    }
    attributes_.push_back(attr);
}

void StunMessage::add_attribute(const std::string& name, uint32_t value) {
    StunAttribute attr;
    if (name == "ICE-CONTROLLING" || name == "ICE-CONTROLLED" || name == "PRIORITY") {
        if (name == "ICE-CONTROLLING") {
            attr.type = STUN_ATTR_ICE_CONTROLLING;
        }
        else if (name == "ICE-CONTROLLED") {
            attr.type = STUN_ATTR_ICE_CONTROLLED;
        }
        else {
            attr.type = STUN_ATTR_PRIORITY;
        }
        uint32_t net_value = htonl(value);
        uint8_t* p = reinterpret_cast<uint8_t*>(&net_value);
        attr.value.assign(p, p + sizeof(uint32_t));
    }
    else {
        // Unsupported attribute
        return;
    }
    attributes_.push_back(attr);
}

std::vector<uint8_t> StunMessage::serialize() const {
    std::vector<uint8_t> data;

    // STUN Header
    uint16_t type_net = htons(type_);
    data.push_back((type_net >> 8) & 0xFF);
    data.push_back(type_net & 0xFF);

    // Message Length: 전체 메시지 길이 - 20 (헤더 길이)
    uint16_t message_length = 0;
    for (const auto& attr : attributes_) {
        message_length += 4 + attr.value.size(); // Type (2) + Length (2) + Value
        // Padding to 4-byte boundary
        if (attr.value.size() % 4 != 0) {
            message_length += (4 - (attr.value.size() % 4));
        }
    }
    uint16_t message_length_net = htons(message_length);
    data.push_back((message_length_net >> 8) & 0xFF);
    data.push_back(message_length_net & 0xFF);

    // Magic Cookie
    uint32_t magic_cookie = htonl(0x2112A442);
    uint8_t* mc_ptr = reinterpret_cast<uint8_t*>(&magic_cookie);
    data.insert(data.end(), mc_ptr, mc_ptr + 4);

    // Transaction ID
    data.insert(data.end(), transaction_id_.begin(), transaction_id_.end());

    // Attributes
    for (const auto& attr : attributes_) {
        uint16_t type_net = htons(attr.type);
        data.push_back((type_net >> 8) & 0xFF);
        data.push_back(type_net & 0xFF);

        uint16_t length_net = htons(static_cast<uint16_t>(attr.value.size()));
        data.push_back((length_net >> 8) & 0xFF);
        data.push_back(length_net & 0xFF);

        data.insert(data.end(), attr.value.begin(), attr.value.end());

        // Padding to 4-byte boundary
        if (attr.value.size() % 4 != 0) {
            size_t padding = 4 - (attr.value.size() % 4);
            data.insert(data.end(), padding, 0x00);
        }
    }

    return data;
}

std::vector<uint8_t> StunMessage::serialize_without_attributes(const std::vector<std::string>& exclude_attributes) const {
    std::vector<uint8_t> data;

    // STUN Header
    uint16_t type_net = htons(type_);
    data.push_back((type_net >> 8) & 0xFF);
    data.push_back(type_net & 0xFF);

    // Message Length: 전체 메시지 길이 - 20 (헤더 길이)
    uint16_t message_length = 0;
    for (const auto& attr : attributes_) {
        // Check if attribute is excluded
        bool exclude = false;
        for (const auto& ex : exclude_attributes) {
            if ((ex == "MESSAGE-INTEGRITY" && attr.type == STUN_ATTR_MESSAGE_INTEGRITY) ||
                (ex == "FINGERPRINT" && attr.type == STUN_ATTR_FINGERPRINT)) {
                exclude = true;
                break;
            }
        }
        if (exclude) continue;

        message_length += 4 + attr.value.size(); // Type (2) + Length (2) + Value
        // Padding to 4-byte boundary
        if (attr.value.size() % 4 != 0) {
            message_length += (4 - (attr.value.size() % 4));
        }
    }
    uint16_t message_length_net = htons(message_length);
    data.push_back((message_length_net >> 8) & 0xFF);
    data.push_back(message_length_net & 0xFF);

    // Magic Cookie
    uint32_t magic_cookie = htonl(0x2112A442);
    uint8_t* mc_ptr = reinterpret_cast<uint8_t*>(&magic_cookie);
    data.insert(data.end(), mc_ptr, mc_ptr + 4);

    // Transaction ID
    data.insert(data.end(), transaction_id_.begin(), transaction_id_.end());

    // Attributes
    for (const auto& attr : attributes_) {
        // Check if attribute is excluded
        bool exclude = false;
        for (const auto& ex : exclude_attributes) {
            if ((ex == "MESSAGE-INTEGRITY" && attr.type == STUN_ATTR_MESSAGE_INTEGRITY) ||
                (ex == "FINGERPRINT" && attr.type == STUN_ATTR_FINGERPRINT)) {
                exclude = true;
                break;
            }
        }
        if (exclude) continue;

        uint16_t type_net = htons(attr.type);
        data.push_back((type_net >> 8) & 0xFF);
        data.push_back(type_net & 0xFF);

        uint16_t length_net = htons(static_cast<uint16_t>(attr.value.size()));
        data.push_back((length_net >> 8) & 0xFF);
        data.push_back(length_net & 0xFF);

        data.insert(data.end(), attr.value.begin(), attr.value.end());

        // Padding to 4-byte boundary
        if (attr.value.size() % 4 != 0) {
            size_t padding = 4 - (attr.value.size() % 4);
            data.insert(data.end(), padding, 0x00);
        }
    }

    return data;
}

std::vector<uint8_t> StunMessage::serialize_without_attribute(const std::string& exclude_attribute) const {
    std::vector<std::string> excludes = { exclude_attribute };
    return serialize_without_attributes(excludes);
}

StunMessage StunMessage::parse(const std::vector<uint8_t>& data) {
    if (data.size() < STUN_HEADER_SIZE) {
        throw std::invalid_argument("STUN message too short.");
    }

    uint16_t type = ntohs(*(reinterpret_cast<const uint16_t*>(data.data())));
    uint16_t length = ntohs(*(reinterpret_cast<const uint16_t*>(data.data() + 2)));
    uint32_t magic_cookie = ntohl(*(reinterpret_cast<const uint32_t*>(data.data() + 4)));

    if (magic_cookie != 0x2112A442) {
        throw std::invalid_argument("Invalid magic cookie.");
    }

    std::vector<uint8_t> transaction_id(data.begin() + 8, data.begin() + 20);

    StunMessage msg(type, transaction_id);
    msg.parse_attributes(std::vector<uint8_t>(data.begin() + STUN_HEADER_SIZE, data.end()));

    return msg;
}

void StunMessage::parse_attributes(const std::vector<uint8_t>& data) {
    size_t offset = 0;
    while (offset + 4 <= data.size()) {
        uint16_t type = ntohs(*(reinterpret_cast<const uint16_t*>(data.data() + offset)));
        uint16_t length = ntohs(*(reinterpret_cast<const uint16_t*>(data.data() + offset + 2)));
        offset += 4;

        if (offset + length > data.size()) {
            throw std::invalid_argument("STUN attribute length mismatch.");
        }

        std::vector<uint8_t> value(data.begin() + offset, data.begin() + offset + length);
        offset += length;

        // Padding to 4-byte boundary
        if (length % 4 != 0) {
            size_t padding = 4 - (length % 4);
            offset += padding;
            if (offset > data.size()) {
                throw std::invalid_argument("STUN attribute padding exceeds data size.");
            }
        }

        StunAttribute attr;
        attr.type = type;
        attr.value = value;
        attributes_.push_back(attr);
    }
}

bool StunMessage::verify_message_integrity(const std::string& password) const {
    // Find MESSAGE-INTEGRITY attribute
    auto it = std::find_if(attributes_.begin(), attributes_.end(), [](const StunAttribute& attr) {
        return attr.type == STUN_ATTR_MESSAGE_INTEGRITY;
    });

    if (it == attributes_.end()) {
        return false;
    }

    // Serialize message without MESSAGE-INTEGRITY and FINGERPRINT
    std::vector<std::string> exclude = { "MESSAGE-INTEGRITY", "FINGERPRINT" };
    std::vector<uint8_t> serialized = serialize_without_attributes(exclude);

    // Calculate HMAC-SHA1
    std::vector<uint8_t> calculated_hmac = hmac_sha1(password, serialized);

    // Compare with received HMAC
    return calculated_hmac == it->value;
}

bool StunMessage::verify_fingerprint() const {
    // Find FINGERPRINT attribute
    auto it = std::find_if(attributes_.begin(), attributes_.end(), [](const StunAttribute& attr) {
        return attr.type == STUN_ATTR_FINGERPRINT;
    });

    if (it == attributes_.end()) {
        return false;
    }

    // Serialize message without FINGERPRINT
    std::vector<uint8_t> serialized = serialize_without_attribute("FINGERPRINT");

    // Calculate CRC32
    uint32_t calculated_crc = calculate_crc32(serialized);

    // Extract received CRC32
    if (it->value.size() != 4) {
        return false;
    }
    uint32_t received_crc = ntohl(*(reinterpret_cast<const uint32_t*>(it->value.data())));

    return calculated_crc == received_crc;
}

std::string StunMessage::get_attribute(const std::string& name) const {
    for (const auto& attr : attributes_) {
        if ((name == "USERNAME" && attr.type == STUN_ATTR_USERNAME) ||
            (name == "PASSWORD" && attr.type == STUN_ATTR_PASSWORD) ||
            (name == "ICE-CONTROLLING" && attr.type == STUN_ATTR_ICE_CONTROLLING) ||
            (name == "ICE-CONTROLLED" && attr.type == STUN_ATTR_ICE_CONTROLLED) ||
            (name == "MAPPED-ADDRESS" && attr.type == STUN_ATTR_MAPPED_ADDRESS) ||
            (name == "PRIORITY" && attr.type == STUN_ATTR_PRIORITY)) {

            if (attr.type == STUN_ATTR_PRIORITY || attr.type == STUN_ATTR_ICE_CONTROLLING || attr.type == STUN_ATTR_ICE_CONTROLLED) {
                if (attr.value.size() != 4) continue;
                uint32_t val = ntohl(*(reinterpret_cast<const uint32_t*>(attr.value.data())));
                return std::to_string(val);
            }
            else {
                return std::string(attr.value.begin(), attr.value.end());
            }
        }
    }
    return "";
}

uint16_t StunMessage::get_type() const {
    return type_;
}

std::vector<uint8_t> StunMessage::get_transaction_id() const {
    return transaction_id_;
}
