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

// STUN Attribute Types as per RFC5389 and RFC8445
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
    // IPv6 지원을 위한 추가 속성 타입
    ALTERNATE_SERVER = 0x8021,
    // 추가적인 STUN 속성 타입 정의
};

class StunMessage {
public:
    /**
     * @brief Constructs a STUN message with the given type and transaction ID.
     * 
     * @param type The type of the STUN message (e.g., Binding Request).
     * @param transaction_id A 12-byte transaction ID.
     */
    StunMessage(StunMessageType type, const std::vector<uint8_t>& transaction_id);

    /**
     * @brief Gets the type of the STUN message.
     * 
     * @return StunMessageType The message type.
     */
    StunMessageType get_type() const;

    /**
     * @brief Gets the transaction ID of the STUN message.
     * 
     * @return std::vector<uint8_t> The 12-byte transaction ID.
     */
    std::vector<uint8_t> get_transaction_id() const;

    /**
     * @brief Adds an attribute to the STUN message.
     * 
     * @param attr_type The attribute type as StunAttributeType.
     * @param value The attribute value as a byte vector.
     */
    void add_attribute(StunAttributeType attr_type, const std::vector<uint8_t>& value);

    /**
     * @brief Adds a string attribute to the STUN message.
     * 
     * @param attr_type The attribute type as StunAttributeType.
     * @param value The attribute value as a string.
     */
    void add_attribute(StunAttributeType attr_type, const std::string& value);

    /**
     * @brief Adds the MESSAGE-INTEGRITY attribute using the provided key.
     * 
     * @param key The shared secret key.
     */
    void add_message_integrity(const std::string& key);

    /**
     * @brief Adds the FINGERPRINT attribute.
     */
    void add_fingerprint();

    /**
     * @brief Serializes the STUN message into a byte vector.
     * 
     * @return std::vector<uint8_t> The serialized STUN message.
     */
    std::vector<uint8_t> serialize() const;

    /**
     * @brief Serializes the STUN message excluding specified attributes.
     * 
     * @param exclude_attributes A list of attribute types to exclude.
     * @return std::vector<uint8_t> The serialized STUN message.
     */
    std::vector<uint8_t> serialize_without_attributes(const std::vector<StunAttributeType>& exclude_attributes) const;

    /**
     * @brief Parses a raw byte vector into a StunMessage object.
     * 
     * @param data The raw byte data.
     * @return StunMessage The parsed STUN message.
     */
    static StunMessage parse(const std::vector<uint8_t>& data);

    /**
     * @brief Verifies the MESSAGE-INTEGRITY of the STUN message.
     * 
     * @param key The shared secret key.
     * @return true If the integrity is verified.
     * @return false Otherwise.
     */
    bool verify_message_integrity(const std::string& key) const;

    /**
     * @brief Verifies the FINGERPRINT of the STUN message.
     * 
     * @return true If the fingerprint is valid.
     * @return false Otherwise.
     */
    bool verify_fingerprint() const;

    /**
     * @brief Checks if the STUN message has a specific attribute.
     * 
     * @param attr_type The attribute type to check.
     * @return true If the attribute exists.
     * @return false Otherwise.
     */
    bool has_attribute(StunAttributeType attr_type) const;

    /**
     * @brief Gets the value of a specific attribute as a string.
     * 
     * @param attr_type The attribute type.
     * @return std::string The attribute value as a string.
     */
    std::string get_attribute_as_string(StunAttributeType attr_type) const;

    /**
     * @brief Gets the value of a specific attribute as a byte vector.
     * 
     * @param attr_type The attribute type.
     * @return std::vector<uint8_t> The attribute value as bytes.
     */
    std::vector<uint8_t> get_attribute_as_bytes(StunAttributeType attr_type) const;

    /**
     * @brief Generates a random 12-byte transaction ID.
     * 
     * @return std::vector<uint8_t> The generated transaction ID.
     */
    static std::vector<uint8_t> generate_transaction_id();
	
	asio::ip::udp::endpoint parse_xor_mapped_address(const std::vector<uint8_t>& xma) const;
	
private:
    StunMessageType type_;
    std::vector<uint8_t> transaction_id_;
    std::unordered_map<StunAttributeType, std::vector<uint8_t>> attributes_;

    /**
     * @brief Parses attributes from raw byte data.
     * 
     * @param data The raw attribute data.
     */
    void parse_attributes(const std::vector<uint8_t>& data);

    /**
     * @brief Calculates the FINGERPRINT CRC32 checksum.
     * 
     * @return uint32_t The calculated CRC32 checksum.
     */
    uint32_t calculate_fingerprint() const;
};

#endif // STUN_MESSAGE_HPP
