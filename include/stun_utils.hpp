// include/stun_utils.hpp

#ifndef STUN_UTILS_HPP
#define STUN_UTILS_HPP

#include "stun_message.hpp"
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cstring>
#include <stdexcept>

namespace StunUtils {

// Calculate HMAC-SHA1 for MESSAGE-INTEGRITY
std::vector<uint8_t> calculate_message_integrity(const StunMessage& msg, const std::string& key) {
    std::vector<uint8_t> serialized = msg.serialize();
    // Append key
    std::vector<uint8_t> data(serialized.begin(), serialized.end());
    data.insert(data.end(), key.begin(), key.end());

    unsigned char* result;
    unsigned int len = SHA_DIGEST_LENGTH;
    std::vector<uint8_t> hmac_result(SHA_DIGEST_LENGTH);

    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create HMAC_CTX.");

    HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha1(), NULL);
    HMAC_Update(ctx, serialized.data(), serialized.size());
    HMAC_Final(ctx, hmac_result.data(), &len);
    HMAC_CTX_free(ctx);

    return hmac_result;
}

// Calculate FINGERPRINT
uint32_t calculate_fingerprint(const StunMessage& msg) {
    std::vector<uint8_t> serialized = msg.serialize();
    uint32_t crc = 0;

    // Exclude the last 4 bytes if FINGERPRINT is already present
    size_t len = serialized.size();
    if (len >= 4) {
        len -= 4;
    }

    for (size_t i = 0; i < len; ++i) {
        crc ^= (static_cast<uint32_t>(serialized[i]) << 24);
        for (int j = 0; j < 8; ++j) {
            if (crc & 0x80000000) {
                crc = (crc << 1) ^ 0x04C11DB7;
            } else {
                crc <<= 1;
            }
        }
    }

    return crc;
}

// Construct XOR-MAPPED-ADDRESS attribute
std::vector<uint8_t> construct_xor_mapped_address(const asio::ip::udp::endpoint& endpoint) {
    std::vector<uint8_t> addr;
    addr.push_back(0x00); // Reserved
    addr.push_back(0x01); // IPv4
    uint16_t xport = endpoint.port() ^ ((0x2112A442 >> 16) & 0xFFFF);
    addr.push_back(static_cast<uint8_t>((xport >> 8) & 0xFF));
    addr.push_back(static_cast<uint8_t>(xport & 0xFF));

    uint32_t xaddr = endpoint.address().to_v4().to_uint() ^ 0x2112A442;
    addr.push_back(static_cast<uint8_t>((xaddr >> 24) & 0xFF));
    addr.push_back(static_cast<uint8_t>((xaddr >> 16) & 0xFF));
    addr.push_back(static_cast<uint8_t>((xaddr >> 8) & 0xFF));
    addr.push_back(static_cast<uint8_t>(xaddr & 0xFF));

    return addr;
}

} // namespace StunUtils

#endif // STUN_UTILS_HPP
