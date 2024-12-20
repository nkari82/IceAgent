// include/turn_utils.hpp

#ifndef TURN_UTILS_HPP
#define TURN_UTILS_HPP

#include "turn_message.hpp"
#include "crypt.hpp"
#include "stun_utils.hpp"
#include <asio.hpp>
#include <stdexcept>
#include <vector>

namespace TurnUtils {

// Calculate HMAC-SHA1 for MESSAGE-INTEGRITY
std::vector<uint8_t> calculate_message_integrity(const Turn::TurnMessage& msg, const std::string& key) {
    std::vector<uint8_t> serialized = msg.serialize();
    // Calculate HMAC-SHA1 over the serialized message
    return Crypt::hmac_sha1(key, serialized);
}

// Construct XOR-RELAYED-ADDRESS attribute
std::vector<uint8_t> construct_xor_relayed_address(const asio::ip::udp::endpoint& endpoint) {
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

} // namespace TurnUtils

#endif // TURN_UTILS_HPP
