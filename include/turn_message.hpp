// include/turn_message.hpp

#ifndef TURN_MESSAGE_HPP
#define TURN_MESSAGE_HPP

#include "stun_message.hpp"

enum TurnMessageType {
    TURN_ALLOCATE = 0x0003,
    TURN_ALLOCATE_RESPONSE_SUCCESS = 0x0103,
    TURN_ALLOCATE_RESPONSE_ERROR = 0x0113,
    TURN_REFRESH = 0x0004,
    TURN_REFRESH_RESPONSE_SUCCESS = 0x0104,
    TURN_REFRESH_RESPONSE_ERROR = 0x0114,
    TURN_SEND = 0x0006,
    TURN_SEND_INDICATION = 0x0016,
    TURN_DATA = 0x0106,
    // Additional TURN methods can be defined here
};

enum TurnAttributeType {
    TURN_ATTR_XOR_RELAYED_ADDRESS = 0x0016,
    TURN_ATTR_XOR_PEER_ADDRESS = 0x0012,
    TURN_ATTR_DATA = 0x0013,
    // Additional TURN attributes can be defined here
};

class TurnMessage : public StunMessage {
public:
    TurnMessage() = default;
    TurnMessage(uint16_t type, const std::vector<uint8_t>& transaction_id)
        : StunMessage(type, transaction_id) {}
    
    // Additional TURN-specific methods can be implemented here
};

#endif // TURN_MESSAGE_HPP
