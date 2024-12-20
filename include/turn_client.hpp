// include/turn_client.hpp

#ifndef TURN_CLIENT_HPP
#define TURN_CLIENT_HPP

#include <asio.hpp>
#include <vector>
#include <memory>
#include <string>
#include "message.hpp" // Assuming TURN messages are similar to STUN messages

// TURN-related constants
constexpr uint16_t TURN_ALLOCATE = 0x0003;
constexpr uint16_t TURN_SUCCESS_RESPONSE = 0x0103;
constexpr uint16_t TURN_ERROR_RESPONSE = 0x0113;
constexpr uint16_t TURN_ATTR_XOR_RELAYED_ADDRESS = 0x0016;
constexpr uint32_t TURN_MAGIC_COOKIE = 0x2112A442;

class TurnClient {
public:
    // Constructor with TURN server information and optional credentials
    TurnClient(asio::io_context& io_context, const std::string& turn_server, const std::string& username = "", const std::string& password = "");

    // Allocate a relay address
    awaitable<asio::ip::udp::endpoint> allocate_relay();

    // Send data through the relay
    awaitable<void> send_data(const std::vector<uint8_t>& data, const asio::ip::udp::endpoint& relay_endpoint);

    // Receive data from the relay
    awaitable<std::pair<std::vector<uint8_t>, asio::ip::udp::endpoint>> receive_data();

    // Close the relay allocation
    void close();

    // Get TURN server identifier
    std::string get_server() const { return turn_server_; }

private:
    asio::io_context& io_context_;
    asio::ip::udp::socket socket_;
    std::string turn_server_;
    std::string username_;
    std::string password_;
    asio::ip::udp::endpoint relay_endpoint_;
    bool allocated_ = false;

    // Helper methods
    awaitable<void> send_allocate_request();
    awaitable<asio::ip::udp::endpoint> receive_allocate_response();
    void authenticate_message(Message& message);
};

#endif // TURN_CLIENT_HPP
