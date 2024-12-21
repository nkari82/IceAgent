// include/turn_client.hpp

#ifndef TURN_CLIENT_HPP
#define TURN_CLIENT_HPP

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <vector>
#include <string>

class TurnClient {
public:
    TurnClient(asio::io_context& io_context, const std::string& server, uint16_t port,
               const std::string& username, const std::string& password);
    ~TurnClient();

    // Allocate Relay Endpoint
    asio::awaitable<asio::ip::udp::endpoint> allocate_relay();

    // Refresh Allocation
    asio::awaitable<void> refresh_allocation();

    bool is_allocated() const { return allocated_; }

    std::string get_server() const { return server_ + ":" + std::to_string(port_); }

private:
    asio::io_context& io_context_;
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint server_endpoint_;
    std::string username_;
    std::string password_;
    bool allocated_;

    // Helper functions
    std::vector<uint8_t> generate_transaction_id();
};

#endif // TURN_CLIENT_HPP
