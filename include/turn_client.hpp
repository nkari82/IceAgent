// include/turn_client.hpp

#ifndef TURN_CLIENT_HPP
#define TURN_CLIENT_HPP

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <string>
#include <vector>
#include "stun_message.hpp"

class TurnClient {
public:
    TurnClient(asio::io_context& io_context, const std::string& host, uint16_t port, const std::string& username, const std::string& password);
    
	asio::awaitable<void> connect();
	
    asio::awaitable<asio::ip::udp::endpoint> allocate_relay();
    
    asio::awaitable<void> refresh_allocation();
    
    bool is_allocated() const;

private:
    asio::io_context& io_context_;
    asio::ip::udp::resolver resolver_;
    asio::ip::udp::endpoint turn_endpoint_;
    asio::ip::udp::socket socket_;
    std::string username_;
    std::string password_;
    bool allocated_;
    
    // Helper method to create TURN Allocate Request
    StunMessage create_allocate_request() const;
    
    // Helper method to create TURN Refresh Request
    StunMessage create_refresh_request() const;
};

#endif // TURN_CLIENT_HPP
