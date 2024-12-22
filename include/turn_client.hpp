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
    /**
     * @brief Constructs a TurnClient with the specified TURN server.
     * 
     * @param io_context The ASIO io_context.
     * @param host The TURN server hostname or IP address.
     * @param port The TURN server port.
     * @param username The TURN server username.
     * @param password The TURN server password.
     */
    TurnClient(asio::io_context& io_context, const std::string& host, uint16_t port, const std::string& username, const std::string& password);
    
    /**
     * @brief Allocates a relay endpoint from the TURN server.
     * 
     * @return asio::awaitable<asio::ip::udp::endpoint> The allocated relay endpoint.
     */
    asio::awaitable<asio::ip::udp::endpoint> allocate_relay();
    
    /**
     * @brief Refreshes the current TURN allocation.
     * 
     * @return asio::awaitable<void>
     */
    asio::awaitable<void> refresh_allocation();
    
    /**
     * @brief Checks if the TURN allocation is active.
     * 
     * @return true If allocated.
     * @return false Otherwise.
     */
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
