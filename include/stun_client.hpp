// include/stun_client.hpp

#ifndef STUN_CLIENT_HPP
#define STUN_CLIENT_HPP

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <string>
#include <vector>
#include <memory>
#include "stun_message.hpp"

class StunClient {
public:
    /**
     * @brief Constructs a StunClient with the specified STUN server.
     * 
     * @param io_context The ASIO io_context.
     * @param host The STUN server hostname or IP address.
     * @param port The STUN server port.
     * @param key The shared secret key for MESSAGE-INTEGRITY (optional).
     */
    StunClient(asio::io_context& io_context, const std::string& host, uint16_t port, const std::string& key = "");

    /**
     * @brief Sends a STUN Binding Request and receives the Binding Response.
     * 
     * @return asio::awaitable<asio::ip::udp::endpoint> The mapped endpoint received from the STUN server.
     */
    asio::awaitable<asio::ip::udp::endpoint> send_binding_request();

    /**
     * @brief Gets the STUN server address as a string.
     * 
     * @return std::string The STUN server address in "host:port" format.
     */
    std::string get_server() const;

private:
    asio::io_context& io_context_;
    asio::ip::udp::resolver resolver_;
    asio::ip::udp::endpoint server_endpoint_;
    asio::ip::udp::socket socket_;
    std::string key_;
};

#endif // STUN_CLIENT_HPP
