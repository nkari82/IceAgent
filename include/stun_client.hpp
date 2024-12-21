// include/stun_client.hpp

#ifndef STUN_CLIENT_HPP
#define STUN_CLIENT_HPP

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <vector>
#include <string>

class StunClient {
public:
    StunClient(asio::io_context& io_context, const std::string& server, uint16_t port, const std::string& key = "");
    ~StunClient();

    // Send Binding Request and receive MAPPED-ADDRESS
    asio::awaitable<asio::ip::udp::endpoint> send_binding_request();

    std::string get_server() const { return server_ + ":" + std::to_string(port_); }

private:
    asio::io_context& io_context_;
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint server_endpoint_;
    std::string key_;
};

#endif // STUN_CLIENT_HPP
