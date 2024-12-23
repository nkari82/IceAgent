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
    StunClient(asio::io_context& io_context, const std::string& host, uint16_t port, const std::string& key = "");

    asio::awaitable<asio::ip::udp::endpoint> send_binding_request();

    std::string get_server() const;

private:
    asio::strand<asio::io_context::executor_type> strand_;
    asio::ip::udp::resolver resolver_;
    asio::ip::udp::endpoint server_endpoint_;
    asio::ip::udp::socket socket_;
    std::string key_;
};

#endif // STUN_CLIENT_HPP
