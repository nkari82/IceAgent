// include/dtls_session.hpp

#ifndef DTLS_SESSION_HPP
#define DTLS_SESSION_HPP

#include <asio.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <memory>
#include <functional>
#include <vector>

class DtlsSession : public std::enable_shared_from_this<DtlsSession> {
public:
    using DataHandler = std::function<void(const std::vector<uint8_t>&, const asio::ip::udp::endpoint&)>;

    DtlsSession(asio::io_context& io_context, SSL_CTX* ssl_ctx, asio::ip::udp::socket& socket);
    ~DtlsSession();

    void start();
    void send_data(const std::vector<uint8_t>& data, const asio::ip::udp::endpoint& endpoint);
    void set_data_handler(DataHandler handler);

private:
    void do_receive();
    void handle_receive(const asio::error_code& ec, std::size_t bytes_transferred);
    void do_send(const std::vector<uint8_t>& data, const asio::ip::udp::endpoint& endpoint);
    void handle_send(const asio::error_code& ec, std::size_t bytes_transferred);

    asio::io_context& io_context_;
    SSL_CTX* ssl_ctx_;
    SSL* ssl_;
    asio::ip::udp::socket& socket_;
    asio::ip::udp::endpoint remote_endpoint_;
    std::array<uint8_t, 1500> recv_buffer_;
    DataHandler data_handler_;
};

#endif // DTLS_SESSION_HPP
