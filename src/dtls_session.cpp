// src/dtls_session.cpp

#include "dtls_session.hpp"
#include <iostream>

DtlsSession::DtlsSession(asio::io_context& io_context, SSL_CTX* ssl_ctx, asio::ip::udp::socket& socket)
    : io_context_(io_context), ssl_ctx_(ssl_ctx), socket_(socket), ssl_(nullptr) {
    ssl_ = SSL_new(ssl_ctx_);
    SSL_set_options(ssl_, SSL_OP_NO_QUERY_MTU | SSL_OP_COOKIE_EXCHANGE);
    // 설정 필요: DTLS를 위한 BIO 설정 등
}

DtlsSession::~DtlsSession() {
    if (ssl_) {
        SSL_free(ssl_);
    }
}

void DtlsSession::set_data_handler(DataHandler handler) {
    data_handler_ = handler;
}

void DtlsSession::start() {
    do_receive();
}

void DtlsSession::do_receive() {
    auto self = shared_from_this();
    socket_.async_receive_from(asio::buffer(recv_buffer_), remote_endpoint_,
        [this, self](const asio::error_code& ec, std::size_t bytes_transferred) {
            handle_receive(ec, bytes_transferred);
        });
}

void DtlsSession::handle_receive(const asio::error_code& ec, std::size_t bytes_transferred) {
    if (!ec && bytes_transferred > 0) {
        // DTLS 데이터 처리
        // SSL_read 등의 OpenSSL 함수 사용 필요
        // 여기서는 단순히 데이터를 전달
        std::vector<uint8_t> data(recv_buffer_.begin(), recv_buffer_.begin() + bytes_transferred);
        if (data_handler_) {
            data_handler_(data, remote_endpoint_);
        }
    } else {
        std::cerr << "DTLS receive error: " << ec.message() << std::endl;
    }
    do_receive();
}

void DtlsSession::send_data(const std::vector<uint8_t>& data, const asio::ip::udp::endpoint& endpoint) {
    do_send(data, endpoint);
}

void DtlsSession::do_send(const std::vector<uint8_t>& data, const asio::ip::udp::endpoint& endpoint) {
    auto self = shared_from_this();
    socket_.async_send_to(asio::buffer(data), endpoint,
        [this, self](const asio::error_code& ec, std::size_t bytes_transferred) {
            handle_send(ec, bytes_transferred);
        });
}

void DtlsSession::handle_send(const asio::error_code& ec, std::size_t /*bytes_transferred*/) {
    if (ec) {
        std::cerr << "DTLS send error: " << ec.message() << std::endl;
    }
}
