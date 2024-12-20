// include/stun_client.hpp

#ifndef STUN_CLIENT_HPP
#define STUN_CLIENT_HPP

#include <asio.hpp>
#include <vector>
#include <array>
#include <functional>
#include <cstdint>
#include <memory>
#include <random>
#include <stdexcept>
#include "message.hpp" // Message 클래스 포함

// STUN Message Types
constexpr uint16_t STUN_BINDING_REQUEST = 0x0001;
constexpr uint16_t STUN_BINDING_RESPONSE_SUCCESS = 0x0101;
constexpr uint16_t STUN_BINDING_RESPONSE_ERROR = 0x0111;

// STUN Magic Cookie
constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// STUN Attribute Types
constexpr uint16_t STUN_ATTR_MAPPED_ADDRESS = 0x0001;
constexpr uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;
constexpr uint16_t STUN_ATTR_USERNAME = 0x0006;
constexpr uint16_t STUN_ATTR_MESSAGE_INTEGRITY = 0x0008;
constexpr uint16_t STUN_ATTR_FINGERPRINT = 0x8028;

// STUN Attribute Lengths
constexpr size_t STUN_HEADER_SIZE = 20;

// STUN Client Class
class StunClient : public std::enable_shared_from_this<StunClient> {
public:
    using Endpoint = asio::ip::udp::endpoint;
    using MappedEndpointCallback = std::function<void(const Endpoint&, const std::string&)>;

    // 생성자
    StunClient(asio::io_context& io_context);
    
    // STUN Binding Request 전송 및 응답 대기
    awaitable<void> send_binding_request(const Endpoint& stun_server, Endpoint& mapped_endpoint);
    
    // Optional: Add support for additional attributes
    void set_username(const std::string& username);
    void set_message_integrity(const std::string& password); // Simplistic, real implementation requires HMAC-SHA1
    void set_fingerprint();

private:
    asio::io_context& io_context_;
    asio::ip::udp::socket socket_;
    asio::steady_timer timer_;
    std::array<uint8_t, 2048> recv_buffer_;
    Endpoint stun_server_endpoint_;
    Endpoint mapped_endpoint_;

    // Transaction ID 생성
    std::array<uint8_t, 12> generate_transaction_id();

    // STUN Binding Request 생성
    std::unique_ptr<Message> create_binding_request();

    // STUN Binding Response 파싱
    void parse_binding_response(const Message& response, Endpoint& mapped_endpoint);

    // STUN Attribute 추가
    void add_attributes(Message& message);
    
    // Optional: Helper functions for Message Integrity and Fingerprint
    // These would require proper HMAC-SHA1 and CRC32 implementations
    // For simplicity, they are omitted here
    // ...
    
    // Optional: Username and Password storage
    std::string username_;
    std::string password_;
};

#endif // STUN_CLIENT_HPP
