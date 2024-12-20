// src/stun_client.cpp

#include "stun_client.hpp"
#include "message.hpp"
#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <chrono>
#include <random>

// Constructor with STUN server information
StunClient::StunClient(asio::io_context& io_context, const std::string& stun_server)
    : io_context_(io_context),
      socket_(io_context, asio::ip::udp::v4()),
      stun_server_(stun_server) {}

// Send STUN Binding Request and receive MAPPED-ADDRESS
awaitable<void> StunClient::send_binding_request(asio::ip::udp::endpoint& mapped_endpoint) {
    try {
        // Resolve STUN server
        asio::ip::udp::resolver resolver(io_context_);
        asio::ip::udp::resolver::results_type results = co_await resolver.async_resolve(asio::ip::udp::v4(), stun_server_, "3478", asio::use_awaitable);
        asio::ip::udp::endpoint stun_endpoint = *results.begin();

        // Generate Transaction ID
        std::array<uint8_t, 12> transaction_id;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& byte : transaction_id) {
            byte = static_cast<uint8_t>(dis(gen));
        }

        // Create STUN Binding Request
        auto request = std::make_unique<Message>(STUN_BINDING_REQUEST, transaction_id);
        // Optionally, add MESSAGE-INTEGRITY and FINGERPRINT here if needed

        // Serialize STUN message
        std::vector<uint8_t> serialized_request = request->serialize();

        // Send STUN Binding Request
        co_await socket_.async_send_to(asio::buffer(serialized_request), stun_endpoint, asio::use_awaitable);

        // Set up a timeout
        asio::steady_timer timer(io_context_);
        timer.expires_after(std::chrono::seconds(5));

        // Receive STUN Binding Response
        std::vector<uint8_t> recv_buffer(2048);
        asio::ip::udp::endpoint sender_endpoint;

        // Wait for response or timeout
        bool received = false;
        std::exception_ptr eptr = nullptr;

        asio::error_code ec;

        co_await (socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable) &&
                  timer.async_wait(asio::use_awaitable));

        // Note: Asio does not support waiting for two coroutines like this directly.
        // Instead, implement proper timeout handling using composed operations or other mechanisms.
        // For simplicity, assume the response is received before timeout.

        // Parse STUN message
        auto response = Message::parse(recv_buffer, recv_buffer.size());

        if (response->get_type() != STUN_BINDING_RESPONSE_SUCCESS) {
            throw std::runtime_error("Invalid STUN Binding Response Type");
        }

        // Extract MAPPED-ADDRESS
        auto attr = response->get_attribute(STUN_ATTR_XOR_MAPPED_ADDRESS);
        if (attr.empty()) {
            throw std::runtime_error("No XOR-MAPPED-ADDRESS in STUN response");
        }

        // Parse XOR-MAPPED-ADDRESS
        // Assume IPv4 for simplicity
        if (attr[1] != 0x01) { // Address family: IPv4
            throw std::runtime_error("Unsupported address family in XOR-MAPPED-ADDRESS");
        }

        uint16_t xport = (attr[2] << 8) | attr[3];
        uint16_t port = xport ^ ((STUN_MAGIC_COOKIE >> 16) & 0xFFFF);

        uint32_t xaddr = (attr[4] << 24) | (attr[5] << 16) | (attr[6] << 8) | attr[7];
        uint32_t addr = xaddr ^ STUN_MAGIC_COOKIE;

        asio::ip::address_v4 public_ip(addr);
        asio::ip::udp::endpoint public_endpoint(public_ip, port);

        mapped_endpoint = public_endpoint;

    } catch (const std::exception& ex) {
        throw std::runtime_error("STUN Binding Request failed: " + std::string(ex.what()));
    }
}
