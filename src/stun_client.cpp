// src/stun_client.cpp

#include "stun_client.hpp"
#include "stun_message.hpp"
#include "hmac_sha1.hpp"
#include "crc32.hpp"
#include <random>
#include <chrono>
#include <stdexcept>

// Constructor
StunClient::StunClient(asio::io_context& io_context, const std::string& server, uint16_t port, const std::string& key)
    : io_context_(io_context), socket_(io_context, asio::ip::udp::v4()), key_(key) {
    asio::ip::udp::resolver resolver(io_context_);
    auto endpoints = resolver.resolve(asio::ip::udp::v4(), server, std::to_string(port));
    server_endpoint_ = *endpoints.begin();
}

// Destructor
StunClient::~StunClient() {
    std::error_code ec;
    socket_.close(ec);
}

// Generate random transaction ID
std::vector<uint8_t> generate_transaction_id() {
    std::vector<uint8_t> txn_id(12);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for(auto& byte : txn_id) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    return txn_id;
}

// Send Binding Request and receive MAPPED-ADDRESS
asio::awaitable<asio::ip::udp::endpoint> StunClient::send_binding_request() {
    // Create Binding Request
    std::vector<uint8_t> txn_id = generate_transaction_id();
    StunMessage binding_request(STUN_BINDING_REQUEST, txn_id);

    // Add necessary attributes
    binding_request.add_attribute("PRIORITY", "16777215"); // Example priority
    binding_request.add_attribute("USERNAME", "user"); // Example username

    // Add MESSAGE-INTEGRITY if key is provided
    if (!key_.empty()) {
        std::vector<uint8_t> serialized = binding_request.serialize_without_attributes({ "MESSAGE-INTEGRITY", "FINGERPRINT" });
        std::vector<uint8_t> hmac = hmac_sha1(key_, serialized);
        binding_request.add_attribute("MESSAGE-INTEGRITY", hmac);
    }

    // Add FINGERPRINT
    std::vector<uint8_t> fingerprint = { 0x00, 0x00, 0x00, 0x00 }; // Placeholder
    binding_request.add_attribute("FINGERPRINT", fingerprint); // Actual fingerprint calculation 필요

    // Serialize message
    std::vector<uint8_t> serialized_request = binding_request.serialize();

    // Send Binding Request
    co_await socket_.async_send_to(asio::buffer(serialized_request), server_endpoint_, asio::use_awaitable);

    // Set timeout
    asio::steady_timer timer(io_context_);
    timer.expires_after(std::chrono::seconds(3));

    // Receive response
    std::vector<uint8_t> recv_buffer(2048);
    asio::ip::udp::endpoint sender_endpoint;
    std::error_code ec;
    size_t bytes_received = 0;

    using namespace asio::experimental::awaitable_operators;
    auto [recv_ec, recv_bytes] = co_await (
        (socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable))
        || (timer.async_wait(asio::use_awaitable))
    );

    if (recv_ec) {
        throw std::runtime_error("STUN Binding Request timed out or failed: " + recv_ec.message());
    }

    bytes_received = recv_bytes;
    recv_buffer.resize(bytes_received);

    // Parse response
    StunMessage response = StunMessage::parse(recv_buffer);

    // Verify response type
    if (response.get_type() != STUN_BINDING_RESPONSE_SUCCESS) {
        throw std::runtime_error("Invalid STUN Binding Response type.");
    }

    // Verify MESSAGE-INTEGRITY if key is provided
    if (!key_.empty()) {
        if (!response.verify_message_integrity(key_)) {
            throw std::runtime_error("Invalid MESSAGE-INTEGRITY in STUN response.");
        }
    }

    // Verify FINGERPRINT
    if (!response.verify_fingerprint()) {
        throw std::runtime_error("Invalid FINGERPRINT in STUN response.");
    }

    // Extract MAPPED-ADDRESS
    std::string mapped_address = response.get_attribute("MAPPED-ADDRESS");
    if (mapped_address.empty()) {
        throw std::runtime_error("MAPPED-ADDRESS attribute missing in STUN response.");
    }

    // Parse MAPPED-ADDRESS (예: "IP:PORT")
    size_t colon_pos = mapped_address.find(':');
    if (colon_pos == std::string::npos) {
        throw std::runtime_error("Invalid MAPPED-ADDRESS format.");
    }
    std::string ip = mapped_address.substr(0, colon_pos);
    uint16_t port = static_cast<uint16_t>(std::stoi(mapped_address.substr(colon_pos + 1)));

    asio::ip::udp::endpoint mapped_endpoint(asio::ip::make_address(ip), port);
    co_return mapped_endpoint;
}
