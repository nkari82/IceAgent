// src/turn_client.cpp

#include "turn_client.hpp"
#include "stun_message.hpp"
#include "hmac_sha1.hpp"
#include "crc32.hpp"
#include <random>
#include <chrono>
#include <stdexcept>

// Constructor
TurnClient::TurnClient(asio::io_context& io_context, const std::string& server, uint16_t port,
                       const std::string& username, const std::string& password)
    : io_context_(io_context), socket_(io_context, asio::ip::udp::v4()),
      username_(username), password_(password), allocated_(false) {
    asio::ip::udp::resolver resolver(io_context_);
    auto endpoints = resolver.resolve(asio::ip::udp::v4(), server, std::to_string(port));
    server_endpoint_ = *endpoints.begin();
}

// Destructor
TurnClient::~TurnClient() {
    std::error_code ec;
    socket_.close(ec);
}

// Generate random transaction ID
std::vector<uint8_t> TurnClient::generate_transaction_id() {
    std::vector<uint8_t> txn_id(12);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for(auto& byte : txn_id) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    return txn_id;
}

// Allocate Relay Endpoint
asio::awaitable<asio::ip::udp::endpoint> TurnClient::allocate_relay() {
    // Create Allocate Request
    std::vector<uint8_t> txn_id = generate_transaction_id();
    StunMessage allocate_request(0x0030, txn_id); // Allocate method

    // Add USERNAME and MESSAGE-INTEGRITY
    allocate_request.add_attribute("USERNAME", username_);
    // Add MESSAGE-INTEGRITY
    std::vector<uint8_t> serialized = allocate_request.serialize_without_attributes({ "MESSAGE-INTEGRITY", "FINGERPRINT" });
    std::vector<uint8_t> hmac = hmac_sha1(password_, serialized);
    allocate_request.add_attribute("MESSAGE-INTEGRITY", hmac);

    // Add FINGERPRINT
    std::vector<uint8_t> fingerprint = { 0x00, 0x00, 0x00, 0x00 }; // Placeholder
    allocate_request.add_attribute("FINGERPRINT", fingerprint); // 실제 CRC32 계산 필요

    // Serialize message
    std::vector<uint8_t> serialized_request = allocate_request.serialize();

    // Send Allocate Request
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
        throw std::runtime_error("TURN Allocate Request timed out or failed: " + recv_ec.message());
    }

    bytes_received = recv_bytes;
    recv_buffer.resize(bytes_received);

    // Parse response
    StunMessage response = StunMessage::parse(recv_buffer);

    // Verify response type
    if (response.get_type() != 0x0031) { // Allocate Success Response
        throw std::runtime_error("Invalid TURN Allocate Response type.");
    }

    // Verify MESSAGE-INTEGRITY
    if (!response.verify_message_integrity(password_)) {
        throw std::runtime_error("Invalid MESSAGE-INTEGRITY in TURN Allocate response.");
    }

    // Verify FINGERPRINT
    if (!response.verify_fingerprint()) {
        throw std::runtime_error("Invalid FINGERPRINT in TURN Allocate response.");
    }

    // Extract RELAY-ADDRESS (예: "IP:PORT")
    std::string relay_address = response.get_attribute("MAPPED-ADDRESS");
    if (relay_address.empty()) {
        throw std::runtime_error("RELAY-ADDRESS attribute missing in TURN Allocate response.");
    }

    // Parse RELAY-ADDRESS
    size_t colon_pos = relay_address.find(':');
    if (colon_pos == std::string::npos) {
        throw std::runtime_error("Invalid RELAY-ADDRESS format.");
    }
    std::string ip = relay_address.substr(0, colon_pos);
    uint16_t port = static_cast<uint16_t>(std::stoi(relay_address.substr(colon_pos + 1)));

    asio::ip::udp::endpoint relay_endpoint(asio::ip::make_address(ip), port);
    allocated_ = true;
    co_return relay_endpoint;
}

// Refresh Allocation
asio::awaitable<void> TurnClient::refresh_allocation() {
    if (!allocated_) {
        throw std::runtime_error("No allocation to refresh.");
    }

    // Create Refresh Request
    std::vector<uint8_t> txn_id = generate_transaction_id();
    StunMessage refresh_request(0x0031, txn_id); // Refresh method

    // Add USERNAME and MESSAGE-INTEGRITY
    refresh_request.add_attribute("USERNAME", username_);
    // Add MESSAGE-INTEGRITY
    std::vector<uint8_t> serialized = refresh_request.serialize_without_attributes({ "MESSAGE-INTEGRITY", "FINGERPRINT" });
    std::vector<uint8_t> hmac = hmac_sha1(password_, serialized);
    refresh_request.add_attribute("MESSAGE-INTEGRITY", hmac);

    // Add FINGERPRINT
    std::vector<uint8_t> fingerprint = { 0x00, 0x00, 0x00, 0x00 }; // Placeholder
    refresh_request.add_attribute("FINGERPRINT", fingerprint); // 실제 CRC32 계산 필요

    // Serialize message
    std::vector<uint8_t> serialized_request = refresh_request.serialize();

    // Send Refresh Request
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
        throw std::runtime_error("TURN Refresh Request timed out or failed: " + recv_ec.message());
    }

    bytes_received = recv_bytes;
    recv_buffer.resize(bytes_received);

    // Parse response
    StunMessage response = StunMessage::parse(recv_buffer);

    // Verify response type
    if (response.get_type() != 0x0031) { // Refresh Success Response
        throw std::runtime_error("Invalid TURN Refresh Response type.");
    }

    // Verify MESSAGE-INTEGRITY
    if (!response.verify_message_integrity(password_)) {
        throw std::runtime_error("Invalid MESSAGE-INTEGRITY in TURN Refresh response.");
    }

    // Verify FINGERPRINT
    if (!response.verify_fingerprint()) {
        throw std::runtime_error("Invalid FINGERPRINT in TURN Refresh response.");
    }

    // Allocation remains active
    co_return;
}
