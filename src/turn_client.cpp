// src/turn_client.cpp

#include "turn_client.hpp"
#include "message.hpp"
#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <chrono>
#include <random>
#include <iostream>

// Constructor with TURN server information and optional credentials
TurnClient::TurnClient(asio::io_context& io_context, const std::string& turn_server, const std::string& username, const std::string& password)
    : io_context_(io_context),
      socket_(io_context, asio::ip::udp::v4()),
      turn_server_(turn_server),
      username_(username),
      password_(password) {}

// Allocate a relay address
awaitable<asio::ip::udp::endpoint> TurnClient::allocate_relay() {
    if (allocated_) {
        co_return relay_endpoint_;
    }

    co_await send_allocate_request();
    relay_endpoint_ = co_await receive_allocate_response();
    allocated_ = true;

    co_return relay_endpoint_;
}

// Send data through the relay
awaitable<void> TurnClient::send_data(const std::vector<uint8_t>& data, const asio::ip::udp::endpoint& relay_endpoint) {
    if (!allocated_) {
        throw std::runtime_error("Relay not allocated. Call allocate_relay() first.");
    }

    // Create TURN Send Indication
    // TURN message structure for Send Indication is similar to STUN messages
    auto send_indication = std::make_unique<Message>(0x0010, {}); // 0x0010: Send Indication

    // Add XOR-RELAYED-ADDRESS attribute
    uint32_t xor_addr = relay_endpoint_.address().to_v4().to_uint() ^ TURN_MAGIC_COOKIE;
    uint16_t xor_port = relay_endpoint_.port() ^ ((TURN_MAGIC_COOKIE >> 16) & 0xFFFF);

    std::vector<uint8_t> xor_relayed_address;
    xor_relayed_address.push_back(0x00); // Reserved
    xor_relayed_address.push_back(0x01); // IPv4
    xor_relayed_address.push_back((xor_port >> 8) & 0xFF);
    xor_relayed_address.push_back(xor_port & 0xFF);
    xor_relayed_address.push_back((xor_addr >> 24) & 0xFF);
    xor_relayed_address.push_back((xor_addr >> 16) & 0xFF);
    xor_relayed_address.push_back((xor_addr >> 8) & 0xFF);
    xor_relayed_address.push_back(xor_addr & 0xFF);

    send_indication->add_attribute(TURN_ATTR_XOR_RELAYED_ADDRESS, xor_relayed_address);

    // Add DATA payload (optional)
    send_indication->set_payload(data);

    // Authenticate if credentials are provided
    if (!username_.empty() && !password_.empty()) {
        authenticate_message(*send_indication);
    }

    // Serialize and send the message
    std::vector<uint8_t> serialized_send = send_indication->serialize();
    co_await socket_.async_send_to(asio::buffer(serialized_send), relay_endpoint_, asio::use_awaitable);
}

// Receive data from the relay
awaitable<std::pair<std::vector<uint8_t>, asio::ip::udp::endpoint>> TurnClient::receive_data() {
    if (!allocated_) {
        throw std::runtime_error("Relay not allocated. Call allocate_relay() first.");
    }

    std::vector<uint8_t> recv_buffer(2048);
    asio::ip::udp::endpoint sender_endpoint;

    size_t len = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);
    recv_buffer.resize(len);

    // Parse the TURN message
    auto message = Message::parse(recv_buffer, len);
    if (message->get_type() != 0x0110) { // 0x0110: Data Indication
        throw std::runtime_error("Invalid TURN message type received.");
    }

    // Extract DATA payload
    std::vector<uint8_t> data = message->get_payload();

    co_return std::make_pair(data, sender_endpoint);
}

// Close the relay allocation
void TurnClient::close() {
    if (!allocated_) {
        return;
    }

    // Implement TURN Refresh or Binding messages to close the allocation
    // For simplicity, we'll just close the socket
    asio::error_code ec;
    socket_.close(ec);
    if (ec) {
        std::cerr << "Error closing TURN socket: " << ec.message() << std::endl;
    }

    allocated_ = false;
}

// Helper method to send TURN Allocate Request
awaitable<void> TurnClient::send_allocate_request() {
    // Create TURN Allocate Request
    auto allocate_request = std::make_unique<Message>(TURN_ALLOCATE, {}); // 0x0003: Allocate Request

    // Add USERNAME and MESSAGE-INTEGRITY if credentials are provided
    if (!username_.empty() && !password_.empty()) {
        allocate_request->add_attribute(0x0006, std::vector<uint8_t>(username_.begin(), username_.end())); // USERNAME
        authenticate_message(*allocate_request);
    }

    // Serialize and send the Allocate Request
    std::vector<uint8_t> serialized_request = allocate_request->serialize();
    co_await socket_.async_send_to(asio::buffer(serialized_request), asio::ip::udp::endpoint(asio::ip::address::from_string("0.0.0.0"), 0), asio::use_awaitable);
}

// Helper method to receive TURN Allocate Response
awaitable<asio::ip::udp::endpoint> TurnClient::receive_allocate_response() {
    // Set up a timeout
    asio::steady_timer timer(io_context_);
    timer.expires_after(std::chrono::seconds(5));

    // Buffer for response
    std::vector<uint8_t> recv_buffer(2048);
    asio::ip::udp::endpoint sender_endpoint;

    // Await for response or timeout
    bool response_received = false;
    asio::error_code ec = asio::error::would_block;
    asio::ip::udp::endpoint allocated_endpoint;

    socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint,
        [&](const asio::error_code& error, std::size_t bytes_transferred) {
            ec = error;
            if (!error && bytes_transferred >= STUN_HEADER_SIZE) {
                try {
                    auto response = Message::parse(recv_buffer, bytes_transferred);
                    if (response->get_type() != TURN_SUCCESS_RESPONSE) {
                        throw std::runtime_error("Invalid TURN Allocate Response Type");
                    }

                    // Extract XOR-RELAYED-ADDRESS
                    auto attr = response->get_attribute(TURN_ATTR_XOR_RELAYED_ADDRESS);
                    if (attr.empty()) {
                        throw std::runtime_error("No XOR-RELAYED-ADDRESS in TURN response");
                    }

                    // Parse XOR-RELAYED-ADDRESS
                    // Assume IPv4 for simplicity
                    if (attr[1] != 0x01) { // Address family: IPv4
                        throw std::runtime_error("Unsupported address family in XOR-RELAYED-ADDRESS");
                    }

                    uint16_t xport = (attr[2] << 8) | attr[3];
                    uint16_t port = xport ^ ((TURN_MAGIC_COOKIE >> 16) & 0xFFFF);

                    uint32_t xaddr = (attr[4] << 24) | (attr[5] << 16) | (attr[6] << 8) | attr[7];
                    uint32_t addr = xaddr ^ TURN_MAGIC_COOKIE;

                    asio::ip::address_v4 relay_ip(addr);
                    asio::ip::udp::endpoint relay_endpoint(relay_ip, port);

                    allocated_endpoint = relay_endpoint;
                    response_received = true;
                    timer.cancel(); // Cancel the timer as response is received
                } catch (const std::exception& ex) {
                    std::cerr << "TURN Allocate Response parse error: " << ex.what() << std::endl;
                    // Handle parsing errors
                }
            }
        });

    timer.async_wait([&](const asio::error_code& error) {
        if (!error && !response_received) {
            socket_.cancel(); // Cancel the receive operation
        }
    });

    // Wait until either receive or timeout occurs
    while (ec == asio::error::would_block) {
        co_await asio::this_coro::executor;
    }

    if (ec && ec != asio::error::operation_aborted) {
        throw std::runtime_error("TURN Allocate Request failed: " + ec.message());
    }

    if (!response_received) {
        throw std::runtime_error("TURN Allocate Request timed out");
    }

    co_return allocated_endpoint;
}

// Helper method to authenticate TURN messages
void TurnClient::authenticate_message(Message& message) {
    // Implement MESSAGE-INTEGRITY based on TURN authentication
    // This typically involves hashing the message with a key derived from the password
    // For simplicity, this example does not implement it
    // You should integrate HMAC-SHA1 here using OpenSSL or another crypto library
}

