// src/turn_client.cpp

#include "turn_client.hpp"
#include <iostream>
#include <cstring>

TurnClient::TurnClient(asio::io_context& io_context, const std::string& host, uint16_t port,
                       const std::string& username, const std::string& password)
    : io_context_(io_context),
      resolver_(io_context),
      socket_(io_context, asio::ip::udp::v4()),
      host_(host),
      port_(port),
      username_(username),
      password_(password) {}

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

asio::awaitable<asio::ip::udp::endpoint> TurnClient::allocate_relay() {
    // Resolve TURN server address
    auto results = co_await resolver_.async_resolve(host_, std::to_string(port_), asio::use_awaitable);
    server_endpoint_ = *results.begin();
    
    // Create TURN Allocate Request
    std::vector<uint8_t> txn_id = generate_transaction_id();
    Stun::StunMessage allocate_request(STUN_ALLOCATE_REQUEST, txn_id);
    // Add REQUIRED attributes: USERNAME, MESSAGE-INTEGRITY, etc.
    allocate_request.add_attribute("USERNAME", username_);
    // For simplicity, omitting MESSAGE-INTEGRITY and other security attributes
    std::vector<uint8_t> serialized_request = allocate_request.serialize();
    
    // Send TURN Allocate Request
    co_await socket_.async_send_to(asio::buffer(serialized_request), server_endpoint_, asio::use_awaitable);
    
    // Await response
    asio::ip::udp::endpoint relay_endpoint = co_await receive_response(txn_id, "Allocate");
    
    allocated_ = true;
    relay_endpoint_ = relay_endpoint;
    co_return relay_endpoint;
}

asio::awaitable<void> TurnClient::refresh_allocation() {
    if (!allocated_) {
        throw std::runtime_error("No active TURN allocation to refresh.");
    }
    
    // Create TURN Refresh Request
    std::vector<uint8_t> txn_id = generate_transaction_id();
    Stun::StunMessage refresh_request(STUN_REFRESH_REQUEST, txn_id);
    refresh_request.add_attribute("USERNAME", username_);
    // For simplicity, omitting MESSAGE-INTEGRITY and other security attributes
    std::vector<uint8_t> serialized_request = refresh_request.serialize();
    
    // Send TURN Refresh Request
    co_await socket_.async_send_to(asio::buffer(serialized_request), server_endpoint_, asio::use_awaitable);
    
    // Await response
    co_await receive_response(txn_id, "Refresh");
    
    co_return;
}

asio::awaitable<asio::ip::udp::endpoint> TurnClient::receive_response(const std::vector<uint8_t>& txn_id, const std::string& message_type) {
    while (true) {
        std::vector<uint8_t> recv_buffer(2048);
        asio::ip::udp::endpoint sender_endpoint;
        size_t bytes_received = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);
        recv_buffer.resize(bytes_received);
        
        // Parse TURN message (STUN-based)
        Stun::StunMessage response = Stun::StunMessage::parse(recv_buffer);
        
        // Verify response
        if (response.get_transaction_id() != txn_id) {
            // Not matching transaction ID, ignore
            continue;
        }
        
        if (message_type == "Allocate" && response.get_type() != STUN_ALLOCATE_RESPONSE_SUCCESS) {
            throw std::runtime_error("Received invalid TURN Allocate response type.");
        }
        if (message_type == "Refresh" && response.get_type() != STUN_REFRESH_RESPONSE_SUCCESS) {
            throw std::runtime_error("Received invalid TURN Refresh response type.");
        }
        
        // Extract RELAY-ADDRESS attribute
        std::string relay_address = response.get_attribute("RELAY-ADDRESS");
        if (relay_address.empty()) {
            throw std::runtime_error("RELAY-ADDRESS attribute missing in TURN response.");
        }
        
        // Parse RELAY-ADDRESS (assuming format "IP:Port")
        size_t colon_pos = relay_address.find(':');
        if (colon_pos == std::string::npos) {
            throw std::runtime_error("Invalid RELAY-ADDRESS format.");
        }
        std::string ip = relay_address.substr(0, colon_pos);
        uint16_t port = static_cast<uint16_t>(std::stoi(relay_address.substr(colon_pos + 1)));
        
        asio::ip::udp::endpoint relay_endpoint(asio::ip::make_address(ip), port);
        co_return relay_endpoint;
    }
}
