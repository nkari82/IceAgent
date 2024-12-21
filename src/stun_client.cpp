// src/stun_client.cpp

#include "stun_client.hpp"
#include <iostream>
#include <cstring>

StunClient::StunClient(asio::io_context& io_context, const std::string& host, uint16_t port, const std::string& username)
    : io_context_(io_context),
      resolver_(io_context),
      socket_(io_context, asio::ip::udp::v4()),
      host_(host),
      port_(port),
      username_(username) {}

std::vector<uint8_t> StunClient::generate_transaction_id() {
    std::vector<uint8_t> txn_id(12);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for(auto& byte : txn_id) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    return txn_id;
}

asio::awaitable<asio::ip::udp::endpoint> StunClient::send_binding_request() {
    // Resolve STUN server address
    auto results = co_await resolver_.async_resolve(host_, std::to_string(port_), asio::use_awaitable);
    server_endpoint_ = *results.begin();
    
    // Create STUN Binding Request
    std::vector<uint8_t> txn_id = generate_transaction_id();
    Stun::StunMessage binding_request(STUN_BINDING_REQUEST, txn_id);
    if (!username_.empty()) {
        binding_request.add_attribute("USERNAME", username_);
    }
    std::vector<uint8_t> serialized_request = binding_request.serialize();
    
    // Send STUN Binding Request
    co_await socket_.async_send_to(asio::buffer(serialized_request), server_endpoint_, asio::use_awaitable);
    
    // Await response
    asio::ip::udp::endpoint mapped_endpoint = co_await receive_response(txn_id);
    
    co_return mapped_endpoint;
}

asio::awaitable<asio::ip::udp::endpoint> StunClient::receive_response(const std::vector<uint8_t>& txn_id) {
    while (true) {
        std::vector<uint8_t> recv_buffer(2048);
        asio::ip::udp::endpoint sender_endpoint;
        size_t bytes_received = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);
        recv_buffer.resize(bytes_received);
        
        // Parse STUN message
        Stun::StunMessage response = Stun::StunMessage::parse(recv_buffer);
        
        // Verify response
        if (response.get_transaction_id() != txn_id) {
            // Not matching transaction ID, ignore
            continue;
        }
        
        if (response.get_type() != STUN_BINDING_RESPONSE_SUCCESS) {
            throw std::runtime_error("Received invalid STUN response type.");
        }
        
        // Extract MAPPED-ADDRESS attribute
        std::string mapped_address = response.get_attribute("MAPPED-ADDRESS");
        if (mapped_address.empty()) {
            throw std::runtime_error("MAPPED-ADDRESS attribute missing in STUN response.");
        }
        
        // Parse MAPPED-ADDRESS (assuming format "IP:Port")
        size_t colon_pos = mapped_address.find(':');
        if (colon_pos == std::string::npos) {
            throw std::runtime_error("Invalid MAPPED-ADDRESS format.");
        }
        std::string ip = mapped_address.substr(0, colon_pos);
        uint16_t port = static_cast<uint16_t>(std::stoi(mapped_address.substr(colon_pos + 1)));
        
        asio::ip::udp::endpoint mapped_endpoint(asio::ip::make_address(ip), port);
        co_return mapped_endpoint;
    }
}
