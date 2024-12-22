// src/turn_client.cpp

#include "turn_client.hpp"
#include "stun_message.hpp"
#include "hmac_sha1.hpp"
#include "crc32.hpp"
#include <stdexcept>
#include <iostream>

// Constructor
TurnClient::TurnClient(asio::io_context& io_context, const std::string& host, uint16_t port, const std::string& username, const std::string& password)
    : io_context_(io_context), resolver_(io_context), socket_(io_context, asio::ip::udp::v4()), 
      username_(username), password_(password), allocated_(false)
{
    turn_endpoint_ = asio::ip::udp::endpoint(asio::ip::make_address(host), port);
}

// Create TURN Allocate Request
StunMessage TurnClient::create_allocate_request() const {
    std::vector<uint8_t> txn_id = StunMessage::generate_transaction_id();
    StunMessage allocate_request(StunMessageType::BINDING_REQUEST, txn_id);
    allocate_request.add_attribute(StunAttributeType::USERNAME, username_);
    allocate_request.add_message_integrity(password_);
    allocate_request.add_fingerprint();
    return allocate_request;
}

// Create TURN Refresh Request
StunMessage TurnClient::create_refresh_request() const {
    std::vector<uint8_t> txn_id = StunMessage::generate_transaction_id();
    StunMessage refresh_request(StunMessageType::BINDING_REQUEST, txn_id);
    refresh_request.add_attribute(StunAttributeType::USERNAME, username_);
    refresh_request.add_message_integrity(password_);
    refresh_request.add_fingerprint();
    return refresh_request;
}

// Allocate relay endpoint
asio::awaitable<asio::ip::udp::endpoint> TurnClient::allocate_relay() {
    if (allocated_) {
        throw std::runtime_error("TURN allocation already exists.");
    }
    
    // Create Allocate Request
    StunMessage allocate_request = create_allocate_request();
    std::vector<uint8_t> serialized = allocate_request.serialize();
    
    // Send Allocate Request
    co_await socket_.async_send_to(asio::buffer(serialized), turn_endpoint_, asio::use_awaitable);
    
    // Receive Allocate Response
    std::vector<uint8_t> recv_buffer(2048);
    asio::ip::udp::endpoint sender_endpoint;
    std::error_code ec;
    size_t bytes_received = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);
    
    if (ec) {
        throw std::runtime_error("Failed to receive TURN Allocate response: " + ec.message());
    }
    
    recv_buffer.resize(bytes_received);
    StunMessage response = StunMessage::parse(recv_buffer);
    
    // Verify response type
    if (response.get_type() != StunMessageType::BINDING_RESPONSE_SUCCESS) {
        throw std::runtime_error("Received non-success TURN Allocate Response.");
    }
    
    // Verify MESSAGE-INTEGRITY
    if (!response.verify_message_integrity(password_)) {
        throw std::runtime_error("Invalid MESSAGE-INTEGRITY in TURN Allocate Response.");
    }
    
    // Verify FINGERPRINT
    if (!response.verify_fingerprint()) {
        throw std::runtime_error("Invalid FINGERPRINT in TURN Allocate Response.");
    }
    
    // Extract RELAYED-ADDRESS
    // RFC5766에서는 RELAYED-ADDRESS가 아니라 XOR-RELAYED-ADDRESS를 사용함
    std::string ip;
    uint16_t port_num = 0;
    
    if (response.has_attribute(StunAttributeType::XOR_MAPPED_ADDRESS)) {
        std::vector<uint8_t> xma = response.get_attribute_as_bytes(StunAttributeType::XOR_MAPPED_ADDRESS);
        if (xma.size() < 8) {
            throw std::runtime_error("Invalid XOR-MAPPED-ADDRESS attribute size.");
        }
        // Parse XOR-MAPPED-ADDRESS
        uint8_t family = xma[1];
        uint16_t x_port = (xma[2] << 8) | xma[3];
        uint16_t port_unxored = x_port ^ (static_cast<uint16_t>((response.get_transaction_id()[2] << 8) | response.get_transaction_id()[3]));
        port_num = port_unxored;
        
        if (family == 0x01) { // IPv4
            uint32_t x_address = 0;
            for(int i = 0; i < 4; ++i) {
                x_address |= (static_cast<uint32_t>(xma[4 + i]) << (24 - 8*i));
            }
            uint32_t address_unxored = x_address ^ 0x2112A442; // MAGIC COOKIE
            asio::ip::address_v4::bytes_type addr_bytes;
            addr_bytes[0] = (address_unxored >> 24) & 0xFF;
            addr_bytes[1] = (address_unxored >> 16) & 0xFF;
            addr_bytes[2] = (address_unxored >> 8) & 0xFF;
            addr_bytes[3] = address_unxored & 0xFF;
            asio::ip::address_v4 addr(addr_bytes);
            ip = addr.to_string();
        }
        else if (family == 0x02) { // IPv6
            // IPv6 parsing (Not implemented here for brevity)
            throw std::runtime_error("IPv6 is not supported in this implementation.");
        }
        else {
            throw std::runtime_error("Unknown address family in XOR-MAPPED-ADDRESS.");
        }
    }
    else if (response.has_attribute(StunAttributeType::MAPPED_ADDRESS)) {
        std::vector<uint8_t> ma = response.get_attribute_as_bytes(StunAttributeType::MAPPED_ADDRESS);
        if (ma.size() < 8) {
            throw std::runtime_error("Invalid MAPPED-ADDRESS attribute size.");
        }
        uint8_t family = ma[1];
        uint16_t port_num_received = (ma[2] << 8) | ma[3];
        port_num = port_num_received;
        
        if (family == 0x01) { // IPv4
            std::string ip_addr;
            for(int i = 0; i < 4; ++i) {
                ip_addr += std::to_string(ma[4 + i]);
                if(i < 3) ip_addr += ".";
            }
            ip = ip_addr;
        }
        else if (family == 0x02) { // IPv6
            // IPv6 parsing (Not implemented here for brevity)
            throw std::runtime_error("IPv6 is not supported in this implementation.");
        }
        else {
            throw std::runtime_error("Unknown address family in MAPPED-ADDRESS.");
        }
    }
    else {
        throw std::runtime_error("Neither MAPPED-ADDRESS nor XOR-MAPPED-ADDRESS is present in TURN Allocate response.");
    }
    
    asio::ip::udp::endpoint relay_endpoint(asio::ip::make_address(ip), port_num);
    allocated_ = true;
    co_return relay_endpoint;
}

// Refresh TURN allocation
asio::awaitable<void> TurnClient::refresh_allocation() {
    if (!allocated_) {
        throw std::runtime_error("TURN allocation not established.");
    }
    
    // Create Refresh Request
    StunMessage refresh_request = create_refresh_request();
    std::vector<uint8_t> serialized = refresh_request.serialize();
    
    // Send Refresh Request
    co_await socket_.async_send_to(asio::buffer(serialized), turn_endpoint_, asio::use_awaitable);
    
    // Receive Refresh Response
    std::vector<uint8_t> recv_buffer(2048);
    asio::ip::udp::endpoint sender_endpoint;
    std::error_code ec;
    size_t bytes_received = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);
    
    if (ec) {
        throw std::runtime_error("Failed to receive TURN Refresh response: " + ec.message());
    }
    
    recv_buffer.resize(bytes_received);
    StunMessage response = StunMessage::parse(recv_buffer);
    
    // Verify response type
    if (response.get_type() != StunMessageType::BINDING_RESPONSE_SUCCESS) {
        throw std::runtime_error("Received non-success TURN Refresh Response.");
    }
    
    // Verify MESSAGE-INTEGRITY
    if (!response.verify_message_integrity(password_)) {
        throw std::runtime_error("Invalid MESSAGE-INTEGRITY in TURN Refresh Response.");
    }
    
    // Verify FINGERPRINT
    if (!response.verify_fingerprint()) {
        throw std::runtime_error("Invalid FINGERPRINT in TURN Refresh Response.");
    }
    
    // Allocation 갱신 성공
    co_return;
}

// Check if TURN allocation is active
bool TurnClient::is_allocated() const {
    return allocated_;
}
