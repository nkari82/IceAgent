// src/stun_client.cpp

#include "stun_client.hpp"
#include "stun_message.hpp"
#include "hmac_sha1.hpp"
#include "crc32.hpp"
#include <stdexcept>

// Constructor
StunClient::StunClient(asio::io_context& io_context, const std::string& host, uint16_t port, const std::string& key)
    : io_context_(io_context), resolver_(io_context), socket_(io_context)
{
    asio::ip::tcp::resolver::results_type endpoints = resolver_.resolve(host, std::to_string(port));
    if(endpoints.empty()) {
        throw std::runtime_error("Failed to resolve STUN server address.");
    }
    // IPv4 및 IPv6 모두 지원하도록 소켓 열기
    asio::ip::udp::endpoint resolved_endpoint = *endpoints.begin();
    socket_.open(resolved_endpoint.protocol());
    server_endpoint_ = resolved_endpoint;
}

// Get STUN server address
std::string StunClient::get_server() const {
    return server_endpoint_.address().to_string() + ":" + std::to_string(server_endpoint_.port());
}

// Send Binding Request and receive Binding Response
asio::awaitable<asio::ip::udp::endpoint> StunClient::send_binding_request() {
    // Generate Transaction ID
    std::vector<uint8_t> txn_id = StunMessage::generate_transaction_id();
    
    // Create Binding Request
    StunMessage binding_request(StunMessageType::BINDING_REQUEST, txn_id);
    binding_request.add_attribute(StunAttributeType::USERNAME, "testuser"); // 필요 시 실제 값으로 대체
    if (!key_.empty()) {
        binding_request.add_message_integrity(key_);
    }
    binding_request.add_fingerprint();
    
    // Serialize
    std::vector<uint8_t> serialized = binding_request.serialize();
    
    // Send Binding Request
    co_await socket_.async_send_to(asio::buffer(serialized), server_endpoint_, asio::use_awaitable);
    
    // Receive Binding Response
    std::vector<uint8_t> recv_buffer(2048);
    asio::ip::udp::endpoint sender_endpoint;
    std::error_code ec;
    size_t bytes_received = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);
    
    if (ec) {
        throw std::runtime_error("Failed to receive STUN response: " + ec.message());
    }
    
    recv_buffer.resize(bytes_received);
    StunMessage response = StunMessage::parse(recv_buffer);
    
    // Verify response type
    if (response.get_type() != StunMessageType::BINDING_RESPONSE_SUCCESS) {
        throw std::runtime_error("Received non-success STUN Binding Response.");
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
    
    // Extract XOR-MAPPED-ADDRESS or MAPPED-ADDRESS
    std::string ip;
    uint16_t port = 0;

    if (response.has_attribute(StunAttributeType::XOR_MAPPED_ADDRESS)) {
        std::vector<uint8_t> xma = response.get_attribute_as_bytes(StunAttributeType::XOR_MAPPED_ADDRESS);
        if (xma.size() < 8) {
            throw std::runtime_error("Invalid XOR-MAPPED-ADDRESS attribute size.");
        }
        // Parse XOR-MAPPED-ADDRESS
        // Structure: Reserved (8 bits), Family (8 bits), X-Port (16 bits), X-Address (32 bits for IPv4, 128 bits for IPv6)
        uint8_t family = xma[1];
        uint16_t x_port = (xma[2] << 8) | xma[3];
        uint16_t port_unxored = x_port ^ (static_cast<uint16_t>((txn_id[2] << 8) | txn_id[3]));
        port = port_unxored;
        
        if (family == 0x01) { // IPv4
            uint32_t x_address = 0;
            for(int i = 0; i < 4; ++i) {
                x_address |= (static_cast<uint32_t>(xma[4 + i]) << (24 - 8*i));
            }
            uint32_t address_unxored = x_address ^ 0x2112A442; // RFC5389 XOR magic cookie
            asio::ip::address_v4::bytes_type addr_bytes;
            addr_bytes[0] = (address_unxored >> 24) & 0xFF;
            addr_bytes[1] = (address_unxored >> 16) & 0xFF;
            addr_bytes[2] = (address_unxored >> 8) & 0xFF;
            addr_bytes[3] = address_unxored & 0xFF;
            asio::ip::address_v4 addr(addr_bytes);
            ip = addr.to_string();
        }
        else if (family == 0x02) { // IPv6
			uint8_t xor_magic_cookie[4] = {0x21, 0x12, 0xA4, 0x42};
			std::vector<uint8_t> cookie_and_txnid;
			cookie_and_txnid.insert(cookie_and_txnid.end(), xor_magic_cookie, xor_magic_cookie + 4);
			cookie_and_txnid.insert(cookie_and_txnid.end(), txn_id.begin(), txn_id.end());

			asio::ip::address_v6::bytes_type addr_bytes;
			for (int i = 0; i < 16; ++i) {
				addr_bytes[i] = xma[4 + i] ^ cookie_and_txnid[i % 16];
			}

			asio::ip::address_v6 addr(addr_bytes);
			ip = addr.to_string();
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
        // Parse MAPPED-ADDRESS
        uint8_t family = ma[1];
        uint16_t port_num = (ma[2] << 8) | ma[3];
        port = port_num;
        
        if (family == 0x01) { // IPv4
            std::string ip_addr;
            for(int i = 0; i < 4; ++i) {
                ip_addr += std::to_string(ma[4 + i]);
                if(i < 3) ip_addr += ".";
            }
            ip = ip_addr;
        }
        else if (family == 0x02) { // IPv6
			std::string ip_addr;
			for (int i = 0; i < 16; i += 2) {
				uint16_t segment = (ma[4 + i] << 8) | ma[4 + i + 1];
				ip_addr += (i > 0 ? ":" : "") + (segment == 0 ? "0" : std::to_string(segment));
			}
			ip = ip_addr;
        }
        else {
            throw std::runtime_error("Unknown address family in MAPPED-ADDRESS.");
        }
    }
    else {
        throw std::runtime_error("Neither MAPPED-ADDRESS nor XOR-MAPPED-ADDRESS is present in STUN response.");
    }

    asio::ip::udp::endpoint mapped_endpoint(asio::ip::make_address(ip), port);
    co_return mapped_endpoint;
}
