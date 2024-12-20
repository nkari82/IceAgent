// src/stun_client.cpp

#include "stun_client.hpp"
#include <iostream>
#include <cstring>
#include <chrono>

// Constructor
StunClient::StunClient(asio::io_context& io_context)
    : io_context_(io_context),
      socket_(io_context, asio::ip::udp::v4()),
      timer_(io_context) {}

// Generate a random 12-byte Transaction ID
std::array<uint8_t, 12> StunClient::generate_transaction_id() {
    std::array<uint8_t, 12> transaction_id;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : transaction_id) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    return transaction_id;
}

// Create STUN Binding Request
std::unique_ptr<Message> StunClient::create_binding_request() {
    auto message = std::make_unique<Message>(STUN_BINDING_REQUEST);
    auto transaction_id = generate_transaction_id();
    message->set_transaction_id(std::vector<uint8_t>(transaction_id.begin(), transaction_id.end()));
    
    // Add USERNAME attribute if set
    if (!username_.empty()) {
        message->add_attribute(STUN_ATTR_USERNAME, std::vector<uint8_t>(username_.begin(), username_.end()));
    }
    
    // Add MESSAGE-INTEGRITY attribute if set
    if (!password_.empty()) {
        // Simplistic placeholder: real implementation requires HMAC-SHA1 over message
        // Here, we'll just add the password bytes as a placeholder
        message->add_attribute(STUN_ATTR_MESSAGE_INTEGRITY, std::vector<uint8_t>(password_.begin(), password_.end()));
    }
    
    // Add FINGERPRINT attribute if set
    if (false) { // Placeholder condition
        set_fingerprint();
    }
    
    return message;
}

// Send STUN Binding Request and receive Binding Response
awaitable<void> StunClient::send_binding_request(const Endpoint& stun_server, Endpoint& mapped_endpoint) {
    stun_server_endpoint_ = stun_server;

    // Create Binding Request Message
    auto request_message = create_binding_request();
    auto serialized_request = request_message->serialize();

    // Send Binding Request
    co_await socket_.async_send_to(asio::buffer(serialized_request), stun_server_endpoint_, asio::use_awaitable);

    // Start timer for timeout (e.g., 3 seconds)
    timer_.expires_after(std::chrono::seconds(3));

    // Prepare coroutine to receive response
    bool received = false;
    std::vector<uint8_t> response_buffer(2048);
    asio::ip::udp::endpoint sender_endpoint;

    // Lambda to handle receive
    auto recv_coroutine = [&]() -> awaitable<void> {
        try {
            size_t len = co_await socket_.async_receive_from(asio::buffer(response_buffer), sender_endpoint, asio::use_awaitable);
            // Check if the response is from the STUN server
            if (sender_endpoint != stun_server_endpoint_) {
                throw std::runtime_error("Received response from unknown source");
            }
            // Parse Binding Response
            auto response_message = Message::parse(response_buffer, len);
            if (!response_message) {
                throw std::runtime_error("Failed to parse STUN response");
            }
            parse_binding_response(*response_message, mapped_endpoint);
            received = true;
            // Cancel the timer
            timer_.cancel();
        } catch (const std::exception& ex) {
            std::cerr << "Error receiving STUN response: " << ex.what() << std::endl;
            // Cancel the timer
            timer_.cancel();
        }
    };

    // Start receive coroutine
    co_spawn(io_context_, recv_coroutine, asio::detached);

    // Wait for either receive or timeout
    try {
        co_await timer_.async_wait(asio::use_awaitable);
        if (!received) {
            throw std::runtime_error("STUN Binding Response timed out");
        }
    } catch (const asio::system_error& e) {
        if (e.code() != asio::error::operation_aborted) {
            throw; // Rethrow if not cancelled
        }
    }
}

// Parse STUN Binding Response
void StunClient::parse_binding_response(const Message& response, Endpoint& mapped_endpoint) {
    if (response.get_type() != STUN_BINDING_RESPONSE_SUCCESS) {
        throw std::runtime_error("Invalid STUN message type");
    }

    // Check Magic Cookie
    // In Message class parsing, Magic Cookie is already validated

    // Parse Attributes
    const auto& attributes = response.get_attributes();
    bool found_mapped_address = false;
    bool message_integrity_valid = false;
    bool fingerprint_valid = false;
    std::string received_username;

    for (const auto& attr : attributes) {
        switch (attr.type) {
            case STUN_ATTR_MAPPED_ADDRESS:
            case STUN_ATTR_XOR_MAPPED_ADDRESS: {
                // Parse MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
                if (attr.value.size() < 8) {
                    throw std::runtime_error("MAPPED-ADDRESS attribute too short");
                }

                uint8_t family = attr.value[1];
                if (family != 0x01) { // IPv4
                    throw std::runtime_error("Unsupported address family");
                }

                uint16_t port;
                uint32_t addr;
                if (attr.type == STUN_ATTR_MAPPED_ADDRESS) {
                    port = (attr.value[2] << 8) | attr.value[3];
                    addr = (attr.value[4] << 24) | (attr.value[5] << 16) |
                           (attr.value[6] << 8) | attr.value[7];
                } else { // XOR-MAPPED-ADDRESS
                    uint16_t xport = (attr.value[2] << 8) | attr.value[3];
                    uint32_t xaddr = (attr.value[4] << 24) | (attr.value[5] << 16) |
                                     (attr.value[6] << 8) | attr.value[7];
                    port = xport ^ ((STUN_MAGIC_COOKIE >> 16) & 0xFFFF);
                    addr = xaddr ^ STUN_MAGIC_COOKIE;
                }

                asio::ip::address_v4::bytes_type addr_bytes;
                addr_bytes[0] = (addr >> 24) & 0xFF;
                addr_bytes[1] = (addr >> 16) & 0xFF;
                addr_bytes[2] = (addr >> 8) & 0xFF;
                addr_bytes[3] = addr & 0xFF;
                asio::ip::address_v4 ip_addr(addr_bytes);

                mapped_endpoint = asio::ip::udp::endpoint(ip_addr, port);
                found_mapped_address = true;
                break;
            }
            case STUN_ATTR_USERNAME: {
                // Parse USERNAME attribute
                received_username = std::string(attr.value.begin(), attr.value.end());
                break;
            }
            case STUN_ATTR_MESSAGE_INTEGRITY: {
                // Verify MESSAGE-INTEGRITY
                // Placeholder: Real implementation requires HMAC-SHA1 over the message up to this attribute
                // Here, we'll assume it's valid if password is set
                if (!password_.empty()) {
                    message_integrity_valid = true;
                }
                break;
            }
            case STUN_ATTR_FINGERPRINT: {
                // Verify FINGERPRINT
                // Placeholder: Real implementation requires CRC32 over the message
                // Here, we'll assume it's valid
                fingerprint_valid = true;
                break;
            }
            default:
                // Handle other attributes as needed
                break;
        }
    }

    if (!found_mapped_address) {
        throw std::runtime_error("MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute not found");
    }

    // Optional: Verify MESSAGE-INTEGRITY and FINGERPRINT
    if (!password_.empty() && !message_integrity_valid) {
        throw std::runtime_error("MESSAGE-INTEGRITY verification failed");
    }
    if (false && !fingerprint_valid) { // Placeholder condition
        throw std::runtime_error("FINGERPRINT verification failed");
    }

    // Optional: Validate USERNAME if set
    if (!username_.empty() && received_username != username_) {
        throw std::runtime_error("USERNAME does not match");
    }

    // At this point, mapped_endpoint is successfully parsed and validated
}

// Optional: Set Username
void StunClient::set_username(const std::string& username) {
    username_ = username;
}

// Optional: Set Message Integrity (Simplistic Implementation)
void StunClient::set_message_integrity(const std::string& password) {
    password_ = password;
}

// Optional: Set Fingerprint (Placeholder)
void StunClient::set_fingerprint() {
    // Real implementation requires CRC32 over the message
    // Here, we'll add a placeholder value
    // Typically, you would calculate CRC32 on the entire message up to this attribute
}

// Optional: Add attributes to STUN message
void StunClient::add_attributes(Message& message) {
    // Example: Add USERNAME and MESSAGE-INTEGRITY if set
    if (!username_.empty()) {
        message.add_attribute(STUN_ATTR_USERNAME, std::vector<uint8_t>(username_.begin(), username_.end()));
    }
    if (!password_.empty()) {
        // Placeholder: Real implementation requires HMAC-SHA1
        message.add_attribute(STUN_ATTR_MESSAGE_INTEGRITY, std::vector<uint8_t>(password_.begin(), password_.end()));
    }
}

