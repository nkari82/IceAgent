// include/turn_client.hpp

#ifndef TURN_CLIENT_HPP
#define TURN_CLIENT_HPP

#include "turn_message.hpp"
#include "turn_utils.hpp"
#include "stun_utils.hpp"
#include <asio.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <string>
#include <memory>
#include <vector>

using asio::ip::udp;

class TurnClient : public std::enable_shared_from_this<TurnClient> {
public:
    TurnClient(asio::io_context& io_context, const std::string& server_host, uint16_t server_port,
               const std::string& username, const std::string& password)
        : socket_(io_context, udp::endpoint(udp::v4(), 0)),
          server_endpoint_(asio::ip::make_address(server_host), server_port),
          username_(username),
          password_(password),
          allocated_(false) {}

    // Allocate Relay Endpoint
    asio::awaitable<udp::endpoint> allocate_relay() {
        // Create TURN Allocate Request
        std::vector<uint8_t> transaction_id(12, 0x00);
        std::generate(transaction_id.begin(), transaction_id.end(), []() { return rand() % 256; });

        TurnMessage request(TURN_ALLOCATE, transaction_id);
        std::vector<uint8_t> xor_relayed_address = TurnUtils::construct_xor_relayed_address(socket_.local_endpoint());
        request.add_attribute(TURN_ATTR_XOR_RELAYED_ADDRESS, xor_relayed_address);

        // Add USERNAME
        std::vector<uint8_t> username_attr(username_.begin(), username_.end());
        request.add_attribute(0x0006, username_attr); // USERNAME attribute type (0x0006)

        // Add MESSAGE-INTEGRITY
        std::vector<uint8_t> message_integrity = TurnUtils::calculate_message_integrity(request, password_);
        request.add_attribute(STUN_ATTR_MESSAGE_INTEGRITY, message_integrity);

        // Add FINGERPRINT
        uint32_t fingerprint = StunUtils::calculate_fingerprint(request);
        std::vector<uint8_t> fingerprint_attr = {
            static_cast<uint8_t>((fingerprint >> 24) & 0xFF),
            static_cast<uint8_t>((fingerprint >> 16) & 0xFF),
            static_cast<uint8_t>((fingerprint >> 8) & 0xFF),
            static_cast<uint8_t>(fingerprint & 0xFF)
        };
        request.add_attribute(STUN_ATTR_FINGERPRINT, fingerprint_attr);

        std::vector<uint8_t> serialized_request = request.serialize();

        // Send Allocate Request
        co_await socket_.async_send_to(asio::buffer(serialized_request), server_endpoint_, asio::use_awaitable);

        // Prepare to receive response
        std::vector<uint8_t> recv_buffer(2048);
        udp::endpoint sender_endpoint;

        // Set a timeout
        asio::steady_timer timer(co_await asio::this_coro::executor);
        timer.expires_after(std::chrono::seconds(5));

        // Await either receive or timeout
        using namespace asio::experimental::awaitable_operators;
        auto [ec, bytes_transferred] = co_await (
            socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable)
            || timer.async_wait(asio::use_awaitable)
        );

        if (ec == asio::error::operation_aborted) {
            throw std::runtime_error("TURN Allocate Request timed out.");
        } else if (ec) {
            throw std::runtime_error("TURN Allocate Request failed: " + ec.message());
        }

        recv_buffer.resize(bytes_transferred);
        TurnMessage response = TurnMessage::parse(recv_buffer);

        // Validate response
        if (response.get_type() != TURN_ALLOCATE_RESPONSE_SUCCESS) {
            throw std::runtime_error("Invalid TURN Allocate Response type.");
        }

        // Validate Transaction ID
        if (response.get_transaction_id() != transaction_id) {
            throw std::runtime_error("TURN Transaction ID mismatch.");
        }

        // Validate MESSAGE-INTEGRITY
        auto attrs = response.get_attributes();
        bool mi_found = false;
        std::vector<uint8_t> received_mi;
        for (const auto& attr : attrs) {
            if (attr.type == STUN_ATTR_MESSAGE_INTEGRITY) {
                received_mi = attr.value;
                mi_found = true;
                break;
            }
        }
        if (!mi_found) {
            throw std::runtime_error("TURN MESSAGE-INTEGRITY attribute missing.");
        }

        std::vector<uint8_t> calculated_mi = TurnUtils::calculate_message_integrity(response, password_);
        if (received_mi.size() != calculated_mi.size() || !std::equal(received_mi.begin(), received_mi.end(), calculated_mi.begin())) {
            throw std::runtime_error("TURN MESSAGE-INTEGRITY validation failed.");
        }

        // Extract XOR-RELAYED-ADDRESS
        asio::ip::udp::endpoint relay_endpoint;
        for (const auto& attr : response.get_attributes()) {
            if (attr.type == TURN_ATTR_XOR_RELAYED_ADDRESS) {
                // Parse XOR-RELAYED-ADDRESS
                if (attr.value.size() < 8) continue;
                uint8_t family = attr.value[1];
                if (family != 0x01) continue; // IPv4
                uint16_t xport = (attr.value[2] << 8) | attr.value[3];
                uint16_t port = xport ^ ((0x2112A442 >> 16) & 0xFFFF);
                uint32_t xaddr = (attr.value[4] << 24) | (attr.value[5] << 16) | (attr.value[6] << 8) | attr.value[7];
                uint32_t addr = xaddr ^ 0x2112A442;

                asio::ip::address_v4 ip_addr(addr);
                relay_endpoint = udp::endpoint(ip_addr, port);
                break;
            }
        }

        if (relay_endpoint.address().is_unspecified()) {
            throw std::runtime_error("TURN XOR-RELAYED-ADDRESS attribute missing.");
        }

        allocated_ = true;
        relay_endpoint_ = relay_endpoint;

        co_return relay_endpoint_;
    }
    
    bool is_allocated() const { return allocated_; }
    udp::endpoint get_relay_endpoint() const { return relay_endpoint_; }

private:
    udp::socket socket_;
    udp::endpoint server_endpoint_;
    std::string username_;
    std::string password_;
    bool allocated_;
    udp::endpoint relay_endpoint_;
};

#endif // TURN_CLIENT_HPP
