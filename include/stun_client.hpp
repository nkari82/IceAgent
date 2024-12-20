// include/stun_client.hpp

#ifndef STUN_CLIENT_HPP
#define STUN_CLIENT_HPP

#include "stun_message.hpp"
#include "stun_utils.hpp"
#include <asio.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <string>
#include <memory>
#include <vector>

using asio::ip::udp;

class StunClient : public std::enable_shared_from_this<StunClient> {
public:
    StunClient(asio::io_context& io_context, const std::string& server_host, uint16_t server_port, const std::string& key = "")
        : socket_(io_context, udp::endpoint(udp::v4(), 0)),
          server_endpoint_(asio::ip::make_address(server_host), server_port),
          key_(key) {}

    // Send Binding Request and await response
    asio::awaitable<udp::endpoint> send_binding_request() {
        // Create STUN Binding Request
        std::vector<uint8_t> transaction_id(12, 0x00);
        asio::steady_timer timer(co_await asio::this_coro::executor);
        std::generate(transaction_id.begin(), transaction_id.end(), []() { return rand() % 256; });

        StunMessage request(STUN_BINDING_REQUEST, transaction_id);
        std::vector<uint8_t> xor_mapped_address = StunUtils::construct_xor_mapped_address(socket_.local_endpoint());
        request.add_attribute(STUN_ATTR_XOR_MAPPED_ADDRESS, xor_mapped_address);

        // Add MESSAGE-INTEGRITY if key is provided
        if (!key_.empty()) {
            std::vector<uint8_t> message_integrity = StunUtils::calculate_message_integrity(request, key_);
            request.add_attribute(STUN_ATTR_MESSAGE_INTEGRITY, message_integrity);
        }

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

        // Send request
        co_await socket_.async_send_to(asio::buffer(serialized_request), server_endpoint_, asio::use_awaitable);

        // Prepare to receive response
        std::vector<uint8_t> recv_buffer(2048);
        udp::endpoint sender_endpoint;

        // Set a timeout
        timer.expires_after(std::chrono::seconds(2));

        // Await either receive or timeout
        using namespace asio::experimental::awaitable_operators;
        auto [ec, bytes_transferred] = co_await (
            socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable)
            || timer.async_wait(asio::use_awaitable)
        );

        if (ec == asio::error::operation_aborted) {
            throw std::runtime_error("STUN Binding Request timed out.");
        } else if (ec) {
            throw std::runtime_error("STUN Binding Request failed: " + ec.message());
        }

        recv_buffer.resize(bytes_transferred);
        StunMessage response = StunMessage::parse(recv_buffer);

        // Validate response
        if (response.get_type() != STUN_BINDING_RESPONSE_SUCCESS) {
            throw std::runtime_error("Invalid STUN Binding Response type.");
        }

        // Validate Transaction ID
        if (response.get_transaction_id() != transaction_id) {
            throw std::runtime_error("STUN Transaction ID mismatch.");
        }

        // Validate MESSAGE-INTEGRITY if key is provided
        if (!key_.empty()) {
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
                throw std::runtime_error("STUN MESSAGE-INTEGRITY attribute missing.");
            }

            std::vector<uint8_t> calculated_mi = StunUtils::calculate_message_integrity(response, key_);
            if (received_mi.size() != calculated_mi.size() || !std::equal(received_mi.begin(), received_mi.end(), calculated_mi.begin())) {
                throw std::runtime_error("STUN MESSAGE-INTEGRITY validation failed.");
            }
        }

        // Extract XOR-MAPPED-ADDRESS
        asio::ip::udp::endpoint mapped_endpoint;
        for (const auto& attr : response.get_attributes()) {
            if (attr.type == STUN_ATTR_XOR_MAPPED_ADDRESS) {
                // Parse XOR-MAPPED-ADDRESS
                if (attr.value.size() < 8) continue;
                uint8_t family = attr.value[1];
                if (family != 0x01) continue; // IPv4
                uint16_t xport = (attr.value[2] << 8) | attr.value[3];
                uint16_t port = xport ^ ((0x2112A442 >> 16) & 0xFFFF);
                uint32_t xaddr = (attr.value[4] << 24) | (attr.value[5] << 16) | (attr.value[6] << 8) | attr.value[7];
                uint32_t addr = xaddr ^ 0x2112A442;

                asio::ip::address_v4 ip_addr(addr);
                mapped_endpoint = udp::endpoint(ip_addr, port);
                break;
            }
        }

        if (mapped_endpoint.address().is_unspecified()) {
            throw std::runtime_error("STUN MAPPED-ADDRESS attribute missing.");
        }

        co_return mapped_endpoint;
    }

private:
    udp::socket socket_;
    udp::endpoint server_endpoint_;
    std::string key_;
};

#endif // STUN_CLIENT_HPP
