// include/turn_client.hpp

#ifndef TURN_CLIENT_HPP
#define TURN_CLIENT_HPP

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <string>
#include <vector>
#include <random>
#include <unordered_map>
#include <mutex>
#include "hash_vector.hpp"
#include "stun_message.hpp"

class TurnClient {
public:
    TurnClient(asio::io_context& io_context, const std::string& host, uint16_t port,
               const std::string& username, const std::string& password);
    
    // Allocate a relay endpoint
    asio::awaitable<asio::ip::udp::endpoint> allocate_relay();
    
    // Refresh the allocation
    asio::awaitable<void> refresh_allocation();
    
    // Check if allocation is active
    bool is_allocated() const { return allocated_; }
    
    // Get TURN server address
    std::string get_server() const { return host_ + ":" + std::to_string(port_); }
    
private:
    asio::io_context& io_context_;
    asio::ip::udp::resolver resolver_;
    asio::ip::udp::endpoint server_endpoint_;
    asio::ip::udp::socket socket_;
    std::string host_;
    uint16_t port_;
    std::string username_;
    std::string password_;
    
    // Allocation state
    bool allocated_ = false;
    asio::ip::udp::endpoint relay_endpoint_;
    
    // Transaction ID 관리
    std::mutex txn_mutex_;
	std::unordered_map<std::vector<uint8_t>, asio::ip::udp::endpoint, VectorHash> txn_map_;
    
    // Helper to generate random transaction ID
    std::vector<uint8_t> generate_transaction_id();
    
    // Receive and process TURN response
    asio::awaitable<asio::ip::udp::endpoint> receive_response(const std::vector<uint8_t>& txn_id, const std::string& message_type);
};

#endif // TURN_CLIENT_HPP
