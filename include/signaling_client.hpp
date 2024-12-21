// include/signaling_client.hpp

#ifndef SIGNALING_CLIENT_HPP
#define SIGNALING_CLIENT_HPP

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <string>
#include <vector>
#include <functional>

class SignalingClient {
public:
    using MessageCallback = std::function<void(const std::string&)>;
    
    SignalingClient(asio::io_context& io_context, const std::string& remote_host, uint16_t remote_port, uint16_t local_port);
    
    // Send SDP message
    asio::awaitable<void> send_sdp(const std::string& sdp);
    
    // Receive SDP message
    asio::awaitable<std::string> receive_sdp();
    
    // Close signaling connection
    void close();
    
private:
    asio::io_context& io_context_;
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint remote_endpoint_;
	uint32_t tie_breaker_;
	IceRole role_;
    
    // Helper methods
    std::string create_sdp(const std::string& ufrag, const std::string& pwd, const std::vector<std::string>& candidates);
    std::pair<std::string, std::string> parse_sdp(const std::string& sdp, std::vector<std::string>& candidates);
};

#endif // SIGNALING_CLIENT_HPP
