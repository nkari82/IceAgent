// include/signaling_client.hpp

#ifndef SIGNALING_CLIENT_HPP
#define SIGNALING_CLIENT_HPP

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <string>
#include <vector>
#include <memory>

enum class IceMode {
    Full,
    Lite
};

class SignalingClient {
public:
    SignalingClient(asio::io_context& io_context, const std::string& signaling_server, uint16_t port);
    
    asio::awaitable<void> send_sdp(const std::string& sdp);
    
    asio::awaitable<std::string> receive_sdp();
    
    std::string create_sdp(const std::string& username_fragment, const std::string& password, const std::vector<std::string>& candidates, IceMode mode, uint64_t tie_breaker);
    
    std::tuple<std::string, std::string, uint64_t> parse_sdp(const std::string& sdp, std::vector<std::string>& candidates);
    
private:
    asio::io_context& io_context_;
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::resolver resolver_;
    
    // Helper methods for SDP handling
};

#endif // SIGNALING_CLIENT_HPP
