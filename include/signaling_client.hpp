// include/signaling_client.hpp

#ifndef SIGNALING_CLIENT_HPP
#define SIGNALING_CLIENT_HPP

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <string>
#include <vector>
#include <memory>
#include <ice_agent.hpp>

class SignalingClient {
public:
    SignalingClient(asio::io_context& io_context, const std::string& signaling_server, uint16_t port);

    asio::awaitable<void> send_sdp(const std::string& sdp);
    
    asio::awaitable<std::string> receive_sdp();
    
    std::string create_sdp(const IceAttributes& ice_attributese, const std::vector<std::string>& candidates);
    
    std::tuple<IceAttributes, std::vector<Candidate>> parse_sdp(const std::string& sdp);
    
private:
    asio::io_context& io_context_;
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::resolver resolver_;
    
    // Helper methods for SDP handling
};

#endif // SIGNALING_CLIENT_HPP
