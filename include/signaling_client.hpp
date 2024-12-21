// include/signaling_client.hpp

#ifndef SIGNALING_CLIENT_HPP
#define SIGNALING_CLIENT_HPP

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <string>
#include <vector>

enum class IceMode {
    Full,
    Lite
};

class SignalingClient {
public:
    SignalingClient(asio::io_context& io_context, const std::string& server, uint16_t port);
    ~SignalingClient();

    // Create SDP with ICE attributes
    std::string create_sdp(const std::string& ufrag, const std::string& pwd, const std::vector<std::string>& candidates, IceMode mode = IceMode::Full);

    // Send SDP to remote peer
    asio::awaitable<void> send_sdp(const std::string& sdp);

    // Receive SDP from remote peer
    asio::awaitable<std::string> receive_sdp();

    // Parse SDP and extract ICE attributes
    std::pair<std::string, std::string> parse_sdp(const std::string& sdp, std::vector<std::string>& candidates);

private:
    asio::io_context& io_context_;
    asio::ip::tcp::socket socket_;
};

#endif // SIGNALING_CLIENT_HPP
