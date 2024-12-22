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
    /**
     * @brief Constructs a SignalingClient with the specified signaling server.
     * 
     * @param io_context The ASIO io_context.
     * @param signaling_server The signaling server hostname or IP address.
     * @param port The signaling server port.
     */
    SignalingClient(asio::io_context& io_context, const std::string& signaling_server, uint16_t port);
    
    /**
     * @brief Sends an SDP message to the signaling server.
     * 
     * @param sdp The SDP message to send.
     */
    asio::awaitable<void> send_sdp(const std::string& sdp);
    
    /**
     * @brief Receives an SDP message from the signaling server.
     * 
     * @return asio::awaitable<std::string> The received SDP message.
     */
    asio::awaitable<std::string> receive_sdp();
    
    /**
     * @brief Creates an SDP message with the provided ICE parameters.
     * 
     * @param username_fragment The ICE username fragment.
     * @param password The ICE password.
     * @param candidates The list of ICE candidates.
     * @param mode The ICE mode (Full or Lite).
     * @return std::string The constructed SDP message.
     */
    std::string create_sdp(const std::string& username_fragment, const std::string& password, const std::vector<std::string>& candidates, IceMode mode);
    
    /**
     * @brief Parses an SDP message to extract ICE parameters.
     * 
     * @param sdp The SDP message to parse.
     * @param candidates Reference to a vector to store extracted candidates.
     * @return std::pair<std::string, std::string> A pair containing ICE username fragment and password.
     */
    std::pair<std::string, std::string> parse_sdp(const std::string& sdp, std::vector<std::string>& candidates);
    
private:
    asio::io_context& io_context_;
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::resolver resolver_;
    
    // Helper methods for SDP handling
};

#endif // SIGNALING_CLIENT_HPP
