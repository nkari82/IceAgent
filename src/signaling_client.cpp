// src/signaling_client.cpp

#include "signaling_client.hpp"
#include <iostream>
#include <sstream>

SignalingClient::SignalingClient(asio::io_context& io_context, const std::string& remote_host, uint16_t remote_port, uint16_t local_port)
    : io_context_(io_context),
      socket_(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), local_port)) {
    asio::ip::udp::resolver resolver(io_context_);
    asio::ip::udp::resolver::results_type results = resolver.resolve(remote_host, std::to_string(remote_port));
    remote_endpoint_ = *results.begin();
}

asio::awaitable<void> SignalingClient::send_sdp(const std::string& sdp) {
    co_await socket_.async_send_to(asio::buffer(sdp), remote_endpoint_, asio::use_awaitable);
}

asio::awaitable<std::string> SignalingClient::receive_sdp() {
    std::vector<char> recv_buffer(65536);
    asio::ip::udp::endpoint sender_endpoint;
    size_t bytes_received = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);
    std::string sdp(recv_buffer.data(), bytes_received);
    co_return sdp;
}

void SignalingClient::close() {
    socket_.close();
}

std::string SignalingClient::create_sdp(const std::string& ufrag, const std::string& pwd, const std::vector<std::string>& candidates) {
    std::ostringstream oss;
    oss << "v=0\r\n"
        << "o=- 0 0 IN IP4 " << get_local_ip() << "\r\n"
        << "s=-\r\n"
        << "c=IN IP4 " << get_local_ip() << "\r\n"
        << "t=0 0\r\n"
        << "a=ice-ufrag:" << ufrag << "\r\n"
        << "a=ice-pwd:" << pwd << "\r\n";
    for(const auto& cand : candidates) {
        oss << cand << "\r\n";
    }
    if(role_ == IceRole::Controller) {
        oss << "a=ice-controlling:" << tie_breaker_ << "\r\n";
    } else if(role_ == IceRole::Controlled) {
        oss << "a=ice-controlled:" << tie_breaker_ << "\r\n";
    }
    return oss.str();
}

std::pair<std::string, std::string> SignalingClient::parse_sdp(const std::string& sdp, std::vector<std::string>& candidates) {
    std::istringstream iss(sdp);
    std::string line;
    std::string ufrag;
    std::string pwd;
    while (std::getline(iss, line)) {
        if (line.find("a=ice-ufrag:") == 0) {
            ufrag = line.substr(12);
        }
        else if (line.find("a=ice-pwd:") == 0) {
            pwd = line.substr(10);
        }
        else if (line.find("a=candidate:") == 0) {
            candidates.push_back(line.substr(2)); // Remove 'a='
        }
		// Handle ICE-CONTROLLING and ICE-CONTROLLED if needed
    }
    return {ufrag, pwd};
}
