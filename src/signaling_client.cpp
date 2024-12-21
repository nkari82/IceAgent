// src/signaling_client.cpp

#include "signaling_client.hpp"
#include <stdexcept>
#include <sstream>
#include <algorithm>

// Constructor
SignalingClient::SignalingClient(asio::io_context& io_context, const std::string& server, uint16_t port)
    : io_context_(io_context), socket_(io_context) {
    asio::ip::tcp::resolver resolver(io_context_);
    auto endpoints = resolver.resolve(server, std::to_string(port));
    asio::connect(socket_, endpoints);
}

// Destructor
SignalingClient::~SignalingClient() {
    std::error_code ec;
    socket_.close(ec);
}

// Create SDP with ICE attributes
std::string SignalingClient::create_sdp(const std::string& ufrag, const std::string& pwd, const std::vector<std::string>& candidates, IceMode mode) {
    std::string sdp = "v=0\r\n"
                      "o=- 0 0 IN IP4 127.0.0.1\r\n"
                      "s=ICE Agent\r\n"
                      "c=IN IP4 0.0.0.0\r\n"
                      "t=0 0\r\n"
                      "a=ice-ufrag:" + ufrag + "\r\n" +
                      "a=ice-pwd:" + pwd + "\r\n";

    // ICE Mode 설정
    if (mode == IceMode::Lite) {
        sdp += "a=ice-lite\r\n";
    } else {
        // Full ICE의 경우, 역할 협상은 SDP 교환 시 상호 합의에 따라 결정됩니다.
        // 여기서는 기본적으로 a=ice-controlling 또는 a=ice-controlled를 추가하지 않음
    }

    // 후보 추가
    for (const auto& cand : candidates) {
        sdp += cand + "\r\n";
    }

    return sdp;
}

// Send SDP to remote peer
asio::awaitable<void> SignalingClient::send_sdp(const std::string& sdp) {
    // Send SDP length first (uint32_t in network byte order)
    uint32_t sdp_length = htonl(static_cast<uint32_t>(sdp.size()));
    std::vector<uint8_t> buffer;
    buffer.resize(4);
    std::memcpy(buffer.data(), &sdp_length, 4);
    co_await asio::async_write(socket_, asio::buffer(buffer), asio::use_awaitable);

    // Send SDP content
    co_await asio::async_write(socket_, asio::buffer(sdp), asio::use_awaitable);
}

// Receive SDP from remote peer
asio::awaitable<std::string> SignalingClient::receive_sdp() {
    // Receive SDP length first
    std::vector<uint8_t> length_buffer(4);
    co_await asio::async_read(socket_, asio::buffer(length_buffer), asio::use_awaitable);
    uint32_t sdp_length = ntohl(*(reinterpret_cast<uint32_t*>(length_buffer.data())));

    // Receive SDP content
    std::vector<char> sdp_buffer(sdp_length);
    co_await asio::async_read(socket_, asio::buffer(sdp_buffer), asio::use_awaitable);

    return std::string(sdp_buffer.begin(), sdp_buffer.end());
}

// Parse SDP and extract ICE attributes
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
            candidates.push_back(line);
        }
        // 추가적인 ICE 속성 파싱 가능
    }

    return { ufrag, pwd };
}
