// src/signaling_client.cpp

#include "signaling_client.hpp"
#include <stdexcept>
#include <sstream>

// Constructor
SignalingClient::SignalingClient(asio::io_context& io_context, const std::string& signaling_server, uint16_t port)
    : io_context_(io_context), resolver_(io_context), socket_(io_context)
{
    // 비동기 연결을 위해 코루틴 내에서 처리
    asio::co_spawn(io_context_, [this, signaling_server, port]() -> asio::awaitable<void> {
        try {
            asio::ip::tcp::resolver::results_type endpoints = co_await resolver_.async_resolve(signaling_server, std::to_string(port), asio::use_awaitable);
            co_await asio::async_connect(socket_, endpoints, asio::use_awaitable);
        } catch (const std::exception& ex) {
            throw std::runtime_error(std::string("SignalingClient connection failed: ") + ex.what());
        }
    }, asio::detached);
}

// Send SDP message
asio::awaitable<void> SignalingClient::send_sdp(const std::string& sdp) {
    // 간단한 구현: SDP 길이를 먼저 전송한 후 SDP 데이터 전송
    uint32_t length = static_cast<uint32_t>(sdp.size());
    std::vector<uint8_t> header = {
        static_cast<uint8_t>((length >> 24) & 0xFF),
        static_cast<uint8_t>((length >> 16) & 0xFF),
        static_cast<uint8_t>((length >> 8) & 0xFF),
        static_cast<uint8_t>(length & 0xFF)
    };
    co_await asio::async_write(socket_, asio::buffer(header), asio::use_awaitable);
    co_await asio::async_write(socket_, asio::buffer(sdp), asio::use_awaitable);
}

// Receive SDP message
asio::awaitable<std::string> SignalingClient::receive_sdp() {
    // 간단한 구현: 먼저 SDP 길이를 수신한 후 SDP 데이터 수신
    std::vector<uint8_t> header(4);
    co_await asio::async_read(socket_, asio::buffer(header), asio::use_awaitable);
    uint32_t length = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
    std::vector<char> sdp_data(length);
    co_await asio::async_read(socket_, asio::buffer(sdp_data), asio::use_awaitable);
    return std::string(sdp_data.begin(), sdp_data.end());
}

// Create SDP message
std::string SignalingClient::create_sdp(const std::string& username_fragment, const std::string& password, const std::vector<std::string>& candidates, IceMode mode) {
    std::ostringstream sdp;
    sdp << "v=0\r\n";
    sdp << "o=- 0 0 IN IP4 127.0.0.1\r\n";
    sdp << "s=-\r\n";
    sdp << "t=0 0\r\n";
    sdp << "a=ice-ufrag:" << username_fragment << "\r\n";
    sdp << "a=ice-pwd:" << password << "\r\n";
    if(mode == IceMode::Full){
        sdp << "a=ice-options:ice2,trickle\r\n";
    }
    for(const auto& cand : candidates){
        sdp << cand << "\r\n";
    }
    return sdp.str();
}

// Parse SDP message
std::pair<std::string, std::string> SignalingClient::parse_sdp(const std::string& sdp, std::vector<std::string>& candidates) {
    std::istringstream iss(sdp);
    std::string line;
    std::string ufrag;
    std::string pwd;
    while(std::getline(iss, line)) {
        if(line.find("a=ice-ufrag:") == 0){
            ufrag = line.substr(12);
        }
        else if(line.find("a=ice-pwd:") == 0){
            pwd = line.substr(10);
        }
        else if(line.find("a=candidate:") == 0){
            candidates.push_back(line);
        }
    }
    return {ufrag, pwd};
}
