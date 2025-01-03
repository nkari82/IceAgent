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

/*
if(mode == IceMode::Lite){
    sdp << "a=ice-options:ice-lite\r\n"; // Include ice-lite option
}
else{
    sdp << "a=ice-options:ice2,trickle\r\n"; // Example ICE options
}
*/

// SDP
// v=: SDP 버전
// o=: 세션의 소유자 및 세션 ID
// s=: 세션 이름
// t=: 세션의 활성 시간
// a=: 속성(attribute)
// m=: 미디어 설명
	
// Create SDP message
std::string SignalingClient::create_sdp(const IceAttributes& attrs, const std::vector<Candidate>& candidates) {
    std::ostringstream sdp;
    sdp << "v=0\r\n";
    sdp << "o=- 0 0 IN IP4 127.0.0.1\r\n"; // Simplified; replace with actual origin
    sdp << "s=-\r\n";
    sdp << "t=0 0\r\n";
	if (!attrs.ufrag.empty())
		sdp << "a=ice-ufrag:" << attrs.ufrag << "\r\n";
	
	if (!attrs.pwd.empty())
		sdp << "a=ice-pwd:" << attrs.pwd << "\r\n";

	if (!attrs.options.empty()) {
        sdp << "a=ice-options:";
        for (auto it = attrs.options.begin(); it != attrs.options.end(); ++it) {
            if (it != attrs.options.begin()) {
                sdp << ",";
            }
            sdp << *it;
        }
        sdp << "\r\n";
	}
		
    for(const auto& cand : candidates){
        sdp << "a=" << cand.to_sdp() << "\r\n";
    }
    // Add ice-controlling or ice-controlled based on role
    if (attrs.controlling_role == IceRole::Controller) {
         sdp << "a=ice-controlling:" << attrs.tie_breaker << "\r\n";
    }
    else if (attrs.controlling_role == IceRole::Controlled) {
        sdp << "a=ice-controlled:" << attrs.tie_breaker << "\r\n";
    }
    return sdp.str();
}

// Parse SDP message
std::tuple<IceAttributes, std::vector<std::string>> SignalingClient::parse_sdp(const std::string& sdp) {
    std::istringstream iss(sdp);
    std::string line;
	IceAttributes attrs;
	std::vector<Candidate> candidates

	while (std::getline(iss, line)) {
        if (line.find("a=ice-ufrag:") == 0) {
            attrs.ufrag = line.substr(11);
        }
        else if (line.find("a=ice-pwd:") == 0) {
            attrs.pwd = line.substr(10);
        }
        else if (line.find("a=ice-options:") == 0) {
            std::string options = line.substr(14);
			std::istringstream iss(options);
            std::string option;
			while (std::getline(iss, option, ',')) {
				attrs.options.insert(option);
            }
        }
        else if (line.find("a=ice-controlling:") == 0) {
           attrs.tie_breaker = std::stoull(line.substr(18));
           attrs.role = IceRole::Controller;
        }
        else if (line.find("a=ice-controlled:") == 0) {
           attrs.tie_breaker = std::stoull(line.substr(17));
           attrs.role = IceRole::Controlled;
        }
        else if (line.find("a=candidate:") == 0) {
            candidates.push_back(Candidate::from_sdp(line));
        }
    }
	
    return {attrs, candidates};
}
