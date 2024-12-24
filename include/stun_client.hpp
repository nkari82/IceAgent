#pragma once

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <functional>
#include <memory>
#include <vector>
#include <string>
#include <random>
#include <stdexcept>
#include <iostream>
#include "stun_message.hpp" // STUN 메시지 관련 클래스 및 정의 포함

// -------------------- STUN CLIENT --------------------
class StunClient : public std::enable_shared_from_this<StunClient> {
public:
    // 생성자
    StunClient(asio::strand<asio::io_context::executor_type> strand,
               const std::string& server_host,
               uint16_t server_port,
               const std::string& username = "")
        : strand_(strand),
          resolver_(strand_),
          socket_(strand_),
          server_host_(server_host),
          server_port_(server_port),
          username_(username)
    {
        // 소켓 열기 (IPv4)
        std::error_code ec;
        socket_.open(asio::ip::udp::v4(), ec);
        if (ec) {
            log(LogLevel::ERROR, "Failed to open UDP socket: " + ec.message());
            throw std::runtime_error("Failed to open UDP socket: " + ec.message());
        }
    }

    ~StunClient() {
        std::error_code ec;
        socket_.close(ec);
    }

    // 바인딩 요청을 보내고 매핑된 엔드포인트를 반환
    asio::awaitable<asio::ip::udp::endpoint> send_binding_request() {
        try {
            // STUN 서버 주소 해석
            auto endpoints = co_await resolver_.async_resolve(server_host_, std::to_string(server_port_), asio::use_awaitable);
            asio::ip::udp::endpoint server_endpoint = *endpoints.begin();

            // 바인딩 요청 메시지 생성
            StunMessage binding_request(StunMessageType::BINDING_REQUEST, generate_transaction_id());
            if (!username_.empty()) {
                binding_request.add_attribute(StunAttributeType::USERNAME, username_);
            }
            binding_request.add_fingerprint();

            std::vector<uint8_t> request_data = binding_request.serialize();

            // 트랜잭션 ID 저장 (응답 확인용)
            transaction_id_ = binding_request.get_transaction_id();

            // 요청 전송
            co_await socket_.async_send_to(asio::buffer(request_data), server_endpoint, asio::use_awaitable);

            // 응답 대기
            asio::steady_timer timer(strand_);
            timer.expires_after(std::chrono::milliseconds(3000)); // 타임아웃 설정 (예: 3초)

            std::vector<uint8_t> recv_buffer(2048);
            asio::ip::udp::endpoint sender_endpoint;

            // 응답 받기 또는 타임아웃 발생을 기다림
            auto [ec, bytes_transferred] = co_await (
                socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable)
                || timer.async_wait(asio::use_awaitable)
            );

            if (ec == asio::error::operation_aborted) {
                throw std::runtime_error("STUN binding request timed out");
            } else if (ec) {
                throw asio::system_error(ec);
            }

            recv_buffer.resize(bytes_transferred);

            // STUN 메시지 파싱
            StunMessage response = StunMessage::parse(recv_buffer);

            // 응답 타입 확인
            if (response.get_type() != StunMessageType::BINDING_RESPONSE_SUCCESS) {
                throw std::runtime_error("Invalid STUN response type");
            }

            // 트랜잭션 ID 확인
            if (response.get_transaction_id() != transaction_id_) {
                throw std::runtime_error("Mismatched STUN transaction ID");
            }

            // 매핑된 엔드포인트 추출
            asio::ip::udp::endpoint mapped_endpoint = extract_mapped_endpoint(response, sender_endpoint);

            co_return mapped_endpoint;
        }
        catch (const std::exception& ex) {
            log(LogLevel::ERROR, std::string("STUN binding request failed: ") + ex.what());
            throw; // 예외를 다시 던져 호출자에게 알림
        }
    }

private:
    // 내부 멤버 변수
    asio::strand<asio::io_context::executor_type> strand_;
    asio::ip::udp::resolver resolver_;
    asio::ip::udp::socket socket_;
    std::string server_host_;
    uint16_t server_port_;
    std::string username_;
    std::vector<uint8_t> transaction_id_;

    // 매핑된 엔드포인트 추출
    asio::ip::udp::endpoint extract_mapped_endpoint(const StunMessage& response, const asio::ip::udp::endpoint& sender) {
        // XOR-MAPPED-ADDRESS 속성 추출
        if (response.has_attribute(StunAttributeType::XOR_MAPPED_ADDRESS)) {
            auto xor_mapped = response.get_attribute_as_xor_mapped_address(StunAttributeType::XOR_MAPPED_ADDRESS, sender);
            return xor_mapped;
        }
        // MAPPED-ADDRESS 속성 추출 (XOR 적용되지 않은 경우)
        else if (response.has_attribute(StunAttributeType::MAPPED_ADDRESS)) {
            auto mapped = response.get_attribute_as_mapped_address(StunAttributeType::MAPPED_ADDRESS);
            return mapped;
        }
        else {
            throw std::runtime_error("STUN response does not contain MAPPED-ADDRESS");
        }
    }

    // 트랜잭션 ID 생성 (16바이트)
    std::vector<uint8_t> generate_transaction_id() {
        std::vector<uint8_t> txn_id(16);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& byte : txn_id) {
            byte = static_cast<uint8_t>(dis(gen));
        }
        return txn_id;
    }

    // 로깅 함수
    enum class LogLevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    void log(LogLevel lvl, const std::string& msg) {
        // 로깅 레벨 필터링 (필요 시 조정)
        if (lvl < LogLevel::INFO) return;

        std::string level_str;
        switch (lvl) {
            case LogLevel::DEBUG: level_str = "DEBUG"; break;
            case LogLevel::INFO: level_str = "INFO"; break;
            case LogLevel::WARNING: level_str = "WARNING"; break;
            case LogLevel::ERROR: level_str = "ERROR"; break;
            default: level_str = "UNKNOWN"; break;
        }

        std::cout << "[StunClient][" << level_str << "] " << msg << std::endl;
    }
};
