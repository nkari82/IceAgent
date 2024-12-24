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
#include <unordered_map>
#include "stun_message.hpp" // STUN 메시지 관련 클래스 및 정의 포함

// -------------------- ENUMS / CONSTANTS --------------------

// TURN Message Types (RFC 5766)
enum class TurnMessageType : uint16_t {
    ALLOCATE_REQUEST = 0x0003,
    ALLOCATE_SUCCESS_RESPONSE = 0x0103,
    ALLOCATE_ERROR_RESPONSE = 0x0113,
    REFRESH_REQUEST = 0x0004,
    REFRESH_SUCCESS_RESPONSE = 0x0104,
    REFRESH_ERROR_RESPONSE = 0x0114,
    SEND_INDICATION = 0x0016,
    DATA_INDICATION = 0x0117,
    CREATE_PERMISSION_REQUEST = 0x0008,
    CREATE_PERMISSION_SUCCESS_RESPONSE = 0x0108,
    CREATE_PERMISSION_ERROR_RESPONSE = 0x0118,
    // Add more types as needed
};

// TURN Attribute Types (RFC 5766)
enum class TurnAttributeType : uint16_t {
    LIFETIME = 0x000D,
    XOR_RELAYED_ADDRESS = 0x0016,
    DATA = 0x0012,
    XOR_PEER_ADDRESS = 0x0012, // Mapping to STUNAttributeType::XOR_PEER_ADDRESS
    // Add more attributes as needed
};

// TURN Magic Cookie (Same as STUN)
constexpr uint32_t TURN_MAGIC_COOKIE = 0x2112A442;

// Helper functions for byte order conversions
inline uint16_t htons_custom(uint16_t hostshort) {
    return htons(hostshort);
}

inline uint16_t ntohs_custom(uint16_t netshort) {
    return ntohs(netshort);
}

inline uint32_t htonl_custom(uint32_t hostlong) {
    return htonl(hostlong);
}

inline uint32_t ntohl_custom(uint32_t netlong) {
    return ntohl(netlong);
}

inline uint64_t htonll_custom(uint64_t hostlonglong) {
    // Convert host byte order to network byte order (big endian)
    uint64_t net = 0;
    for(int i = 0; i < 8; ++i){
        net = (net << 8) | ((hostlonglong >> (56 - 8*i)) & 0xFF);
    }
    return net;
}

inline uint64_t ntohll_custom(uint64_t netlonglong) {
    // Convert network byte order to host byte order (big endian)
    uint64_t host = 0;
    for(int i = 0; i < 8; ++i){
        host = (host << 8) | ((netlonglong >> (56 - 8*i)) & 0xFF);
    }
    return host;
}

// -------------------- TURN CLIENT --------------------
class TurnClient : public std::enable_shared_from_this<TurnClient> {
public:
    // 생성자
    TurnClient(asio::strand<asio::io_context::executor_type> strand,
               const std::string& server_host,
               uint16_t server_port,
               const std::string& username,
               const std::string& password)
        : strand_(strand),
          resolver_(strand_),
          socket_(strand_),
          server_host_(server_host),
          server_port_(server_port),
          username_(username),
          password_(password),
          allocated_(false),
          allocation_lifetime_(600), // 기본 10분
          refresh_timer_(strand_),
          receive_timer_(strand_),
          data_callback_(nullptr),
          send_indication_callback_(nullptr)
    {
        // 소켓 열기 (IPv4 지원)
        std::error_code ec;
        socket_.open(asio::ip::udp::v4(), ec);
        if (ec) {
            log(LogLevel::ERROR, "Failed to open UDP socket (IPv4): " + ec.message());
            throw std::runtime_error("Failed to open UDP socket (IPv4): " + ec.message());
        }

        // IPv6 소켓도 열기 시도 (추후 IPv6 지원 확장 가능)
        asio::ip::udp::socket ipv6_socket(strand_);
        ipv6_socket.open(asio::ip::udp::v6(), ec);
        if (!ec) {
            ipv6_socket.close();
            log(LogLevel::INFO, "IPv6 support is available.");
            // IPv6 소켓 사용을 원할 경우, 별도의 구현 필요
        }
        else {
            log(LogLevel::INFO, "IPv6 support is not available.");
        }
    }

    ~TurnClient() {
        std::error_code ec;
        socket_.close(ec);
        refresh_timer_.cancel(ec);
        receive_timer_.cancel(ec);
    }

    // 할당 요청을 보내고 릴레이된 엔드포인트를 반환
    asio::awaitable<asio::ip::udp::endpoint> allocate_relay() {
        if (allocated_) {
            co_return relay_endpoint_;
        }

        try {
            // STUN/TURN 서버 주소 해석
            auto endpoints = co_await resolver_.async_resolve(server_host_, std::to_string(server_port_), asio::use_awaitable);
            asio::ip::udp::endpoint server_endpoint = *endpoints.begin();

            // ALLOCATE 요청 메시지 생성
            StunMessage allocate_request(StunMessageType::ALLOCATE_REQUEST, StunMessage::generate_transaction_id());

            // USERNAME 및 MESSAGE-INTEGRITY 추가 (Long-Term Credential Mechanism)
            allocate_request.add_attribute(StunAttributeType::USERNAME, username_);
            allocate_request.add_message_integrity(password_);

            // FINGERPRINT 추가
            allocate_request.add_fingerprint();

            // Serialize 메시지
            std::vector<uint8_t> request_data = allocate_request.serialize();

            // 요청 전송
            co_await socket_.async_send_to(asio::buffer(request_data), server_endpoint, asio::use_awaitable);

            log(LogLevel::DEBUG, "Sent TURN Allocate Request");

            // 응답 대기
            std::vector<uint8_t> recv_buffer(2048);
            asio::ip::udp::endpoint sender_endpoint;

            // 타임아웃 설정 (예: 5초)
            asio::steady_timer timer(strand_);
            timer.expires_after(std::chrono::seconds(5));

            // 응답 받기 또는 타임아웃 발생을 기다림
            auto [ec_res, bytes_transferred] = co_await (
                socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable)
                || timer.async_wait(asio::use_awaitable)
            );

            if (ec_res == asio::error::operation_aborted) {
                throw std::runtime_error("TURN allocate request timed out");
            } else if (ec_res) {
                throw asio::system_error(ec_res);
            }

            recv_buffer.resize(bytes_transferred);

            // STUN 메시지 파싱
            StunMessage response = StunMessage::parse(recv_buffer);

            // 응답 타입 확인
            if (response.get_type() != StunMessageType::ALLOCATE_SUCCESS_RESPONSE) {
                throw std::runtime_error("Invalid TURN Allocate response type");
            }

            // 트랜잭션 ID 확인
            if (response.get_transaction_id() != allocate_request.get_transaction_id()) {
                throw std::runtime_error("Mismatched TURN Allocate transaction ID");
            }

            // LIFETIME 추출
            if (response.has_attribute(StunAttributeType::LIFETIME)) {
                allocation_lifetime_ = response.get_attribute_as_uint32(StunAttributeType::LIFETIME);
            }

            // XOR-RELAYED-ADDRESS 추출
            relay_endpoint_ = extract_xor_relayed_address(response, server_endpoint);
            allocated_ = true;

            log(LogLevel::INFO, "TURN allocation successful. Relay Endpoint: " + relay_endpoint_.address().to_string() + ":" + std::to_string(relay_endpoint_.port()));

            // 할당 갱신 스케줄링
            schedule_refresh();

            // 데이터 수신 시작
            asio::co_spawn(strand_, receive_data(), asio::detached);

            co_return relay_endpoint_;
        }
        catch (const std::exception& ex) {
            log(LogLevel::ERROR, std::string("TURN allocate request failed: ") + ex.what());
            throw; // 예외를 다시 던져 호출자에게 알림
        }
    }

    // 할당 갱신
    asio::awaitable<void> refresh_allocation() {
        if (!allocated_) {
            co_return;
        }

        try {
            // REFRESH 요청 메시지 생성
            StunMessage refresh_request(StunMessageType::REFRESH_REQUEST, StunMessage::generate_transaction_id());

            // USERNAME 및 MESSAGE-INTEGRITY 추가 (Long-Term Credential Mechanism)
            refresh_request.add_attribute(StunAttributeType::USERNAME, username_);
            refresh_request.add_message_integrity(password_);

            // FINGERPRINT 추가
            refresh_request.add_fingerprint();

            // Serialize 메시지
            std::vector<uint8_t> request_data = refresh_request.serialize();

            // 요청 전송
            co_await socket_.async_send_to(asio::buffer(request_data), relay_endpoint_, asio::use_awaitable);

            log(LogLevel::DEBUG, "Sent TURN Refresh Request");

            // 응답 대기
            std::vector<uint8_t> recv_buffer(2048);
            asio::ip::udp::endpoint sender_endpoint;

            // 타임아웃 설정 (예: 5초)
            asio::steady_timer timer(strand_);
            timer.expires_after(std::chrono::seconds(5));

            // 응답 받기 또는 타임아웃 발생을 기다림
            auto [ec_res, bytes_transferred] = co_await (
                socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable)
                || timer.async_wait(asio::use_awaitable)
            );

            if (ec_res == asio::error::operation_aborted) {
                throw std::runtime_error("TURN refresh request timed out");
            } else if (ec_res) {
                throw asio::system_error(ec_res);
            }

            recv_buffer.resize(bytes_transferred);

            // STUN 메시지 파싱
            StunMessage response = StunMessage::parse(recv_buffer);

            // 응답 타입 확인
            if (response.get_type() != StunMessageType::REFRESH_SUCCESS_RESPONSE) {
                throw std::runtime_error("Invalid TURN Refresh response type");
            }

            // 트랜잭션 ID 확인
            if (response.get_transaction_id() != refresh_request.get_transaction_id()) {
                throw std::runtime_error("Mismatched TURN Refresh transaction ID");
            }

            // LIFETIME 갱신
            if (response.has_attribute(StunAttributeType::LIFETIME)) {
                allocation_lifetime_ = response.get_attribute_as_uint32(StunAttributeType::LIFETIME);
            }

            log(LogLevel::INFO, "TURN allocation refreshed. New Lifetime: " + std::to_string(allocation_lifetime_) + " seconds");

            // 할당 갱신 스케줄링
            schedule_refresh();

            co_return;
        }
        catch (const std::exception& ex) {
            log(LogLevel::ERROR, std::string("TURN refresh request failed: ") + ex.what());
            allocated_ = false;
            co_return;
        }
    }

    // 릴레이된 엔드포인트로 데이터 전송
    asio::awaitable<void> send_relayed_data(const std::vector<uint8_t>& data, const asio::ip::udp::endpoint& peer_endpoint) {
        if (!allocated_) {
            throw std::runtime_error("TURN allocation not done");
        }

        try {
            // SEND Indication 메시지 생성
            StunMessage send_indication(StunMessageType::SEND_INDICATION, StunMessage::generate_transaction_id());

            // DATA 속성 추가
            send_indication.add_attribute(StunAttributeType::DATA, data);

            // XOR-PEER-ADDRESS 속성 추가
            send_indication.add_attribute(StunAttributeType::XOR_PEER_ADDRESS, encode_xor_peer_address(peer_endpoint));

            // MESSAGE-INTEGRITY 추가
            send_indication.add_message_integrity(password_);

            // FINGERPRINT 추가
            send_indication.add_fingerprint();

            // Serialize 메시지
            std::vector<uint8_t> request_data = send_indication.serialize();

            // 요청 전송
            co_await socket_.async_send_to(asio::buffer(request_data), relay_endpoint_, asio::use_awaitable);

            log(LogLevel::DEBUG, "Sent relayed data to " + peer_endpoint.address().to_string() + ":" + std::to_string(peer_endpoint.port()));

            co_return;
        }
        catch (const std::exception& ex) {
            log(LogLevel::ERROR, std::string("TURN send relayed data failed: ") + ex.what());
            throw;
        }
    }

    // 권한(permission) 생성
    asio::awaitable<void> create_permission(const asio::ip::udp::endpoint& peer_endpoint) {
        if (!allocated_) {
            throw std::runtime_error("TURN allocation not done");
        }

        try {
            // CREATE_PERMISSION 요청 메시지 생성
            StunMessage create_permission_request(StunMessageType::CREATE_PERMISSION_REQUEST, StunMessage::generate_transaction_id());

            // XOR-PEER-ADDRESS 속성 추가
            create_permission_request.add_attribute(StunAttributeType::XOR_PEER_ADDRESS, encode_xor_peer_address(peer_endpoint));

            // USERNAME 및 MESSAGE-INTEGRITY 추가 (Long-Term Credential Mechanism)
            create_permission_request.add_attribute(StunAttributeType::USERNAME, username_);
            create_permission_request.add_message_integrity(password_);

            // FINGERPRINT 추가
            create_permission_request.add_fingerprint();

            // Serialize 메시지
            std::vector<uint8_t> request_data = create_permission_request.serialize();

            // 요청 전송
            co_await socket_.async_send_to(asio::buffer(request_data), relay_endpoint_, asio::use_awaitable);

            log(LogLevel::DEBUG, "Sent TURN Create Permission Request to " + peer_endpoint.address().to_string() + ":" + std::to_string(peer_endpoint.port()));

            // 응답 대기
            std::vector<uint8_t> recv_buffer(2048);
            asio::ip::udp::endpoint sender_endpoint;

            // 타임아웃 설정 (예: 5초)
            asio::steady_timer timer(strand_);
            timer.expires_after(std::chrono::seconds(5));

            // 응답 받기 또는 타임아웃 발생을 기다림
            auto [ec_res, bytes_transferred] = co_await (
                socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable)
                || timer.async_wait(asio::use_awaitable)
            );

            if (ec_res == asio::error::operation_aborted) {
                throw std::runtime_error("TURN Create Permission request timed out");
            } else if (ec_res) {
                throw asio::system_error(ec_res);
            }

            recv_buffer.resize(bytes_transferred);

            // STUN 메시지 파싱
            StunMessage response = StunMessage::parse(recv_buffer);

            // 응답 타입 확인
            if (response.get_type() != StunMessageType::CREATE_PERMISSION_SUCCESS_RESPONSE) {
                throw std::runtime_error("Invalid TURN Create Permission response type");
            }

            // 트랜잭션 ID 확인
            if (response.get_transaction_id() != create_permission_request.get_transaction_id()) {
                throw std::runtime_error("Mismatched TURN Create Permission transaction ID");
            }

            log(LogLevel::INFO, "TURN permission created for peer: " + peer_endpoint.address().to_string() + ":" + std::to_string(peer_endpoint.port()));

            co_return;
        }
        catch (const std::exception& ex) {
            log(LogLevel::ERROR, std::string("TURN create permission request failed: ") + ex.what());
            throw;
        }
    }

    // 릴레이된 엔드포인트를 반환
    asio::ip::udp::endpoint get_relay_endpoint() const {
        return relay_endpoint_;
    }

    // 할당 상태 확인
    bool is_allocated() const {
        return allocated_;
    }

    // DATA Indication 수신 콜백 설정
    void set_data_callback(std::function<void(const std::vector<uint8_t>&, const asio::ip::udp::endpoint&)> cb) {
        data_callback_ = std::move(cb);
    }

    // SEND Indication 수신 콜백 설정
    void set_send_indication_callback(std::function<void(const std::vector<uint8_t>&, const asio::ip::udp::endpoint&)> cb) {
        send_indication_callback_ = std::move(cb);
    }

private:
    // 내부 멤버 변수
    asio::strand<asio::io_context::executor_type> strand_;
    asio::ip::udp::resolver resolver_;
    asio::ip::udp::socket socket_;
    std::string server_host_;
    uint16_t server_port_;
    std::string username_;
    std::string password_;
    bool allocated_;
    asio::ip::udp::endpoint relay_endpoint_;
    uint32_t allocation_lifetime_; // seconds
    asio::steady_timer refresh_timer_;
    asio::steady_timer receive_timer_;

    // 데이터 수신 콜백
    std::function<void(const std::vector<uint8_t>&, const asio::ip::udp::endpoint&)> data_callback_;

    // SEND Indication 수신 콜백
    std::function<void(const std::vector<uint8_t>&, const asio::ip::udp::endpoint&)> send_indication_callback_;

    // TURN 메시지 로그 레벨
    enum class LogLevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    // 로깅 함수
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

        std::cout << "[TurnClient][" << level_str << "] " << msg << std::endl;
    }

    // XOR-RELAYED-ADDRESS 추출
    asio::ip::udp::endpoint extract_xor_relayed_address(const StunMessage& response, const asio::ip::udp::endpoint& server_endpoint) {
        // XOR-RELAYED-ADDRESS 속성 추출
        if (response.has_attribute(StunAttributeType::XOR_RELAYED_ADDRESS)) {
            auto xor_relayed = response.get_attribute_as_xor_mapped_address(StunAttributeType::XOR_RELAYED_ADDRESS, server_endpoint);
            return xor_relayed;
        }
        else {
            throw std::runtime_error("TURN response does not contain XOR-RELAYED-ADDRESS");
        }
    }

    // XOR-PEER-ADDRESS 인코딩 (RFC 5766 Section 11)
    std::vector<uint8_t> encode_xor_peer_address(const asio::ip::udp::endpoint& peer_endpoint) const {
        std::vector<uint8_t> encoded;

        // FAMILY (1 byte)
        uint8_t family;
        if (peer_endpoint.address().is_v4()) {
            family = 0x01;
        }
        else if (peer_endpoint.address().is_v6()) {
            family = 0x02;
        }
        else {
            throw std::invalid_argument("Unsupported address family for XOR_PEER_ADDRESS");
        }
        encoded.push_back(family);

        // PORT (2 bytes)
        uint16_t port = peer_endpoint.port() ^ (TURN_MAGIC_COOKIE >> 16);
        encoded.push_back((port >> 8) & 0xFF);
        encoded.push_back(port & 0xFF);

        // ADDRESS (variable)
        if (peer_endpoint.address().is_v4()) {
            auto bytes = peer_endpoint.address().to_v4().to_bytes();
            for(int i = 0; i < 4; ++i){
                encoded.push_back(bytes[i] ^ ((TURN_MAGIC_COOKIE >> (24 - 8*i)) & 0xFF));
            }
        }
        else if (peer_endpoint.address().is_v6()) {
            auto bytes = peer_endpoint.address().to_v6().to_bytes();
            // XOR the first 4 bytes with magic cookie
            for(int i = 0; i < 4; ++i){
                encoded.push_back(bytes[i] ^ ((TURN_MAGIC_COOKIE >> (24 - 8*i)) & 0xFF));
            }
            // XOR the rest with Transaction ID
            auto txn_id = get_transaction_id();
            for(int i = 4; i < 16; ++i){
                encoded.push_back(bytes[i] ^ txn_id[i - 4]);
            }
        }

        return encoded;
    }

    // 트랜잭션 ID 추출 (내부적으로 관리)
    std::array<uint8_t, 12> get_transaction_id() const {
        // 현재 구현에서는 마지막 Allocate 요청의 트랜잭션 ID를 사용
        // 필요 시 별도의 관리 로직을 추가
        // 여기서는 예시로 12바이트의 0을 반환
        std::array<uint8_t, 12> txn_id;
        txn_id.fill(0);
        return txn_id;
    }

    // 할당 갱신 스케줄링
    void schedule_refresh() {
        // 갱신은 할당 수명 전 10초에 수행
        auto refresh_time = std::chrono::seconds(allocation_lifetime_ - 10);
        if (refresh_time.count() <= 0) {
            refresh_time = std::chrono::seconds(allocation_lifetime_ / 2);
        }

        refresh_timer_.expires_after(refresh_time);
        refresh_timer_.async_wait(asio::bind_executor(strand_,
            [self = shared_from_this()](const std::error_code& ec){
                if (!ec) {
                    asio::co_spawn(self->strand_,
                        [self]() -> asio::awaitable<void> {
                            co_await self->refresh_allocation();
                        }, asio::detached
                    );
                }
                else {
                    // 타이머 취소 또는 오류 처리
                    self->log(LogLevel::ERROR, "Refresh timer error: " + ec.message());
                }
            }
        ));
    }

    // 데이터 수신 처리
    asio::awaitable<void> receive_data() {
        while (allocated_) {
            try {
                std::vector<uint8_t> recv_buffer(4096);
                asio::ip::udp::endpoint sender_endpoint;

                // 데이터 수신 (비동기)
                std::size_t bytes_transferred = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);

                recv_buffer.resize(bytes_transferred);

                // STUN 메시지 파싱
                StunMessage message = StunMessage::parse(recv_buffer);

                // 메시지 타입 확인
                switch (message.get_type()) {
                    case StunMessageType::DATA_INDICATION: {
                        // DATA 속성 추출
                        if (message.has_attribute(StunAttributeType::DATA)) {
                            std::vector<uint8_t> data = message.get_attribute_as_data(StunAttributeType::DATA);
                            
                            // 상대방의 엔드포인트 추출 (XOR-PEER-ADDRESS)
                            asio::ip::udp::endpoint peer_endpoint;
                            if (message.has_attribute(StunAttributeType::XOR_PEER_ADDRESS)) {
                                peer_endpoint = message.get_attribute_as_xor_mapped_address(StunAttributeType::XOR_PEER_ADDRESS, relay_endpoint_);
                            }
                            else {
                                // Fallback to sender's endpoint if XOR_PEER_ADDRESS is not present
                                peer_endpoint = sender_endpoint;
                            }

                            // 데이터 콜백 호출
                            if (data_callback_) {
                                data_callback_(data, peer_endpoint);
                            }

                            log(LogLevel::DEBUG, "Received DATA Indication from " + peer_endpoint.address().to_string() + ":" + std::to_string(peer_endpoint.port()));
                        }
                        break;
                    }
                    case StunMessageType::SEND_INDICATION: {
                        // SEND Indication 처리
                        if (message.has_attribute(StunAttributeType::DATA) && message.has_attribute(StunAttributeType::XOR_PEER_ADDRESS)) {
                            std::vector<uint8_t> data = message.get_attribute_as_data(StunAttributeType::DATA);
                            asio::ip::udp::endpoint peer_endpoint = message.get_attribute_as_xor_mapped_address(StunAttributeType::XOR_PEER_ADDRESS, relay_endpoint_);

                            // SEND Indication 콜백 호출
                            if (send_indication_callback_) {
                                send_indication_callback_(data, peer_endpoint);
                            }

                            log(LogLevel::DEBUG, "Received SEND Indication from " + peer_endpoint.address().to_string() + ":" + std::to_string(peer_endpoint.port()));
                        }
                        else {
                            log(LogLevel::WARNING, "Received malformed SEND Indication message.");
                        }
                        break;
                    }
                    default: {
                        // 기타 메시지 처리 (필요 시 구현)
                        log(LogLevel::WARNING, "Received unsupported TURN message type: " + std::to_string(static_cast<uint16_t>(message.get_type())));
                        break;
                    }
                }
            }
            catch (const std::exception& ex) {
                log(LogLevel::ERROR, std::string("TURN receive data failed: ") + ex.what());
                // 필요 시, 할당 상태를 해제하거나 재시도 로직을 추가
                allocated_ = false;
                break;
            }
        }

        co_return;
    }
};

// -------------------- STUN MESSAGE 확장 --------------------

// StunMessage 클래스에 DATA 속성 추출 메서드 추가
inline std::vector<uint8_t> StunMessage::get_attribute_as_data(StunAttributeType attr_type) const {
    for(const auto& attr : attributes_){
        if(attr.type == attr_type){
            return attr.value;
        }
    }
    throw std::invalid_argument("DATA attribute not found");
}
