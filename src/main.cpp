// src/main.cpp

#include "ice_agent.hpp"
#include "signaling_client.hpp"
#include <asio.hpp>
#include <memory>
#include <iostream>

// Test ICE Agent with Signaling and Restart
awaitable<void> test_ice_with_signaling_and_restart(asio::io_context& io_context) {
    // ICE Agent 생성
    auto controller = std::make_shared<IceAgent>(
        io_context, IceRole::Controller, "stun.l.google.com", "stun2.l.google.com", "turn.example.com");
    auto controlled = std::make_shared<IceAgent>(
        io_context, IceRole::Controlled, "stun.l.google.com", "stun2.l.google.com", "turn.example.com");

    // SignalingClient 생성 및 설정
    auto controller_signaling = std::make_shared<SignalingClient>(io_context, "ws://localhost:8765", controller);
    auto controlled_signaling = std::make_shared<SignalingClient>(io_context, "ws://localhost:8765", controlled);

    controller->set_signaling_client(controller_signaling);
    controlled->set_signaling_client(controlled_signaling);

    // SignalingClient 연결 시작
    asio::post(io_context, [&]() { controller_signaling->connect(); });
    asio::post(io_context, [&]() { controlled_signaling->connect(); });

    // SignalingClient 실행 (비동기)
    asio::post(io_context, [&]() { controller_signaling->run(); });
    asio::post(io_context, [&]() { controlled_signaling->run(); });

    // 상태 변경 콜백 설정
    controller->set_on_state_change_callback([](IceConnectionState state) {
        std::cout << "[Controller State]: " << static_cast<int>(state) << std::endl;
    });

    controlled->set_on_state_change_callback([](IceConnectionState state) {
        std::cout << "[Controlled State]: " << static_cast<int>(state) << std::endl;
    });

    // Candidate 교환 콜백 설정
    controller->set_candidate_callback([controlled](const Candidate& candidate) {
        controller->log(LogLevel::INFO, "Controller sending Candidate: " + candidate.endpoint.address().to_string() + ":" + std::to_string(candidate.endpoint.port()));
        controlled->add_remote_candidate(candidate);
    });

    controlled->set_candidate_callback([controller](const Candidate& candidate) {
        controlled->log(LogLevel::INFO, "Controlled sending Candidate: " + candidate.endpoint.address().to_string() + ":" + std::to_string(candidate.endpoint.port()));
        controller->add_remote_candidate(candidate);
    });

    // 데이터 수신 콜백 설정
    controlled->set_data_callback([](const std::vector<uint8_t>& data, const asio::ip::udp::endpoint& endpoint) {
        std::string message(data.begin(), data.end());
        std::cout << "[Controlled] Received data: " << message << " from " << endpoint << std::endl;
    });

    // ICE Agent 시작
    co_await controller->start();
    co_await controlled->start();

    // ICE Restart 트리거 (예: 10초 후)
    asio::steady_timer restart_timer(io_context, std::chrono::seconds(10));
    restart_timer.async_wait([controller](const asio::error_code& ec) {
        if (!ec) {
            controller->send_restart_signal();
            controller->log(LogLevel::INFO, "ICE Restart triggered.");
        }
    });

    // 데이터 전송 예제 (ICE 연결 후)
    asio::steady_timer send_timer(io_context, std::chrono::seconds(15));
    send_timer.async_wait([controller](const asio::error_code& ec) {
        if (!ec) {
            std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o', '!', '\n'};
            controller->send_data(data);
            controller->log(LogLevel::INFO, "Controller sent data: Hello!");
        }
    });

    // 연결 성공 여부 확인
    asio::steady_timer check_timer(io_context, std::chrono::seconds(20));
    check_timer.async_wait([controller, controlled](const asio::error_code& ec) {
        if (!ec) {
            if (controller->selected_pair_.is_nominated && controlled->selected_pair_.is_nominated) {
                std::cout << "[Test] ICE Connection and Restart Successful!" << std::endl;
            } else {
                std::cerr << "[Test] ICE Connection and Restart Failed!" << std::endl;
            }
        }
    });

    co_return;
}

int main() {
    try {
        asio::io_context io_context;

        asio::co_spawn(io_context, test_ice_with_signaling_and_restart(io_context), asio::detached);

        io_context.run();
    } catch (const std::exception& ex) {
        std::cerr << "Exception in main: " << ex.what() << std::endl;
    }

    return 0;
}
