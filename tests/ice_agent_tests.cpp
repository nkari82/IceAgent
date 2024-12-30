// test/test_ice_agent.cpp

#include <asio.hpp>
#include <ice_agent.hpp>
#include <iostream>
#include <thread>

// Callback functions
void on_state_change(IceConnectionState state) {
    std::cout << "ICE State Changed: " << static_cast<int>(state) << std::endl;
}

void on_candidate(const Candidate &candidate) {
    std::cout << "Candidate gathered: " << candidate.to_sdp() << std::endl;
}

void on_data(const std::vector<uint8_t> &data, const asio::ip::udp::endpoint &sender) {
    std::string msg(data.begin(), data.end());
    std::cout << "Received data from " << sender.address().to_string() << ":" << sender.port() << " - " << msg
              << std::endl;
}

void on_nominate(const CandidatePair &pair) {
    std::cout << "Nominated Pair: " << pair.remote_candidate.to_sdp() << std::endl;
}

int main() {
    try {
        asio::io_context io_context;

        // Initialize Signaling Client
        // 이 테스트에서는 signaling 서버가 필요하므로, 실제 서버를 실행 중이어야 합니다.
        // 또는 로컬에서 간단한 TCP 서버를 실행하여 테스트할 수 있습니다.
        // auto signaling_client = std::make_shared<SignalingClient>(io_context, "127.0.0.1", 5000);

        // Initialize IceAgent
        IceRole role = IceRole::Controller;  // 또는 IceRole::Controlled
        IceMode mode = IceMode::Full;        // 또는 IceMode::Lite
        std::vector<std::string> stun_servers = {"stun.l.google.com:19302"};
        std::vector<std::string> turn_server;  // TURN 서버가 있다면 설정
        std::string turn_username = "";
        std::string turn_password = "";

        auto ice_agent =
            std::make_shared<IceAgent>(io_context, role, mode, stun_servers, turn_server, turn_username, turn_password);

        // Set callbacks
        ice_agent->set_on_state_change_callback(on_state_change);
        ice_agent->set_candidate_callback(on_candidate);
        ice_agent->set_data_callback(on_data);
        // ice_agent->set_nat_type_callback(on_nat_type_detected);
        ice_agent->set_nominate_callback(on_nominate);
        // ice_agent->set_signaling_client(signaling_client);

        // Set log level
        ice_agent->set_log_level(LogLevel::Debug);

        // Start ICE process
        ice_agent->start();

        // Run io_context in separate thread
        std::thread io_thread0([&io_context]() { io_context.run(); });
        std::thread io_thread1([&io_context]() { io_context.run(); });

        // Keep the main thread alive
        io_thread0.join();
        io_thread1.join();
    } catch (const std::exception &ex) {
        std::cerr << "Exception in main: " << ex.what() << std::endl;
    }

    return 0;
}
