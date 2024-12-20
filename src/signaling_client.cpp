// src/signaling_client.cpp

#include "signaling_client.hpp"
#include "ice_agent.hpp"
#include <iostream>

// Constructor
SignalingClient::SignalingClient(asio::io_context& io_context, const std::string& uri, std::shared_ptr<IceAgent> ice_agent)
    : ws_client_(), uri_(uri), io_context_(io_context), ice_agent_(ice_agent) {
    ws_client_.init_asio(&io_context_);
    ws_client_.set_open_handler(std::bind(&SignalingClient::on_open, this, std::placeholders::_1));
    ws_client_.set_message_handler(std::bind(&SignalingClient::on_message, this, std::placeholders::_1, std::placeholders::_2));
    ws_client_.set_fail_handler(std::bind(&SignalingClient::on_fail, this, std::placeholders::_1));
}

// Connect to signaling server
void SignalingClient::connect() {
    websocketpp::lib::error_code ec;
    auto con = ws_client_.get_connection(uri_, ec);
    if (ec) {
        ice_agent_->log(LogLevel::ERROR, "Connection error: " + ec.message());
        return;
    }
    ws_client_.connect(con);
}

// Run the WebSocket client
void SignalingClient::run() {
    ws_client_.run();
}

// Send message to signaling server
void SignalingClient::send_message(const std::string& message) {
    if (connection_.expired()) return;
    ws_client_.send(connection_, message, websocketpp::frame::opcode::text);
}

// Handle message received from signaling server
void SignalingClient::on_message(websocketpp::connection_hdl hdl, WebSocketClient::message_ptr msg) {
    std::string payload = msg->get_payload();
    ice_agent_->log(LogLevel::INFO, "Received message: " + payload);

    json data = json::parse(payload);

    if (data.contains("action")) {
        std::string action = data["action"];
        if (action == "ready_to_punch") {
            // Handle UDP Hole Punching synchronization signal
            ice_agent_->log(LogLevel::INFO, "Received ready_to_punch signal.");
            // Actual synchronization logic should be implemented here
        } else if (action == "restart_ice") {
            ice_agent_->on_receive_restart_signal();
        }
    }

    // Handle Candidate Exchange
    if (data.contains("endpoint")) {
        std::string endpoint_str = data["endpoint"];
        size_t colon = endpoint_str.find(':');
        if (colon != std::string::npos) {
            std::string ip = endpoint_str.substr(0, colon);
            int port = std::stoi(endpoint_str.substr(colon + 1));
            Candidate candidate;
            candidate.endpoint = asio::ip::udp::endpoint(asio::ip::address::from_string(ip), port);
            candidate.priority = data.value("priority", 1000);
            candidate.type = data.value("type", "host");

            ice_agent_->add_remote_candidate(candidate);
            ice_agent_->log(LogLevel::INFO, "Added remote candidate from signaling: " + endpoint_str);
        }
    }
}

// Handle WebSocket open
void SignalingClient::on_open(websocketpp::connection_hdl hdl) {
    connection_ = hdl;
    ice_agent_->log(LogLevel::INFO, "Connected to signaling server");
}

// Handle WebSocket failure
void SignalingClient::on_fail(websocketpp::connection_hdl hdl) {
    ice_agent_->log(LogLevel::ERROR, "Connection to signaling server failed");
}
