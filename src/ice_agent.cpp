// src/ice_agent.cpp

#include "ice_agent.hpp"
#include <iostream>
#include <thread>
#include <cstdlib>

// Constructor
IceAgent::IceAgent(asio::io_context& io_context, IceRole role, IceMode mode,
                   const std::vector<std::string>& stun_servers, 
                   const std::string& turn_server,
                   const std::string& turn_username, 
                   const std::string& turn_password)
    : io_context_(io_context), 
      socket_(io_context, asio::ip::udp::v4()), 
      role_(role), 
      mode_(mode),
      stun_servers_(stun_servers), 
      turn_server_(turn_server),
      turn_username_(turn_username),
      turn_password_(turn_password),
      current_state_(IceConnectionState::New), 
      keep_alive_timer_(io_context),
      log_level_(LogLevel::INFO),
      connectivity_checks_running_(false) {
    // Initialize StunClients for each STUN server
    for (const auto& server : stun_servers_) {
        size_t colon_pos = server.find(':');
        if (colon_pos == std::string::npos) {
            log(LogLevel::WARNING, "Invalid STUN server address: " + server);
            continue;
        }
        std::string host = server.substr(0, colon_pos);
        uint16_t port = static_cast<uint16_t>(std::stoi(server.substr(colon_pos + 1)));
        auto stun_client = std::make_shared<StunClient>(io_context_, host, port, ""); // Provide key if needed
        stun_clients_.push_back(stun_client);
    }

    // Initialize TurnClient if TURN server is provided
    if (!turn_server_.empty()) {
        size_t colon_pos = turn_server_.find(':');
        if (colon_pos == std::string::npos) {
            log(LogLevel::WARNING, "Invalid TURN server address: " + turn_server_);
        }
        else {
            std::string host = turn_server_.substr(0, colon_pos);
            uint16_t port = static_cast<uint16_t>(std::stoi(turn_server_.substr(colon_pos + 1)));
            turn_client_ = std::make_shared<TurnClient>(io_context_, host, port, turn_username_, turn_password_);
        }
    }
}

// Setters for callbacks
void IceAgent::set_on_state_change_callback(StateCallback callback) {
    state_callback_ = std::move(callback);
}

void IceAgent::set_candidate_callback(CandidateCallback callback) {
    candidate_callback_ = std::move(callback);
}

void IceAgent::set_data_callback(DataCallback callback) {
    data_callback_ = std::move(callback);
}

void IceAgent::set_nat_type_callback(NatTypeCallback cb) {
    on_nat_type_detected_ = cb;
}

void IceAgent::set_signaling_client(std::shared_ptr<SignalingClient> signaling_client) {
    signaling_client_ = signaling_client;
}

// Set log level
void IceAgent::set_log_level(LogLevel level) {
    log_level_ = level;
}

// Logging function
void IceAgent::log(LogLevel level, const std::string& message) {
    if (level >= log_level_) {
        switch (level) {
            case LogLevel::DEBUG:
                std::cout << "[DEBUG] ";
                break;
            case LogLevel::INFO:
                std::cout << "[INFO] ";
                break;
            case LogLevel::WARNING:
                std::cout << "[WARNING] ";
                break;
            case LogLevel::ERROR:
                std::cout << "[ERROR] ";
                break;
        }
        std::cout << message << std::endl;
    }
}

// Start ICE process
asio::awaitable<void> IceAgent::start() {
    if (!transition_to_state(IceConnectionState::Gathering)) {
        co_return;
    }

    try {
        // Step 1: Detect NAT Type
        NatType nat_type = co_await detect_nat_type();

        // Notify via callback
        if (on_nat_type_detected_) {
            on_nat_type_detected_(nat_type);
        }
        
        // Step 2: Gather Candidates
        co_await gather_candidates();

        // NAT Type Based Candidate Gathering
        switch (nat_type) {
            case NatType::FullCone:
            case NatType::RestrictedCone:
            case NatType::PortRestrictedCone:
                // These NAT types generally allow for successful peer-to-peer connections.
                // Prioritize gathering server reflexive (srflx) candidates.
                log(LogLevel::INFO, "Detected NAT type supports direct peer-to-peer connections. Gathering srflx candidates.");
                co_await gather_srflx_candidates();
                break;
            case NatType::Symmetric:
                // Symmetric NATs may require relay candidates via TURN.
                log(LogLevel::INFO, "Detected Symmetric NAT. Gathering relay candidates via TURN.");
                if (turn_client_) {
                    co_await gather_relay_candidates();
                } else {
                    log(LogLevel::WARNING, "TURN server not configured. Relay candidates cannot be gathered.");
                }
                break;
            case NatType::OpenInternet:
                // No NAT; direct connections are straightforward.
                log(LogLevel::INFO, "No NAT detected. Direct peer-to-peer connections are straightforward.");
                break;
            default:
                log(LogLevel::WARNING, "Unknown NAT type. Proceeding with default candidate gathering.");
                break;
        }

        if (!transition_to_state(IceConnectionState::Checking)) {
            co_return;
        }

        // Perform connectivity checks
        co_await perform_connectivity_checks();
        
        if (current_state_ == IceConnectionState::Connected) { // Corrected condition
            // Spawn perform_keep_alive coroutine
            co_spawn(io_context_, perform_keep_alive(), asio::detached);
        
            // Spawn perform_turn_refresh coroutine if TURN is used
            if (turn_client_ && turn_client_->is_allocated()) {
                co_spawn(io_context_, perform_turn_refresh(), asio::detached);
            }

            // Start data reception
            asio::co_spawn(io_context_, start_data_receive(), asio::detached);
        }
    } catch (const std::exception& ex) {
        log(LogLevel::ERROR, "Exception in ICE Agent: " + std::string(ex.what()));
        transition_to_state(IceConnectionState::Failed);
    }
}

// Restart ICE process
asio::awaitable<void> IceAgent::restart_ice() {
    if (mode_ == IceMode::Lite) {
        log(LogLevel::WARNING, "ICE Restart is not supported in ICE Lite mode.");
        co_return;
    }

    log(LogLevel::INFO, "Restarting ICE process...");

    // Reset state
    current_state_ = IceConnectionState::New;
    selected_pair_ = CandidatePair();
    candidate_pairs_.clear();
    remote_candidates_.clear();
    log(LogLevel::INFO, "ICE state reset.");

    // Restart ICE process
    co_await start();
}

// Send data over established connection
void IceAgent::send_data(const std::vector<uint8_t>& data) {
    if (current_state_ != IceConnectionState::Connected || !selected_pair_.is_nominated) {
        log(LogLevel::WARNING, "Cannot send data. Connection not established.");
        return;
    }

    asio::co_spawn(io_context_, [this, data]() -> asio::awaitable<void> {
        try {
            co_await socket_.async_send_to(asio::buffer(data), selected_pair_.remote_candidate.endpoint, asio::use_awaitable);
            log(LogLevel::INFO, "Data sent successfully.");
        } catch (const std::exception& ex) {
            log(LogLevel::ERROR, "Failed to send data: " + std::string(ex.what()));
        }
    }, asio::detached);
}

// Add remote candidate received via signaling
void IceAgent::add_remote_candidate(const Candidate& candidate) {
    remote_candidates_.push_back(candidate);
    log(LogLevel::INFO, "Added remote candidate: " + candidate.type + " - " +
        candidate.endpoint.address().to_string() + ":" + std::to_string(candidate.endpoint.port()));

    // Notify via callback
    if (candidate_callback_) {
        candidate_callback_(candidate);
    }

    // Create Candidate Pairs
    for (const auto& local : local_candidates_) {
        CandidatePair pair;
        pair.local_candidate = local;
        pair.remote_candidate = candidate;
        pair.priority = calculate_priority(local, candidate);
        candidate_pairs_.push_back(pair);
    }

    // Perform connectivity checks if not already running
    if (!connectivity_checks_running_) {
        connectivity_checks_running_ = true;
        asio::co_spawn(io_context_, [this]() -> asio::awaitable<void> {
            co_await perform_connectivity_checks();
            connectivity_checks_running_ = false;
        }, asio::detached);
    }
}

// Convert NatType to string
std::string IceAgent::nat_type_to_string(NatType nat_type) const {
    switch (nat_type) {
        case NatType::Unknown: return "Unknown";
        case NatType::OpenInternet: return "Open Internet";
        case NatType::FullCone: return "Full Cone NAT";
        case NatType::RestrictedCone: return "Restricted Cone NAT";
        case NatType::PortRestrictedCone: return "Port Restricted Cone NAT";
        case NatType::Symmetric: return "Symmetric NAT";
        default: return "Invalid NAT Type";
    }
}

// Calculate priority based on RFC 8445
uint64_t IceAgent::calculate_priority(const Candidate& local, const Candidate& remote) const {
    // RFC 8445 Priority Calculation
    // priority = (2^24)*(type preference) + (2^8)*(local preference) + (2^0)*(256 - local component ID)
    // For simplicity, using existing priority values
    return (static_cast<uint64_t>(std::min(local.priority, remote.priority)) << 32) +
           (2 * static_cast<uint64_t>(std::max(local.priority, remote.priority))) +
           (local.priority > remote.priority ? 1 : 0);
}

// Sort candidate pairs based on priority
void IceAgent::sort_candidate_pairs() {
    std::sort(candidate_pairs_.begin(), candidate_pairs_.end(), [&](const CandidatePair& a, const CandidatePair& b) {
        return a.priority > b.priority; // Descending order
    });
}

// Transition ICE state
bool IceAgent::transition_to_state(IceConnectionState new_state) {
    if (current_state_ != new_state) {
        current_state_ = new_state;
        if (state_callback_) {
            state_callback_(new_state);
        }
        log(LogLevel::INFO, "ICE state transitioned to " + std::to_string(static_cast<int>(new_state)));
        return true;
    }
    return false;
}

// NAT Type Inference Logic
NatType IceAgent::infer_nat_type(const std::vector<asio::ip::udp::endpoint>& mapped_endpoints) {
    // Basic Checks
    if (mapped_endpoints.empty()) {
        return NatType::Symmetric;
    }

    // Collect unique IPs and ports
    std::vector<asio::ip::address_v4> unique_ips;
    std::vector<uint16_t> unique_ports;

    for (const auto& ep : mapped_endpoints) {
        // Check for unique IPs
        if (std::find(unique_ips.begin(), unique_ips.end(), ep.address().to_v4()) == unique_ips.end()) {
            unique_ips.push_back(ep.address().to_v4());
        }

        // Check for unique Ports
        if (std::find(unique_ports.begin(), unique_ports.end(), ep.port()) == unique_ports.end()) {
            unique_ports.push_back(ep.port());
        }
    }

    // Analyze unique IPs and Ports
    if (unique_ips.size() == 1) {
        if (unique_ports.size() == 1) {
            // Same IP and Port across all STUN servers
            return NatType::FullCone;
        } else {
            // Same IP but different Ports
            return NatType::RestrictedCone;
        }
    } else {
        if (unique_ports.size() == 1) {
            // Different IPs but same Port
            return NatType::PortRestrictedCone;
        } else {
            // Different IPs and different Ports
            return NatType::Symmetric;
        }
    }

    // Fallback
    return NatType::Unknown;
}

// Detect NAT Type using STUN
asio::awaitable<NatType> IceAgent::detect_nat_type() {
    log(LogLevel::INFO, "Starting NAT type detection...");

    // Gather mapped endpoints by sending STUN Binding Requests to all STUN servers
    std::vector<asio::ip::udp::endpoint> mapped_endpoints;
    for (auto& stun_client : stun_clients_) {
        try {
            asio::ip::udp::endpoint mapped_endpoint = co_await stun_client->send_binding_request();
            mapped_endpoints.push_back(mapped_endpoint);
            log(LogLevel::INFO, "Received mapped endpoint from " + stun_client->get_server() + ": " +
                mapped_endpoint.address().to_string() + ":" + std::to_string(mapped_endpoint.port()));
        } catch (const std::exception& ex) {
            log(LogLevel::WARNING, "Failed to gather host candidate from " + stun_client->get_server() + ": " + ex.what());
        }
    }

    // Infer NAT type based on mapped_endpoints
    NatType nat_type = infer_nat_type(mapped_endpoints);

    log(LogLevel::INFO, "Detected NAT Type: " + nat_type_to_string(nat_type));

    co_return nat_type;
}

// Gather local and TURN candidates
asio::awaitable<void> IceAgent::gather_candidates() {
    // Gather local candidates
    co_await gather_local_candidates();
    
    // Gather STUN candidates
    co_await gather_host_candidates();
}

// Gather local host candidates
asio::awaitable<void> IceAgent::gather_local_candidates() {
    log(LogLevel::INFO, "Gathering local candidates...");
    asio::ip::udp::resolver resolver(io_context_);
    asio::ip::udp::resolver::results_type results = co_await resolver.async_resolve("0.0.0.0", "0", asio::use_awaitable);

    for (const auto& entry : results) {
        Candidate candidate;
        candidate.endpoint = entry.endpoint();
        candidate.priority = 1000; // Example priority
        candidate.type = "host";
        candidate.foundation = "1";
        candidate.component_id = 1;
        candidate.transport = "UDP";

        local_candidates_.push_back(candidate);
        if (candidate_callback_) {
            candidate_callback_(candidate);
        }

        log(LogLevel::INFO, "Local Candidate gathered: " + candidate.endpoint.address().to_string() + ":" + std::to_string(candidate.endpoint.port()));
    }
    co_return;
}

// Gather Host Candidates using StunClient (srflx candidates)
asio::awaitable<void> IceAgent::gather_host_candidates() {
    // Assuming first STUN client is used for srflx candidates
    if (stun_clients_.empty()) {
        log(LogLevel::WARNING, "No STUN clients available to gather srflx candidates.");
        co_return;
    }

    for (auto& stun_client : stun_clients_) {
        try {
            asio::ip::udp::endpoint mapped_endpoint = co_await stun_client->send_binding_request();
            
            // Create srflx candidate
            Candidate srflx_candidate;
            srflx_candidate.endpoint = mapped_endpoint;
            srflx_candidate.priority = 800; // Lower than host candidates
            srflx_candidate.type = "srflx";
            srflx_candidate.foundation = "SRFLX1";
            srflx_candidate.component_id = 1;
            srflx_candidate.transport = "UDP";

            local_candidates_.push_back(srflx_candidate);
            log(LogLevel::INFO, "Added local srflx candidate: " + mapped_endpoint.address().to_string() + ":" + std::to_string(mapped_endpoint.port()));

            // Notify via callback
            if (candidate_callback_) {
                candidate_callback_(srflx_candidate);
            }

            // Create Candidate Pair with srflx Candidate
            CandidatePair pair;
            pair.local_candidate = srflx_candidate;
            // remote_candidate는 추후 추가
            candidate_pairs_.push_back(pair);
        } catch (const std::exception& ex) {
            log(LogLevel::WARNING, "Failed to gather srflx candidate from STUN client: " + std::string(ex.what()));
        }
    }
    co_return;
}

// Gather Server Reflexive (srflx) Candidates
asio::awaitable<void> IceAgent::gather_srflx_candidates() {
    log(LogLevel::INFO, "Gathering server reflexive (srflx) candidates...");

    for (auto& stun_client : stun_clients_) {
        try {
            asio::ip::udp::endpoint mapped_endpoint = co_await stun_client->send_binding_request();
            
            // Create srflx candidate
            Candidate srflx_candidate;
            srflx_candidate.endpoint = mapped_endpoint;
            srflx_candidate.priority = 800; // Lower than host candidates
            srflx_candidate.type = "srflx";
            srflx_candidate.foundation = "SRFLX1";
            srflx_candidate.component_id = 1;
            srflx_candidate.transport = "UDP";

            local_candidates_.push_back(srflx_candidate);
            log(LogLevel::INFO, "Added local srflx candidate: " + mapped_endpoint.address().to_string() + ":" + std::to_string(mapped_endpoint.port()));

            // Notify via callback
            if (candidate_callback_) {
                candidate_callback_(srflx_candidate);
            }

            // Create Candidate Pair with srflx Candidate
            CandidatePair pair;
            pair.local_candidate = srflx_candidate;
            // remote_candidate는 추후 추가
            candidate_pairs_.push_back(pair);
        } catch (const std::exception& ex) {
            log(LogLevel::WARNING, "Failed to gather srflx candidate from STUN client: " + std::string(ex.what()));
        }
    }
    co_return;
}

// Gather Relay Candidates via TurnClient
asio::awaitable<void> IceAgent::gather_relay_candidates() {
    if (!turn_client_) {
        log(LogLevel::ERROR, "TurnClient not initialized.");
        co_return;
    }

    try {
        // Allocate a relay endpoint
        asio::ip::udp::endpoint relay_endpoint = co_await turn_client_->allocate_relay();
        log(LogLevel::INFO, "Allocated relay endpoint: " + relay_endpoint.address().to_string() + ":" + std::to_string(relay_endpoint.port()));

        // Create Relay Candidate
        Candidate relay_candidate;
        relay_candidate.endpoint = relay_endpoint;
        relay_candidate.priority = 900; // Lower priority than host candidates
        relay_candidate.type = "relay";
        relay_candidate.foundation = "RELAY1";
        relay_candidate.component_id = 1;
        relay_candidate.transport = "UDP";

        local_candidates_.push_back(relay_candidate);
        log(LogLevel::INFO, "Added local relay candidate: " + relay_endpoint.address().to_string() + ":" + std::to_string(relay_endpoint.port()));

        // Notify via callback
        if (candidate_callback_) {
            candidate_callback_(relay_candidate);
        }

        // Create Candidate Pair with Relay Candidate
        CandidatePair pair;
        pair.local_candidate = relay_candidate;
        // remote_candidate는 추후 추가
        candidate_pairs_.push_back(pair);
    } catch (const std::exception& ex) {
        log(LogLevel::ERROR, "Failed to allocate relay via TURN: " + std::string(ex.what()));
    }

    co_return;
}

// Perform connectivity checks
asio::awaitable<void> IceAgent::perform_connectivity_checks() {
    log(LogLevel::INFO, "Performing connectivity checks...");

    sort_candidate_pairs();

    for (auto& pair : candidate_pairs_) {
        if (pair.state == CandidatePairState::Succeeded || pair.is_nominated) {
            continue; // 이미 성공했거나 지명된 경우 건너뜁니다.
        }

        // IceMode에 따른 로직 분기
        if (mode_ == IceMode::Full) {
            // Full ICE 모드에서는 모든 후보 쌍에 대해 연결성 검사를 수행합니다.
            try {
                if (pair.remote_candidate.type == "srflx" || pair.remote_candidate.type == "prflx") {
                    // 직접 연결성 검사 (STUN Binding Request)
                    std::vector<uint8_t> transaction_id(12, 0x00);
                    std::generate(transaction_id.begin(), transaction_id.end(), []() { return rand() % 256; });

                    Stun::StunMessage connectivity_check(STUN_BINDING_REQUEST, transaction_id);
                    std::vector<uint8_t> serialized_check = connectivity_check.serialize();
                    co_await socket_.async_send_to(asio::buffer(serialized_check), pair.remote_candidate.endpoint, asio::use_awaitable);

                    log(LogLevel::INFO, "Sent STUN Binding Request to " +
                        pair.remote_candidate.endpoint.address().to_string() + ":" +
                        std::to_string(pair.remote_candidate.endpoint.port()));

                    // 타임아웃 설정
                    asio::steady_timer timer(io_context_);
                    timer.expires_after(std::chrono::seconds(2));

                    std::vector<uint8_t> recv_buffer(2048);
                    asio::ip::udp::endpoint sender_endpoint;

                    using namespace asio::experimental::awaitable_operators;
                    auto [ec, bytes_transferred] = co_await (
                        socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable)
                        || timer.async_wait(asio::use_awaitable)
                    );

                    if (ec == asio::error::operation_aborted) {
                        throw std::runtime_error("Connectivity check timed out.");
                    } else if (ec) {
                        throw std::runtime_error("Connectivity check failed: " + ec.message());
                    }

                    recv_buffer.resize(bytes_transferred);
                    Stun::StunMessage response = Stun::StunMessage::parse(recv_buffer);

                    // 응답 검증
                    if (response.get_type() != STUN_BINDING_RESPONSE_SUCCESS) {
                        throw std::runtime_error("Invalid STUN Binding Response type.");
                    }

                    // Transaction ID 검증
                    if (response.get_transaction_id() != transaction_id) {
                        throw std::runtime_error("STUN Transaction ID mismatch.");
                    }

                    // 후보 쌍 업데이트
                    pair.state = CandidatePairState::Succeeded;
                    pair.is_nominated = true;
                    selected_pair_ = pair;
                    log(LogLevel::INFO, "Connectivity established with " +
                        pair.remote_candidate.endpoint.address().to_string() + ":" +
                        std::to_string(pair.remote_candidate.endpoint.port()));
                    transition_to_state(IceConnectionState::Connected);
                }
                else if (pair.remote_candidate.type == "relay") {
                    // Relay 기반 연결성 검사 (TURN Send)
                    std::vector<uint8_t> data = { 'D', 'A', 'T', 'A' };
                    co_await socket_.async_send_to(asio::buffer(data), pair.remote_candidate.endpoint, asio::use_awaitable);
                    log(LogLevel::INFO, "Sent data via TURN relay to " +
                        pair.remote_candidate.endpoint.address().to_string() + ":" +
                        std::to_string(pair.remote_candidate.endpoint.port()));

                    // 타임아웃 설정
                    asio::steady_timer timer(io_context_);
                    timer.expires_after(std::chrono::seconds(2));

                    std::vector<uint8_t> recv_buffer(2048);
                    asio::ip::udp::endpoint sender_endpoint;

                    using namespace asio::experimental::awaitable_operators;
                    auto [ec, bytes_transferred] = co_await (
                        socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable)
                        || timer.async_wait(asio::use_awaitable)
                    );

                    if (ec == asio::error::operation_aborted) {
                        throw std::runtime_error("Relay connectivity check timed out.");
                    } else if (ec) {
                        throw std::runtime_error("Relay connectivity check failed: " + ec.message());
                    }

                    recv_buffer.resize(bytes_transferred);
                    if (bytes_transferred > 0) {
                        pair.state = CandidatePairState::Succeeded;
                        pair.is_nominated = true;
                        selected_pair_ = pair;
                        log(LogLevel::INFO, "Relay-based connectivity established with " +
                            pair.remote_candidate.endpoint.address().to_string() + ":" +
                            std::to_string(pair.remote_candidate.endpoint.port()));
                        transition_to_state(IceConnectionState::Connected);
                        co_return;
                    }
                }
            } catch (const std::exception& ex) {
                log(LogLevel::WARNING, "Connectivity check failed: " + std::string(ex.what()));
                pair.state = CandidatePairState::Failed;
                continue;
            }
        }
        else if (mode_ == IceMode::Lite) {
            // Lite ICE 모드에서는 주로 Controller 역할을 수행하는 피어가 연결성 검사를 주도합니다.
            // Controlled 역할을 수행하는 피어는 응답만 처리합니다.

            if (role_ == IceRole::Controller) {
                // Controller는 연결성 검사를 주도적으로 수행합니다.
                try {
                    if (pair.remote_candidate.type == "srflx" || pair.remote_candidate.type == "prflx") {
                        // 직접 연결성 검사 (STUN Binding Request)
                        std::vector<uint8_t> transaction_id(12, 0x00);
                        std::generate(transaction_id.begin(), transaction_id.end(), []() { return rand() % 256; });

                        Stun::StunMessage connectivity_check(STUN_BINDING_REQUEST, transaction_id);
                        std::vector<uint8_t> serialized_check = connectivity_check.serialize();
                        co_await socket_.async_send_to(asio::buffer(serialized_check), pair.remote_candidate.endpoint, asio::use_awaitable);

                        log(LogLevel::INFO, "Sent STUN Binding Request to " +
                            pair.remote_candidate.endpoint.address().to_string() + ":" +
                            std::to_string(pair.remote_candidate.endpoint.port()));

                        // 타임아웃 설정
                        asio::steady_timer timer(io_context_);
                        timer.expires_after(std::chrono::seconds(2));

                        std::vector<uint8_t> recv_buffer(2048);
                        asio::ip::udp::endpoint sender_endpoint;

                        using namespace asio::experimental::awaitable_operators;
                        auto [ec, bytes_transferred] = co_await (
                            socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable)
                            || timer.async_wait(asio::use_awaitable)
                        );

                        if (ec == asio::error::operation_aborted) {
                            throw std::runtime_error("Connectivity check timed out.");
                        } else if (ec) {
                            throw std::runtime_error("Connectivity check failed: " + ec.message());
                        }

                        recv_buffer.resize(bytes_transferred);
                        Stun::StunMessage response = Stun::StunMessage::parse(recv_buffer);

                        // 응답 검증
                        if (response.get_type() != STUN_BINDING_RESPONSE_SUCCESS) {
                            throw std::runtime_error("Invalid STUN Binding Response type.");
                        }

                        // Transaction ID 검증
                        if (response.get_transaction_id() != transaction_id) {
                            throw std::runtime_error("STUN Transaction ID mismatch.");
                        }

                        // 후보 쌍 업데이트
                        pair.state = CandidatePairState::Succeeded;
                        pair.is_nominated = true;
                        selected_pair_ = pair;
                        log(LogLevel::INFO, "Connectivity established with " +
                            pair.remote_candidate.endpoint.address().to_string() + ":" +
                            std::to_string(pair.remote_candidate.endpoint.port()));
                        transition_to_state(IceConnectionState::Connected);
                    }
                    else if (pair.remote_candidate.type == "relay") {
                        // Relay 기반 연결성 검사 (TURN Send)
                        std::vector<uint8_t> data = { 'D', 'A', 'T', 'A' };
                        co_await socket_.async_send_to(asio::buffer(data), pair.remote_candidate.endpoint, asio::use_awaitable);
                        log(LogLevel::INFO, "Sent data via TURN relay to " +
                            pair.remote_candidate.endpoint.address().to_string() + ":" +
                            std::to_string(pair.remote_candidate.endpoint.port()));

                        // 타임아웃 설정
                        asio::steady_timer timer(io_context_);
                        timer.expires_after(std::chrono::seconds(2));

                        std::vector<uint8_t> recv_buffer(2048);
                        asio::ip::udp::endpoint sender_endpoint;
                        size_t len = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);

                        if (len > 0) {
                            pair.state = CandidatePairState::Succeeded;
                            pair.is_nominated = true;
                            selected_pair_ = pair;
                            log(LogLevel::INFO, "Relay-based connectivity established with " +
                                pair.remote_candidate.endpoint.address().to_string() + ":" +
                                std::to_string(pair.remote_candidate.endpoint.port()));
                            transition_to_state(IceConnectionState::Connected);
                            co_return;
                        }
                    }
                } catch (const std::exception& ex) {
                    log(LogLevel::WARNING, "Connectivity check failed: " + std::string(ex.what()));
                    pair.state = CandidatePairState::Failed;
                    continue;
                }
            }
            else if (role_ == IceRole::Controlled) {
                // Controlled 역할에서는 주로 응답만 처리합니다.
                // 연결성 검사 로직을 구현할 필요가 없습니다.
                log(LogLevel::INFO, "IceMode::Lite - Controlled role: Skipping connectivity checks.");
                break; // Controlled 피어는 더 이상 검사할 필요가 없으므로 루프를 종료합니다.
            }
        }
    }

    // After all checks
    bool any_succeeded = false;
    for (const auto& pair : candidate_pairs_) {
        if (pair.state == CandidatePairState::Succeeded || pair.is_nominated) {
            any_succeeded = true;
            break;
        }
    }

    if (any_succeeded) {
        transition_to_state(IceConnectionState::Connected);
    } else {
        log(LogLevel::ERROR, "No valid candidate pairs found after connectivity checks.");
        transition_to_state(IceConnectionState::Failed);
    }
    co_return;
}

// Perform Keep-Alive messages
asio::awaitable<void> IceAgent::perform_keep_alive() {
    while (current_state_ == IceConnectionState::Connected) {
        // Keep-Alive interval (e.g., 30 seconds)
        keep_alive_timer_.expires_after(std::chrono::seconds(30));
        co_await keep_alive_timer_.async_wait(asio::use_awaitable);

        log(LogLevel::INFO, "Performing periodic connectivity check (Keep-Alive).");

        // Perform connectivity checks
        co_await perform_connectivity_checks();
    }

    co_return;
}

// Perform TURN allocation refresh
asio::awaitable<void> IceAgent::perform_turn_refresh() {
    while (current_state_ == IceConnectionState::Connected && turn_client_ && turn_client_->is_allocated()) {
        // Set the timer for the TURN allocation refresh interval, e.g., 5 minutes
        keep_alive_timer_.expires_after(std::chrono::minutes(5));
        co_await keep_alive_timer_.async_wait(asio::use_awaitable);

        log(LogLevel::INFO, "Refreshing TURN allocation.");

        try {
            co_await turn_client_->allocate_relay(); // Re-allocate or refresh as needed
            log(LogLevel::INFO, "TURN allocation refreshed successfully.");
        }
        catch (const std::exception& ex) {
            log(LogLevel::ERROR, "Failed to refresh TURN allocation: " + std::string(ex.what()));
            // Optional: Implement retry logic or handle failure
        }
    }

    co_return;
}

// Start receiving data
asio::awaitable<void> IceAgent::start_data_receive() {
    while (current_state_ == IceConnectionState::Connected) {
        std::vector<uint8_t> buffer(1024);
        asio::ip::udp::endpoint sender_endpoint;
        try {
            size_t bytes_received = co_await socket_.async_receive_from(asio::buffer(buffer), sender_endpoint, asio::use_awaitable);
            buffer.resize(bytes_received);
            if (data_callback_) {
                data_callback_(buffer, sender_endpoint);
            }
        } catch (const std::exception& ex) {
            log(LogLevel::ERROR, "Error receiving data: " + std::string(ex.what()));
        }
    }
    co_return;
}

// ICE Restart
asio::awaitable<void> IceAgent::restart_ice() {
    if (mode_ == IceMode::Lite) {
        log(LogLevel::WARNING, "ICE Restart is not supported in ICE Lite mode.");
        co_return;
    }

    log(LogLevel::INFO, "Restarting ICE process...");

    // Reset state
    current_state_ = IceConnectionState::New;
    selected_pair_ = CandidatePair();
    candidate_pairs_.clear();
    remote_candidates_.clear();
    log(LogLevel::INFO, "ICE state reset.");

    // Restart ICE process
    co_await start();
}
