// src/ice_agent.cpp

#include "ice_agent.hpp"
#include "signaling_client.hpp"
#include <algorithm>
#include <iostream>
#include <thread>

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
    stun_server1_(stun_server1), 
	stun_server2_(stun_server2), 
	turn_server_(turn_server),
    current_state_(IceConnectionState::New), 
	keep_alive_timer_(io_context),
    log_level_(LogLevel::INFO) {
	// Initialize StunClients for each STUN server
    for (const auto& server : stun_servers_) {
        auto stun_client = std::make_shared<StunClient>(io_context_);
        stun_clients_.push_back(stun_client);
    }	  
	
	// Initialize TurnClient if TURN server is provided
    if (!turn_server_.empty()) {
        turn_client_ = std::make_shared<TurnClient>(io_context_, turn_server_, turn_username_, turn_password_);
    }
}

// Setters
void IceAgent::set_on_state_change_callback(StateCallback callback) {
    state_callback_ = std::move(callback);
}

void IceAgent::set_candidate_callback(CandidateCallback callback) {
    candidate_callback_ = std::move(callback);
}

void IceAgent::set_data_callback(DataCallback callback) {
    data_callback_ = std::move(callback);
}

void IceAgent::set_log_level(LogLevel level) {
    log_level_ = level;
}

void IceAgent::set_nat_type_callback(NatTypeCallback cb) {
    on_nat_type_detected_ = cb;
}

void IceAgent::set_signaling_client(std::shared_ptr<SignalingClient> signaling_client) {
    signaling_client_ = signaling_client;
}

// Logging function
void IceAgent::log(LogLevel level, const std::string& message) {
    if (level >= log_level_) {
        switch (level) {
            case LogLevel::INFO:
                std::cout << "[INFO] " << message << std::endl;
                break;
            case LogLevel::WARNING:
                std::cout << "[WARNING] " << message << std::endl;
                break;
            case LogLevel::ERROR:
                std::cerr << "[ERROR] " << message << std::endl;
                break;
        }
    }
}

// Start ICE process
awaitable<void> IceAgent::start() {
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
			case NatType::SymmetricUDPFirewall:
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

        // NAT 탐지 및 우회 전략 적용
        log(LogLevel::INFO, "Detected NAT Type: " + nat_type_to_string(nat_type));
        co_await apply_nat_traversal_strategy(nat_type);

        if (!transition_to_state(IceConnectionState::Checking)) {
            co_return;
        }

        sort_candidate_pairs();
        co_await perform_connectivity_checks();

        if (selected_pair_.is_nominated) {
            if (transition_to_state(IceConnectionState::Connected)) {
                start_keep_alive();
                start_data_receive();
            }
        } else {
            transition_to_state(IceConnectionState::Failed);
        }
    } catch (const std::exception& ex) {
        log(LogLevel::ERROR, "Exception in ICE Agent: " + std::string(ex.what()));
        transition_to_state(IceConnectionState::Failed);
    }
}

// Send data over established connection
void IceAgent::send_data(const std::vector<uint8_t>& data) {
    if (current_state_ != IceConnectionState::Connected || !selected_pair_.is_nominated) {
        log(LogLevel::WARNING, "Cannot send data. Connection not established.");
        return;
    }

    asio::co_spawn(io_context_, [this, data]() -> awaitable<void> {
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
    for (const auto& local : local_candidates_) {
        CandidatePair pair(io_context_);
        pair.local_candidate = local;
        pair.remote_candidate = candidate;
        pair.priority = calculate_priority(local, candidate);
        candidate_pairs_.push_back(pair);
    }
    asio::co_spawn(io_context_, perform_connectivity_checks(), asio::detached);
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
    return (std::min(local.priority, remote.priority) << 32) +
           (2 * std::max(local.priority, remote.priority)) +
           (local.priority > remote.priority ? 1 : 0);
}

// Sort candidate pairs based on priority
void IceAgent::sort_candidate_pairs() {
    std::sort(candidate_pairs_.begin(), candidate_pairs_.end(),
              [](const CandidatePair& a, const CandidatePair& b) {
                  return a.priority > b.priority;
              });
}

// Transition ICE state
bool IceAgent::transition_to_state(IceConnectionState new_state) {
    current_state_ = new_state;
    if (state_callback_) {
        state_callback_(current_state_);
    }
    log(LogLevel::INFO, "Transitioned to state: " + std::to_string(static_cast<int>(current_state_)));
    return true;
}

// NAT Type Inference Logic
NatType IceAgent::infer_nat_type(const std::vector<asio::ip::udp::endpoint>& mapped_endpoints) {
    // Basic Checks
    if (mapped_endpoints.empty()) {
        return NatType::SymmetricUDPFirewall;
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

// Gather local and TURN candidates
awaitable<void> IceAgent::gather_candidates() {
    // Gather local candidates
    co_await gather_local_candidates();
	
	// Gather STUN candidates
	co_await gather_host_candidates();
	
    // Gather TURN candidates
    // co_await gather_relay_candidates();
}

// Gather local host candidates
awaitable<void> IceAgent::gather_local_candidates() {
    log(LogLevel::INFO, "Gathering local candidates...");
    asio::ip::udp::resolver resolver(io_context_);
    asio::ip::udp::resolver::results_type results = co_await resolver.async_resolve("0.0.0.0", "0", asio::use_awaitable);

    for (const auto& entry : results) {
        Candidate candidate;
        candidate.endpoint = entry.endpoint();
        candidate.priority = 1000;
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

// Gather Host Candidates using StunClient
awaitable<void> IceAgent::gather_host_candidates() {
    // Define STUN server endpoint (stun_server1_)
    asio::ip::udp::resolver resolver(io_context_);
    auto results = co_await resolver.async_resolve(asio::ip::udp::v4(), stun_server1_, "3478", asio::use_awaitable);
    asio::ip::udp::endpoint stun_endpoint = *results.begin();

    // Send STUN Binding Request and await response
    asio::ip::udp::endpoint mapped_endpoint;
    try {
        co_await stun_client_->send_binding_request(stun_endpoint, mapped_endpoint);
		    
		Candidate host_candidate;
		host_candidate.endpoint = mapped_endpoint;
		host_candidate.priority = 1000; // 예시 우선순위, 실제 계산 필요
		host_candidate.type = "host";
		host_candidate.foundation = "HOST1";
		host_candidate.component_id = 1;
		host_candidate.transport = "UDP";

		local_candidates_.push_back(host_candidate);
		log(LogLevel::INFO, "Added local host candidate: " + mapped_endpoint.address().to_string() + ":" + std::to_string(mapped_endpoint.port()));

		// Candidate Pair 생성 (Remote Candidate는 추후 추가)
		CandidatePair pair(io_context_);
		pair.local_candidate = host_candidate;
		
		// remote_candidate는 추후 remote_candidates_에서 추가
		candidate_pairs_.push_back(pair);
    } catch (const std::exception& ex) {
        log(LogLevel::WARNING, "Failed to gather host candidate: " + std::string(ex.what()));
    }
}

// Detect NAT Type using STUN
awaitable<NatType> IceAgent::detect_nat_type() {
   log(LogLevel::INFO, "Starting NAT type detection...");

    // Gather mapped endpoints by sending STUN Binding Requests to all STUN servers
    std::vector<asio::ip::udp::endpoint> mapped_endpoints;
    for (auto& stun_client : stun_clients_) {
        // Send STUN Binding Request and await response
        asio::ip::udp::endpoint mapped_endpoint;
        try {
            co_await stun_client->send_binding_request(mapped_endpoint);
            mapped_endpoints.push_back(mapped_endpoint);
            log(LogLevel::INFO, "Received mapped endpoint from " + stun_client->get_server() + ": " +
                mapped_endpoint.address().to_string() + ":" + std::to_string(mapped_endpoint.port()));
        } catch (const std::exception& ex) {
            log(LogLevel::WARNING, "Failed to gather host candidate from " + stun_client->get_server() + ": " + ex.what());
        }
    }

    // Infer NAT type based on mapped_endpoints
    NatType nat_type = infer_nat_type(mapped_endpoints);

    log(LogLevel::INFO, "NAT type detected: " + std::to_string(static_cast<int>(nat_type)));

    co_return nat_type;
}

// Apply NAT traversal strategy based on detected NAT type
awaitable<void> IceAgent::apply_nat_traversal_strategy(NatType nat_type) {
    switch (nat_type) {
        case NatType::OpenInternet:
        case NatType::FullCone:
            log(LogLevel::INFO, "NAT Type: Open Internet or Full Cone NAT. Attempting Direct P2P Connection.");
            co_await direct_p2p_connection();
            break;

        case NatType::RestrictedCone:
        case NatType::PortRestrictedCone:
            log(LogLevel::INFO, "NAT Type: Restricted Cone NAT. Attempting UDP Hole Punching.");
            co_await udp_hole_punching();
            break;

        case NatType::Symmetric:
            log(LogLevel::INFO, "NAT Type: Symmetric NAT. Using TURN Relay Connection.");
            co_await turn_relay_connection();
            break;

        default:
            log(LogLevel::WARNING, "NAT Type: Unknown. Falling back to TURN Relay Connection.");
            co_await turn_relay_connection();
            break;
    }
}

// Start Keep-Alive messages
void IceAgent::keep_alive() {
    asio::co_spawn(io_context_, [this]() -> awaitable<void> {
        while (current_state_ == IceConnectionState::Connected) {
            std::vector<uint8_t> keep_alive_request(20, 0);
			// Message Type: Binding Request (0x0001)
			keep_alive_request[0] = 0x00;
			keep_alive_request[1] = 0x01;

			// Message Length: 0 (no attributes)
			keep_alive_request[2] = 0x00;
			keep_alive_request[3] = 0x00;

			// Magic Cookie: 0x2112A442
			keep_alive_request[4] = 0x21;
			keep_alive_request[5] = 0x12;
			keep_alive_request[6] = 0xA4;
			keep_alive_request[7] = 0x42;
            try {
                co_await socket_.async_send_to(asio::buffer(keep_alive_request), selected_pair_.remote_candidate.endpoint, asio::use_awaitable);
                log(LogLevel::INFO, "Sent Keep-Alive message.");
            } catch (const std::exception& ex) {
                log(LogLevel::ERROR, "Failed to send Keep-Alive message: " + std::string(ex.what()));
            }

            co_await asio::steady_timer(io_context_, std::chrono::seconds(15)).async_wait(asio::use_awaitable);
        }
    }, asio::detached);
}

// Start receiving data
void IceAgent::start_data_receive() {
    asio::co_spawn(io_context_, [this]() -> awaitable<void> {
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
    }, asio::detached);
}

// ICE Restart
awaitable<void> IceAgent::restart_ice() {
    if (mode_ == IceMode::Lite) {
        log(LogLevel::WARNING, "ICE Restart is not supported in ICE Lite mode.");
        co_return;
    }

    log(LogLevel::INFO, "Restarting ICE process...");

    // 상태를 초기화
    current_state_ = IceConnectionState::New;
    selected_pair_ = CandidatePair(io_context_);
    candidate_pairs_.clear();
    remote_candidates_.clear();
    log(LogLevel::INFO, "ICE state reset.");

    // 새로운 후보 수집 시작
    co_await start();
}

// Signal ready to punch (for synchronization)
void IceAgent::signal_ready_to_punch(const CandidatePair& pair) {
    if (signaling_client_) {
        json signal = {
            {"action", "ready_to_punch"},
            {"local_endpoint", pair.local_candidate.endpoint.address().to_string() + ":" + std::to_string(pair.local_candidate.endpoint.port())},
            {"remote_endpoint", pair.remote_candidate.endpoint.address().to_string() + ":" + std::to_string(pair.remote_candidate.endpoint.port())}
        };
        signaling_client_->send_message(signal.dump());
        log(LogLevel::INFO, "Sent UDP Hole Punching synchronization signal.");
    }
}

// Validate Candidate Pair with strategy
awaitable<void> IceAgent::validate_pair_with_strategy(CandidatePair& pair, std::function<std::vector<uint8_t>(const CandidatePair&)> create_request) {
    while (pair.retry_count < max_retries_) {
        try {
            // Set timeout
            pair.timeout_timer.expires_after(std::chrono::seconds(pair_timeout_seconds_));
            log(LogLevel::INFO, "Validating pair: " + pair.local_candidate.endpoint.address().to_string() + ":" +
                                       std::to_string(pair.local_candidate.endpoint.port()) + " <-> " +
                                       pair.remote_candidate.endpoint.address().to_string() + ":" +
                                       std::to_string(pair.remote_candidate.endpoint.port()));

            // Create and send request
            auto request = create_request(pair);
            co_await socket_.async_send_to(asio::buffer(request), pair.remote_candidate.endpoint, asio::use_awaitable);

            // Wait for response or timeout
            std::vector<uint8_t> response(1024);
            asio::ip::udp::endpoint sender_endpoint;
            co_await (socket_.async_receive_from(asio::buffer(response), sender_endpoint, asio::use_awaitable) ||
                      pair.timeout_timer.async_wait(asio::use_awaitable));

            // Check if response is from expected endpoint
            if (sender_endpoint == pair.remote_candidate.endpoint) {
                pair.state = CandidatePairState::Succeeded;
                log(LogLevel::INFO, "Connection succeeded for: " +
                                       pair.local_candidate.endpoint.address().to_string() + ":" +
                                       std::to_string(pair.local_candidate.endpoint.port()) + " <-> " +
                                       pair.remote_candidate.endpoint.address().to_string() + ":" +
                                       std::to_string(pair.remote_candidate.endpoint.port()));
                co_return;
            }
        } catch (const std::exception& ex) {
            // Retry on failure
            pair.retry_count++;
            pair.state = CandidatePairState::Failed;
            log(LogLevel::WARNING, "Retry " + std::to_string(pair.retry_count) + " for: " +
                                        pair.local_candidate.endpoint.address().to_string() + ":" +
                                        std::to_string(pair.local_candidate.endpoint.port()) + " <-> " +
                                        pair.remote_candidate.endpoint.address().to_string() + ":" +
                                        std::to_string(pair.remote_candidate.endpoint.port()) + " (" + ex.what() + ")");

            if (pair.retry_count >= max_retries_) {
                log(LogLevel::ERROR, "Max retries reached for: " +
                                         pair.local_candidate.endpoint.address().to_string() + ":" +
                                         std::to_string(pair.local_candidate.endpoint.port()) + " <-> " +
                                         pair.remote_candidate.endpoint.address().to_string() + ":" +
                                         std::to_string(pair.remote_candidate.endpoint.port()));
            }
        }
    }
}

// Gather Relay Candidates via TurnClient
awaitable<void> IceAgent::gather_relay_candidates() {
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

        // Create Candidate Pair with Relay Candidate
        CandidatePair pair(io_context_);
        pair.local_candidate = relay_candidate;
        // remote_candidate will be added when remote candidates are received
        candidate_pairs_.push_back(pair);

        // Notify about the new relay candidate via callback
        if (on_candidate_) {
            on_candidate_(relay_candidate);
        }
    } catch (const std::exception& ex) {
        log(LogLevel::ERROR, "Failed to allocate relay via TURN: " + std::string(ex.what()));
    }

    co_return;
}

// Gather Server Reflexive (srflx) Candidates
awaitable<void> IceAgent::gather_srflx_candidates() {
    log(LogLevel::INFO, "Gathering server reflexive (srflx) candidates...");

    for (auto& stun_client : stun_clients_) {
        asio::ip::udp::endpoint mapped_endpoint;
        try {
            co_await stun_client->send_binding_request(mapped_endpoint);
            // Create srflx candidate
            Candidate srflx_candidate;
            srflx_candidate.endpoint = mapped_endpoint;
            srflx_candidate.priority = 800; // Lower priority than host candidates
            srflx_candidate.type = "srflx";
            srflx_candidate.foundation = "SRFLX1";
            srflx_candidate.component_id = 1;
            srflx_candidate.transport = "UDP";

            local_candidates_.push_back(srflx_candidate);
            log(LogLevel::INFO, "Added srflx candidate: " +
                srflx_candidate.endpoint.address().to_string() + ":" +
                std::to_string(srflx_candidate.endpoint.port()));

            // Notify via callback
            if (on_candidate_) {
                on_candidate_(srflx_candidate);
            }

            // Create Candidate Pair with srflx Candidate
            CandidatePair pair(io_context_);
            pair.local_candidate = srflx_candidate;
            // remote_candidate will be added when remote candidates are received
            candidate_pairs_.push_back(pair);
        } catch (const std::exception& ex) {
            log(LogLevel::WARNING, "Failed to gather srflx candidate from " + stun_client->get_server() + ": " + ex.what());
        }
    }

    co_return;
}

// Connectivity check
awaitable<void> IceAgent::perform_connectivity_checks() {
    log(LogLevel::INFO, "Performing connectivity checks...");
    for (auto& pair : candidate_pairs_) {
        if (pair.state == CandidatePairState::Succeeded || pair.is_nominated) {
            continue; // 이미 성공한 Pair는 건너뜀
        }

        // 전략에 따라 검증 수행
        if (pair.local_candidate.type == "host" && pair.remote_candidate.type == "host") {
            co_await udp_hole_punching();
        } else if (pair.local_candidate.type == "relay") {
            co_await turn_relay_connection();
        }

        // QoS 데이터 수집 (RTT 측정)
        co_await measure_rtt(pair);
    }

    // QoS 기반 우선순위 재조정
    adjust_priority_based_on_qos();

    // ICE Lite 모드일 경우, 모든 Pair를 검사하지 않고 최적 Pair를 선택
    if (mode_ == IceMode::Lite) {
        for (auto& pair : candidate_pairs_) {
            if (pair.state == CandidatePairState::Succeeded) {
                pair.is_nominated = true;
                selected_pair_ = pair;
                transition_to_state(IceConnectionState::Connected);
                co_return;
            }
        }
    } else {
        // 기존 Full ICE 모드의 연결 상태 확인
        if (selected_pair_.is_nominated) {
            log(LogLevel::INFO, "ICE Connection Established.");
        } else {
            log(LogLevel::ERROR, "ICE Connection Failed.");
            transition_to_state(IceConnectionState::Failed);
        }
    }
}

// UDP Hole Punching implementation
awaitable<void> IceAgent::udp_hole_punching() {
    log(LogLevel::INFO, "[NAT Traversal] Starting UDP Hole Punching...");

    for (auto& pair : candidate_pairs_) {
        if (pair.state != CandidatePairState::Waiting || pair.local_candidate.type != "host" || pair.remote_candidate.type != "host") {
            continue; // Skip non-host or already validated pairs
        }

        pair.state = CandidatePairState::InProgress;

        // Signal ready to punch via signaling server
        signal_ready_to_punch(pair);

        // Validate pair using common strategy
        co_await validate_pair_with_strategy(pair, [this](const CandidatePair& p) {
			// Message Type: Binding Request (0x0001)
			std::vector<uint8_t> request(20, 0);
			request[0] = 0x00; request[1] = 0x01;

			// Message Length: 0 (no attributes)
			request[2] = 0x00; request[3] = 0x00;

			// Magic Cookie: 0x2112A442
			request[4] = 0x21; request[5] = 0x12; request[6] = 0xA4; request[7] = 0x42;
            return request; // STUN Binding Request
        });

        if (pair.state == CandidatePairState::Succeeded) {
            if (role_ == IceRole::Controller) {
                pair.is_nominated = true;
                selected_pair_ = pair;
                transition_to_state(IceConnectionState::Connected);
                co_return; // Stop after nominating the first successful pair
            } else if (role_ == IceRole::Controlled) {
                selected_pair_ = pair;
                transition_to_state(IceConnectionState::Connected);
                co_return;
            }
        }
    }

    log(LogLevel::ERROR, "[UDP Hole Punching] All pairs failed.");
}

// Direct P2P Connection implementation
awaitable<void> IceAgent::direct_p2p_connection() {
    log(LogLevel::INFO, "[NAT Traversal] Attempting Direct P2P Connection...");

    for (auto& pair : candidate_pairs_) {
        if (pair.state != CandidatePairState::Waiting || pair.local_candidate.type != "host" || pair.remote_candidate.type != "host") {
            continue; // Skip non-host or already validated pairs
        }

        pair.state = CandidatePairState::InProgress;

        // Validate pair using common strategy
        co_await validate_pair_with_strategy(pair, [this](const CandidatePair& p) {
            return create_stun_binding_request(p); // STUN Binding Request
        });

        if (pair.state == CandidatePairState::Succeeded) {
            if (role_ == IceRole::Controller) {
                pair.is_nominated = true;
                selected_pair_ = pair;
                transition_to_state(IceConnectionState::Connected);
                co_return; // Stop after nominating the first successful pair
            } else if (role_ == IceRole::Controlled) {
                selected_pair_ = pair;
                transition_to_state(IceConnectionState::Connected);
                co_return;
            }
        }
    }

    log(LogLevel::ERROR, "[Direct P2P] All pairs failed.");
}

// TURN Relay Connection implementation
awaitable<void> IceAgent::turn_relay_connection() {
    log(LogLevel::INFO, "[NAT Traversal] Using TURN Relay Connection...");

    for (auto& pair : candidate_pairs_) {
        if (pair.local_candidate.type != "relay" || pair.state != CandidatePairState::Waiting) {
            continue; // Skip non-relay or already validated pairs
        }

        pair.state = CandidatePairState::InProgress;

        // Validate pair using common strategy
        co_await validate_pair_with_strategy(pair, [this](const CandidatePair& p) {
            return create_turn_allocate_request(); // TURN Allocate Request
        });

        if (pair.state == CandidatePairState::Succeeded) {
            if (role_ == IceRole::Controller) {
                pair.is_nominated = true;
                selected_pair_ = pair;
                transition_to_state(IceConnectionState::Connected);
                co_return; // Stop after nominating the first successful pair
            } else if (role_ == IceRole::Controlled) {
                selected_pair_ = pair;
                transition_to_state(IceConnectionState::Connected);
                co_return;
            }
        }
    }

    log(LogLevel::ERROR, "[TURN Relay] All pairs failed.");
}

awaitable<void> IceAgent::measure_rtt(CandidatePair& pair) {
    try {
        auto start_time = std::chrono::steady_clock::now();

        // STUN Binding Request 전송
        std::vector<uint8_t> request = create_stun_binding_request(pair);
        co_await socket_.async_send_to(asio::buffer(request), pair.remote_candidate.endpoint, asio::use_awaitable);

        // 응답 대기 (타임아웃 설정)
        std::vector<uint8_t> response(1024);
        asio::ip::udp::endpoint sender_endpoint;
        asio::steady_timer timer(io_context_);
        timer.expires_after(std::chrono::seconds(pair_timeout_seconds_));
        bool timeout = false;

        co_await (
            socket_.async_receive_from(asio::buffer(response), sender_endpoint, asio::use_awaitable) ||
            timer.async_wait([&](const asio::error_code& ec) { if (!ec) timeout = true; })
        );

        if (timeout || sender_endpoint != pair.remote_candidate.endpoint) {
            throw std::runtime_error("RTT Measurement Failed");
        }

        auto end_time = std::chrono::steady_clock::now();
        pair.rtt = std::chrono::duration<double, std::milli>(end_time - start_time).count(); // RTT in milliseconds
        log(LogLevel::INFO, "RTT for pair " + pair.local_candidate.endpoint.address().to_string() + ":" + 
                                   std::to_string(pair.local_candidate.endpoint.port()) + " <-> " + 
                                   pair.remote_candidate.endpoint.address().to_string() + ":" + 
                                   std::to_string(pair.remote_candidate.endpoint.port()) + " = " + 
                                   std::to_string(pair.rtt) + " ms");
    } catch (const std::exception& ex) {
        log(LogLevel::WARNING, "RTT measurement failed: " + std::string(ex.what()));
        pair.rtt = std::numeric_limits<double>::max(); // 최악의 RTT 값 설정
    }
}

void IceAgent::adjust_priority_based_on_qos() {
    for (auto& pair : candidate_pairs_) {
        // 예제: RTT가 낮을수록 우선순위를 높게 설정
        // 실제 RFC 8445의 우선순위 계산을 따릅니다.
        if (pair.rtt < std::numeric_limits<double>::max()) {
            pair.priority = static_cast<uint64_t>(10000 / pair.rtt); // 단순한 예제
        } else {
            pair.priority = 0; // 실패한 Pair는 낮은 우선순위
        }
    }

    // 우선순위 기반으로 정렬
    sort_candidate_pairs();
}