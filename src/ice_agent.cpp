// src/ice_agent.cpp

#include "ice_agent.hpp"
#include "signaling_client.hpp"
#include <algorithm>
#include <iostream>
#include <thread>

// Constructor
IceAgent::IceAgent(asio::io_context& io_context, IceRole role, IceMode mode,
                   const std::string& stun_server1, const std::string& stun_server2, const std::string& turn_server)
    : io_context_(io_context), 
	  socket_(io_context, asio::ip::udp::v4()), 
	  role_(role), 
	  mode_(mode),
      stun_server1_(stun_server1), 
	  stun_server2_(stun_server2), 
	  turn_server_(turn_server),
      current_state_(IceConnectionState::New), 
	  keep_alive_timer_(io_context),
      log_level_(LogLevel::INFO) {}

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
        co_await gather_candidates();

        // NAT 탐지 및 우회 전략 적용
        NatType nat_type = detect_nat_type();
        log(LogLevel::INFO, "Detected NAT Type: " + nat_type_to_string(nat_type));
        co_await apply_nat_traversal_strategy(nat_type);

        if (!transition_to_state(IceConnectionState::Checking)) {
            co_return;
        }

        sort_candidate_pairs();
        co_await connectivity_check();

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
    asio::co_spawn(io_context_, connectivity_check(), asio::detached);
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

// Gather local and TURN candidates
awaitable<void> IceAgent::gather_candidates() {
    // Gather local candidates
    co_await gather_local_candidates();
	
	// Gather STUN candidates
	co_await gather_host_candidates();
	
    // Gather TURN candidates
    co_await gather_turn_candidates();
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
    Endpoint mapped_endpoint;
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

// Gather TURN relay candidates
awaitable<void> IceAgent::gather_turn_candidates() {
    log(LogLevel::INFO, "Gathering TURN candidates...");
    try {
        asio::ip::udp::resolver resolver(io_context_);
        asio::ip::udp::resolver::results_type endpoints = co_await resolver.async_resolve(turn_server_, "3478", asio::use_awaitable);
        asio::ip::udp::endpoint turn_endpoint = *endpoints.begin();

        // TURN Allocate 요청
        std::vector<uint8_t> allocate_request = create_turn_allocate_request();
        co_await socket_.async_send_to(asio::buffer(allocate_request), turn_endpoint, asio::use_awaitable);
        log(LogLevel::INFO, "TURN Allocate request sent to: " + turn_endpoint.address().to_string() + ":" + std::to_string(turn_endpoint.port()));

        // 응답 수신
        std::vector<uint8_t> response(1024);
        asio::ip::udp::endpoint sender_endpoint;
        size_t length = co_await socket_.async_receive_from(asio::buffer(response), sender_endpoint, asio::use_awaitable);

        // 응답 검증
        if (sender_endpoint != turn_endpoint) {
            log(LogLevel::WARNING, "Invalid TURN Allocate response from unexpected endpoint.");
            co_return;
        }

        Candidate relay_candidate = parse_turn_allocate_response(response, length);
        local_candidates_.push_back(relay_candidate);
        if (candidate_callback_) {
            candidate_callback_(relay_candidate);
        }

        log(LogLevel::INFO, "TURN Relay Candidate gathered: " + relay_candidate.endpoint.address().to_string() + ":" + std::to_string(relay_candidate.endpoint.port()));
    } catch (const std::exception& ex) {
        log(LogLevel::ERROR, "Failed to gather TURN candidates: " + std::string(ex.what()));
    }
    co_return;
}

// Create TURN Allocate Request
std::vector<uint8_t> IceAgent::create_turn_allocate_request() const {
    std::vector<uint8_t> request(20, 0);
    request[0] = 0x00; // TURN Allocate Request
    request[1] = 0x03;
    request[4] = 0x21; // Magic Cookie
    request[5] = 0x12;
    request[6] = 0xA4;
    request[7] = 0x42;

    // Attributes (e.g., Requested Transport: UDP)
    uint16_t attribute_type = 0x0019; // REQUESTED-TRANSPORT
    uint16_t attribute_length = 4;
    request.push_back((attribute_type >> 8) & 0xFF);
    request.push_back(attribute_type & 0xFF);
    request.push_back((attribute_length >> 8) & 0xFF);
    request.push_back(attribute_length & 0xFF);

    request.push_back(0x11);  // UDP Transport
    request.push_back(0x00);
    request.push_back(0x00);
    request.push_back(0x00);

    return request;
}

// Parse TURN Allocate Response
Candidate IceAgent::parse_turn_allocate_response(const std::vector<uint8_t>& response, size_t length) const {
    Candidate relay_candidate;
    relay_candidate.priority = 100; // Example priority for TURN Candidates
    relay_candidate.type = "relay";
    relay_candidate.transport = "UDP";

    // 실제 STUN/TURN 메시지 파싱 구현 필요
    // 여기서는 예제로 고정된 Relay Address 사용
    relay_candidate.endpoint = asio::ip::udp::endpoint(asio::ip::address::from_string("203.0.113.1"), 40000);

    return relay_candidate;
}

// Create STUN Binding Request
std::vector<uint8_t> IceAgent::create_stun_binding_request(const CandidatePair& pair) const {
    std::vector<uint8_t> request(20, 0);
    // Message Type: Binding Request (0x0001)
    request[0] = 0x00;
    request[1] = 0x01;

    // Message Length: 0 (no attributes)
    request[2] = 0x00;
    request[3] = 0x00;

    // Magic Cookie: 0x2112A442
    request[4] = 0x21;
    request[5] = 0x12;
    request[6] = 0xA4;
    request[7] = 0x42;

    // Transaction ID: 12 bytes 랜덤값
    for (int i = 8; i < 20; ++i) {
        request[i] = static_cast<uint8_t>(rand() % 256);
    }

    return request;
}

struct StunAttribute {
    uint16_t type;
    uint16_t length;
    std::vector<uint8_t> value;
};

std::vector<StunAttribute> parse_stun_attributes(const std::vector<uint8_t>& response, size_t length) const {
    std::vector<StunAttribute> attributes;
    size_t offset = 20; // 헤더 이후부터 시작

    while (offset + 4 <= length) {
        StunAttribute attr;
        attr.type = (response[offset] << 8) | response[offset + 1];
        attr.length = (response[offset + 2] << 8) | response[offset + 3];
        offset += 4;

        if (offset + attr.length > length) {
            throw std::runtime_error("STUN attribute length mismatch");
        }

        attr.value.insert(attr.value.end(), response.begin() + offset, response.begin() + offset + attr.length);
        attributes.push_back(attr);
        offset += attr.length;

        // Attribute padding: STUN attributes are padded to 4-byte boundaries
        if (attr.length % 4 != 0) {
            offset += (4 - (attr.length % 4));
        }
    }

    return attributes;
}
// Parse STUN Binding Response
asio::ip::udp::endpoint IceAgent::parse_stun_binding_response(const std::vector<uint8_t>& response, size_t length) const {
    // STUN 메시지 파싱 (RFC 5389)
    if (length < 20) {
        throw std::runtime_error("STUN response too short");
    }

    // Check message type
    uint16_t message_type = (response[0] << 8) | response[1];
    if (message_type != 0x0101) { // Binding Success Response
        throw std::runtime_error("Invalid STUN message type");
    }

    // Check magic cookie
    uint32_t magic_cookie = (response[4] << 24) | (response[5] << 16) | (response[6] << 8) | response[7];
    if (magic_cookie != 0x2112A442) {
        throw std::runtime_error("Invalid magic cookie");
    }

    // Parse attributes
    std::vector<StunAttribute> attributes = parse_stun_attributes(response, length);

    asio::ip::udp::endpoint mapped_endpoint(asio::ip::address_v4::any(), 0);

    for (const auto& attr : attributes) {
        if (attr.type == 0x0001) { // MAPPED-ADDRESS
            if (attr.length >= 8) {
                uint8_t family = attr.value[1];
                uint16_t port = (attr.value[2] << 8) | attr.value[3];
                std::string ip = std::to_string(attr.value[4]) + "." +
                                 std::to_string(attr.value[5]) + "." +
                                 std::to_string(attr.value[6]) + "." +
                                 std::to_string(attr.value[7]);
                mapped_endpoint = asio::ip::udp::endpoint(asio::ip::address::from_string(ip), port);
                break;
            }
        } else if (attr.type == 0x0020) { // XOR-MAPPED-ADDRESS
            if (attr.length >= 8) {
                uint8_t family = attr.value[1];
                uint16_t xport = (attr.value[2] << 8) | attr.value[3];
                uint32_t xaddr = (attr.value[4] << 24) | (attr.value[5] << 16) |
                                 (attr.value[6] << 8) | attr.value[7];
                uint32_t magic_cookie = 0x2112A442;
                uint16_t port = xport ^ ((magic_cookie >> 16) & 0xFFFF);
                uint32_t addr = xaddr ^ magic_cookie;
                asio::ip::address_v4::bytes_type addr_bytes;
                addr_bytes[0] = (addr >> 24) & 0xFF;
                addr_bytes[1] = (addr >> 16) & 0xFF;
                addr_bytes[2] = (addr >> 8) & 0xFF;
                addr_bytes[3] = addr & 0xFF;
                asio::ip::address_v4 ip_addr(addr_bytes);
                mapped_endpoint = asio::ip::udp::endpoint(ip_addr, port);
                break;
            }
        }
        // 추가적인 속성 파싱 가능
    }

    if (mapped_endpoint.address() == asio::ip::address_v4::any()) {
        throw std::runtime_error("MAPPED-ADDRESS not found in STUN response");
    }

    return mapped_endpoint;
}

// Detect NAT Type using STUN
NatType IceAgent::detect_nat_type() {
    try {
        asio::ip::udp::resolver resolver(io_context_);
        asio::ip::udp::resolver::results_type endpoints = resolver.resolve(stun_server1_, "3478");
        asio::ip::udp::endpoint stun_server = *endpoints.begin();

        // Send STUN Binding Request
		
        std::vector<uint8_t> request = create_stun_binding_request(*candidate_pairs_.begin());
        co_await socket_.async_send_to(asio::buffer(request), stun_server, asio::use_awaitable);
		
		/*
		Endpoint mapped_endpoint;
		co_await stun_client_->send_binding_request(*candidate_pairs_.begin(), mapped_endpoint);
		*/
        log(LogLevel::INFO, "Sent STUN Binding Request to " + stun_server.address().to_string() + ":" + std::to_string(stun_server.port()));

        // Receive STUN Binding Response
        std::vector<uint8_t> response(1024);
        asio::ip::udp::endpoint sender_endpoint;
        size_t length = co_await socket_.async_receive_from(asio::buffer(response), sender_endpoint, asio::use_awaitable);

        // Parse MAPPED-ADDRESS
        asio::ip::udp::endpoint primary_mapped_address = parse_stun_binding_response(response, length);
        log(LogLevel::INFO, "Received STUN Binding Response from " + sender_endpoint.address().to_string() + ":" + std::to_string(sender_endpoint.port()));

        // Send STUN Binding Request to secondary STUN server
        asio::ip::udp::resolver::results_type secondary_endpoints = resolver.resolve(stun_server2_, "3478");
        asio::ip::udp::endpoint secondary_stun_server = *secondary_endpoints.begin();
        co_await socket_.async_send_to(asio::buffer(request), secondary_stun_server, asio::use_awaitable);
        log(LogLevel::INFO, "Sent STUN Binding Request to secondary STUN server: " + secondary_stun_server.address().to_string() + ":" + std::to_string(secondary_stun_server.port()));

        // Receive STUN Binding Response from secondary STUN server
        asio::ip::udp::endpoint secondary_mapped_address;
        try {
            length = co_await socket_.async_receive_from(asio::buffer(response), sender_endpoint, asio::use_awaitable);
            secondary_mapped_address = parse_stun_binding_response(response, length);
            log(LogLevel::INFO, "Received STUN Binding Response from secondary STUN server: " + sender_endpoint.address().to_string() + ":" + std::to_string(sender_endpoint.port()));
        } catch (...) {
            log(LogLevel::WARNING, "No response from secondary STUN server.");
            return NatType::FullCone; // Assume Full Cone NAT if no response
        }

        // Compare MAPPED-ADDRESS
        if (primary_mapped_address != secondary_mapped_address) {
            return NatType::Symmetric; // Different MAPPED-ADDRESS implies Symmetric NAT
        }

        // Check if port is restricted
        if (primary_mapped_address.port() != stun_server.port()) {
            return NatType::PortRestrictedCone;
        }

        return NatType::RestrictedCone;
    } catch (const std::exception& ex) {
        log(LogLevel::ERROR, "NAT Type Detection Failed: " + std::string(ex.what()));
        return NatType::Unknown;
    }
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
            std::vector<uint8_t> keep_alive_request = create_stun_binding_request(selected_pair_);
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

// Connectivity check
awaitable<void> IceAgent::connectivity_check() {
    log(LogLevel::INFO, "Starting connectivity check...");
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