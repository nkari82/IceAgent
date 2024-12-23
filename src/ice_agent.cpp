// src/ice_agent.cpp

#include "ice_agent.hpp"
#include "hmac_sha1.hpp" // HMAC-SHA1 구현체 필요
#include "crc32.hpp"      // CRC32 구현체 필요
#include <iostream>
#include <thread>
#include <random>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <asio/experimental/parallel_group.hpp>
using namespace asio::experimental::awaitable_operators;

// Constants
constexpr int NUM_COMPONENTS = 1; // ICE 컴포넌트 수 (예: RTP, RTCP)
constexpr size_t MAX_CONCURRENT_CHECKS = 5; // 최대 동시 연결 검사 수
constexpr int MAX_RETRIES = 3;
const std::chrono::seconds INITIAL_BACKOFF = std::chrono::seconds(1);
const std::chrono::seconds MAX_BACKOFF = std::chrono::seconds(32);
constexpr double BACKOFF_MULTIPLIER = 2.0;
constexpr double BACKOFF_JITTER = 0.1; // 10%
	
static std::vector<uint8_t> serialize_uint32(uint32_t value) {
    std::vector<uint8_t> serialized(4);
    serialized[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    serialized[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    serialized[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    serialized[3] = static_cast<uint8_t>(value & 0xFF);
    return serialized;
}

// Constructor
IceAgent::IceAgent(asio::io_context& io_context, IceRole role, IceMode mode,
                   const std::vector<std::string>& stun_servers, 
                   const std::string& turn_server,
                   const std::string& turn_username, 
                   const std::string& turn_password,
                   std::chrono::seconds connectivity_check_timeout,
                   size_t connectivity_check_retries)
    : strand_(io_context.get_executor()),
      socket_(strand_),
      role_(role),
      mode_(mode),
      stun_servers_(stun_servers),
      turn_server_(turn_server),
      turn_username_(turn_username),
      turn_password_(turn_password),
      current_state_(IceConnectionState::New), 
      keep_alive_timer_(strand_),
      log_level_(LogLevel::INFO),
      connectivity_check_timeout_(connectivity_check_timeout),
      connectivity_check_retries_(connectivity_check_retries)
{
	// Generate ICE credentials
    std::random_device rd;
    std::mt19937 gen(rd());
	std::mt19937_64 gen64(rd());
    std::uniform_int_distribution<> dis(0, 255);
	std::uniform_int_distribution<uint64_t> dis64;
    ice_attributes_.ufrag = "u" + std::to_string(dis(gen)) + std::to_string(dis(gen));
    ice_attributes_.pwd = "p" + std::to_string(dis(gen)) + std::to_string(dis(gen));
	ice_attributes_.tie_breaker = dis64(gen);
	ice_attributes_.role = role;
	
    // STUN 클라이언트 초기화
    for (const auto& server : stun_servers_) {
        size_t colon_pos = server.find(':');
        if (colon_pos == std::string::npos) {
            log(LogLevel::WARNING, "Invalid STUN server address: " + server);
            continue;
        }
        std::string host = server.substr(0, colon_pos);
        uint16_t port = static_cast<uint16_t>(std::stoi(server.substr(colon_pos + 1)));
        auto stun_client = std::make_shared<StunClient>(strand_, host, port, ""); // 필요 시 키 제공
        stun_clients_.push_back(std::move(stun_client));
    }

    // TURN 클라이언트 초기화
    if (!turn_server_.empty()) {
        size_t colon_pos = turn_server_.find(':');
        if (colon_pos == std::string::npos) {
            log(LogLevel::WARNING, "Invalid TURN server address: " + turn_server_);
        }
        else {
            std::string host = turn_server_.substr(0, colon_pos);
            uint16_t port = static_cast<uint16_t>(std::stoi(turn_server_.substr(colon_pos + 1)));
            turn_client_ = std::make_shared<TurnClient>(strand_, host, port, turn_username_, turn_password_);
        }
    }

    // 소켓을 Dual-Stack으로 열기 (IPv6 소켓이 IPv4도 지원하도록)
    std::error_code ec;
    socket_.open(asio::ip::udp::v6(), ec);
    if(ec){
        log(LogLevel::WARNING, "Failed to open IPv6 socket: " + ec.message());
    }
    else{
        asio::ip::v6_only v6_option(false);
        socket_.set_option(v6_option, ec);
        if(ec){
            log(LogLevel::WARNING, "Failed to set IPv6 dual-stack option: " + ec.message());
        }
    }

    // Bind socket to any available port
    socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v6(), 0), ec);
    if(ec){
        log(LogLevel::ERROR, "Failed to bind UDP socket: " + ec.message());
        transition_to_state(IceConnectionState::Failed);
    }
}

// Destructor
IceAgent::~IceAgent() {
    std::error_code ec;
    socket_.close(ec);
    if(ec){
        log(LogLevel::WARNING, "Error closing socket: " + ec.message());
    }

    // 타이머 취소
    keep_alive_timer_.cancel();
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

void IceAgent::set_nominate_callback(NominateCallback cb) {
    nominate_callback_ = std::move(cb);
}

void IceAgent::set_signaling_client(std::shared_ptr<SignalingClient> signaling_client) {
    signaling_client_ = signaling_client;
}

// Set log level
void IceAgent::set_log_level(LogLevel level) {
    log_level_ = level;
}

// public
// Start ICE process
void IceAgent::start() {
	if (current_state_ == IceConnectionState::Gathering) {
		return;
	}

    // Spawn the main ICE initiation coroutine using a lambda and strand_
    asio::co_spawn(strand_,
        [this, self = shared_from_this()]() -> asio::awaitable<void> {
            try {
                nominated_pair_ = CandidatePair();
                check_list_.clear();
                remote_candidates_.clear();
                local_candidates_.clear();

                // Step 1: Gather Candidates
                co_await gather_candidates();

                // Exchange ICE parameters via signaling
                if (signaling_client_) {
					// Continue gathering and sending candidates if ICE-Trickle is supported
					// Handle sending candidates as they are gathered
					// This requires implementing candidate gathering callbacks or signals
				
                    // Create SDP message
                    std::vector<std::string> cand_strings;
                    for(const auto& cand : local_candidates_) {
                        cand_strings.push_back("a=" + cand.to_sdp());
                    }
                    std::string sdp = signaling_client_->create_sdp(ice_attributes_, cand_strings, mode_);
                    co_await signaling_client_->send_sdp(sdp);
                    
                    // Spawn a coroutine to handle incoming signaling messages
                    asio::co_spawn(strand_, handle_incoming_signaling_messages(), asio::detached);
                }

                if (mode_ == IceMode::Full) {
                    if (!transition_to_state(IceConnectionState::Checking)) {
                        co_return;
                    }

                    // Perform connectivity checks with retry logic
                    co_await perform_connectivity_checks();
                }
                else {
                    // In ICE Lite mode, skip connectivity checks
                    log(LogLevel::INFO, "ICE Lite mode: Skipping connectivity checks.");
                    transition_to_state(IceConnectionState::Connected); // Transition directly to Connected state
                    // **ICE Lite** assumes the remote side performs Full ICE; wait for Nominated Pair via add_remote_candidate
                }
                
				if (current_state_ == IceConnectionState::Connected || current_state_ == IceConnectionState::Completed) {
					if (mode_ == IceMode::Full) {
						// Spawn keep-alive coroutine only in Full mode
						asio::co_spawn(strand_, perform_keep_alive(), asio::detached);
					}

					// Spawn TURN allocation refresh coroutine if TURN is used
					if (turn_client_ && turn_client_->is_allocated()) {
						asio::co_spawn(strand_, perform_turn_refresh(), asio::detached);
					}

					// Start data reception
					asio::co_spawn(strand_, start_data_receive(), asio::detached);
				}
            } catch (const std::exception& ex) {
                log(LogLevel::ERROR, "Exception in ICE Agent: " + std::string(ex.what()));
                transition_to_state(IceConnectionState::Failed);
            }
            co_return;
        },
        asio::detached
    );
}

// Send data over established connection
void IceAgent::send_data(const std::vector<uint8_t>& data) {
    if (current_state_ != IceConnectionState::Connected && current_state_ != IceConnectionState::Completed) {
        log(LogLevel::WARNING, "Cannot send data: ICE is not connected.");
        return;
    }

    socket_.async_send_to(asio::buffer(data), nominated_pair_.remote_candidate.endpoint,
        [this](std::error_code ec, std::size_t bytes_sent) {
            if (ec) {
                log(LogLevel::ERROR, "Failed to send data: " + ec.message());
            } else {
                log(LogLevel::INFO, "Sent data: " + std::to_string(bytes_sent) + " bytes.");
            }
        });
}

// private
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

asio::awaitable<void> IceAgent::gather_candidates(uint32_t attempts) {
    try {
        co_await gather_local_candidates();
        co_await gather_srflx_candidates();
        co_await gather_relay_candidates();

        log(LogLevel::INFO, "Candidate gathering completed.");
        transition_to_state(IceConnectionState::Gathering); // Remain in Gathering until connectivity checks
    } catch (const std::exception& ex) {
        log(LogLevel::ERROR, "Error during candidate gathering: " + std::string(ex.what()));
        transition_to_state(IceConnectionState::Failed);
    }
    co_return;
}

// Gather local host candidates
asio::awaitable<void> IceAgent::gather_local_candidates() {
    log(LogLevel::INFO, "Gathering local candidates...");
    
    // Resolve both IPv4 and IPv6 local addresses
    asio::ip::udp::resolver resolver(strand_);
    asio::ip::udp::resolver::results_type results_v4 = co_await resolver.async_resolve(asio::ip::udp::v4(), "0.0.0.0", "0", asio::use_awaitable);
    asio::ip::udp::resolver::results_type results_v6 = co_await resolver.async_resolve(asio::ip::udp::v6(), "::", "0", asio::use_awaitable);

    auto add_candidate = [&](const asio::ip::udp::endpoint& endpoint) -> void {
        for (int component = 1; component <= NUM_COMPONENTS; ++component) { // 다중 컴포넌트 지원
			Candidate candidate;
			candidate.endpoint = endpoint;
			candidate.type = "host";
			candidate.foundation = "1";
			candidate.component_id = component;
			candidate.transport = "UDP";
			candidate.priority = calculate_priority(candidate); // Calculate priority dynamically

            local_candidates_.push_back(candidate);
            if (candidate_callback_) {
                candidate_callback_(candidate);
            }

            log(LogLevel::INFO, "Local Candidate gathered: " + candidate.endpoint.address().to_string() + ":" + std::to_string(candidate.endpoint.port()) +
                " [Component " + std::to_string(component) + "]");
        }
    };

    for (const auto& entry : results_v4) {
        add_candidate(entry.endpoint());
    }

    for (const auto& entry : results_v6) {
        if (entry.endpoint().address().is_v6() && entry.endpoint().address().is_v4_mapped()) {
            // Extract the embedded IPv4 address
            asio::ip::address_v4 addr_v4 = entry.endpoint().address().to_v4();
            asio::ip::address_v6 mapped_v6 = asio::ip::address_v6::v4_mapped(addr_v4);
            asio::ip::udp::endpoint mapped_endpoint(mapped_v6, entry.endpoint().port());

            add_candidate(mapped_endpoint);
        } else {
            add_candidate(entry.endpoint());
        }
    }

    co_return;
}

// Gather srflx candidates using STUN clients
asio::awaitable<void> IceAgent::gather_srflx_candidates() {
    if (stun_clients_.empty()) {
        log(LogLevel::WARNING, "No STUN clients available to gather srflx candidates.");
        co_return;
    }

    for (auto& stun_client : stun_clients_) {
        try {
            asio::ip::udp::endpoint mapped_endpoint = co_await stun_client->send_binding_request();

            for (int component = 1; component <= NUM_COMPONENTS; ++component) { // 다중 컴포넌트 지원
                // SRFLX 후보 생성
                Candidate srflx_candidate;
                srflx_candidate.endpoint = mapped_endpoint;
                srflx_candidate.type = "srflx";
                srflx_candidate.foundation = "SRFLX1";
                srflx_candidate.component_id = component;
                srflx_candidate.transport = "UDP";
				srflx_candidate.priority = calculate_priority(srflx_candidate);

                local_candidates_.push_back(srflx_candidate);
                log(LogLevel::INFO, "Added local srflx candidate: " + mapped_endpoint.address().to_string() + ":" + std::to_string(mapped_endpoint.port()) +
                    " [Component " + std::to_string(component) + "]");

                if (candidate_callback_) {
                    candidate_callback_(srflx_candidate);
                }

                // Candidate Pair 생성
                CandidatePair pair(srflx_candidate, Candidate());
                check_list_.emplace_back(pair);
            }

            // Handle IPv4-mapped IPv6 if applicable
            if(mapped_endpoint.address().is_v6() && mapped_endpoint.address().is_v4_mapped()){
                // Create IPv4-mapped IPv6 endpoint
                asio::ip::address_v6 addr_v6 = mapped_endpoint.address().to_v6();
                asio::ip::address_v4 addr_v4 = asio::ip::address_v4::any();
                asio::ip::address_v6 mapped_v6 = asio::ip::address_v6::v4_mapped(addr_v4);
                asio::ip::udp::endpoint mapped_v6_endpoint(mapped_v6, mapped_endpoint.port());

                for (int component = 1; component <= NUM_COMPONENTS; ++component) { // 다중 컴포넌트 지원
                    Candidate srflx_candidate_v6;
                    srflx_candidate_v6.endpoint = mapped_v6_endpoint;
                    srflx_candidate_v6.type = "srflx";
                    srflx_candidate_v6.foundation = "SRFLX2";
                    srflx_candidate_v6.component_id = component;
                    srflx_candidate_v6.transport = "UDP";
					srflx_candidate_v6.priority = calculate_priority(srflx_candidate);

                    local_candidates_.push_back(srflx_candidate_v6);
                    log(LogLevel::INFO, "Added local IPv4-mapped IPv6 srflx candidate: " + mapped_v6_endpoint.address().to_string() + ":" + std::to_string(mapped_v6_endpoint.port()) +
                        " [Component " + std::to_string(component) + "]");

                    if (candidate_callback_) {
                        candidate_callback_(srflx_candidate_v6);
                    }

                    // Candidate Pair 생성
                    CandidatePair pair_v6(srflx_candidate_v6, Candidate());
                    check_list_.emplace_back(pair_v6);
                }
            }
        } catch (const std::exception& ex) {
            log(LogLevel::WARNING, "Failed to gather srflx candidate from STUN client: " + std::string(ex.what()));
        }
    }
    co_return;
}

// Gather relay candidates via TURN client
asio::awaitable<void> IceAgent::gather_relay_candidates() {
    if (!turn_client_) {
        log(LogLevel::ERROR, "TurnClient not initialized.");
        co_return;
    }

    try {
        asio::ip::udp::endpoint relay_endpoint = co_await turn_client_->allocate_relay();
        log(LogLevel::INFO, "Allocated relay endpoint: " + relay_endpoint.address().to_string() + ":" + std::to_string(relay_endpoint.port()));

        for (int component = 1; component <= NUM_COMPONENTS; ++component) { // 다중 컴포넌트 지원
            // Relay Candidate 생성
            Candidate relay_candidate;
            relay_candidate.endpoint = relay_endpoint;
            relay_candidate.type = "relay";
            relay_candidate.foundation = "RELAY1";
            relay_candidate.component_id = component;
            relay_candidate.transport = "UDP";
			relay_candidate.priority = calculate_priority(relay_candidate);
			
            local_candidates_.push_back(relay_candidate);
            log(LogLevel::INFO, "Added local relay candidate: " + relay_endpoint.address().to_string() + ":" + std::to_string(relay_endpoint.port()) +
                " [Component " + std::to_string(component) + "]");

            if (candidate_callback_) {
                candidate_callback_(relay_candidate);
            }

            // Candidate Pair 생성
            CandidatePair pair(relay_candidate, Candidate());
            check_list_.emplace_back(pair);
        }

        // Handle IPv4-mapped IPv6 relay endpoints if applicable
        if(relay_endpoint.address().is_v6() && relay_endpoint.address().is_v4_mapped()){
            // Create IPv4-mapped IPv6 endpoint
            asio::ip::address_v6 addr_v6 = relay_endpoint.address().to_v6();
            asio::ip::address_v4 addr_v4 = asio::ip::address_v4::any();
            asio::ip::address_v6 mapped_v6 = asio::ip::address_v6::v4_mapped(addr_v4);
            asio::ip::udp::endpoint mapped_v6_relay_endpoint(mapped_v6, relay_endpoint.port());

            for (int component = 1; component <= NUM_COMPONENTS; ++component) { // 다중 컴포넌트 지원
                Candidate relay_candidate_v6;
                relay_candidate_v6.endpoint = mapped_v6_relay_endpoint;
                relay_candidate_v6.type = "relay";
                relay_candidate_v6.foundation = "RELAY2";
                relay_candidate_v6.component_id = component;
                relay_candidate_v6.transport = "UDP";
				relay_candidate_v6.priority = calculate_priority(relay_candidate_v6);

                local_candidates_.push_back(relay_candidate_v6);
                log(LogLevel::INFO, "Added local IPv4-mapped IPv6 relay candidate: " + mapped_v6_relay_endpoint.address().to_string() + ":" + std::to_string(mapped_v6_relay_endpoint.port()) +
                    " [Component " + std::to_string(component) + "]");

                if (candidate_callback_) {
                    candidate_callback_(relay_candidate_v6);
                }

                // Candidate Pair 생성
                CandidatePair pair_v6(relay_candidate_v6, Candidate());
                check_list_.emplace_back(pair_v6);
            }
        }
    } catch (const std::exception& ex) {
        log(LogLevel::ERROR, "Failed to allocate relay via TURN: " + std::string(ex.what()));
    }

    co_return;
}

// Perform a single connectivity check
asio::awaitable<void> IceAgent::perform_single_connectivity_check(CheckListEntry& entry) {
    const CandidatePair& pair = entry.pair;

    if (pair.remote_candidate.type == "srflx" || pair.remote_candidate.type == "host") {
        // STUN Binding Request를 사용한 연결 검사
        std::vector<uint8_t> txn_id = StunMessage::generate_transaction_id();
        StunMessage binding_request(StunMessageType::BINDING_REQUEST, txn_id);
        binding_request.add_attribute(StunAttributeType::PRIORITY, serialize_uint32(pair.local_candidate.priority));
        binding_request.add_attribute(StunAttributeType::USERNAME, ice_attributes_.username_fragment);
        binding_request.add_attribute(StunAttributeType::ICE_CONTROLLED, serialize_uint32(ice_attributes_.tie_breaker));
        binding_request.add_message_integrity(ice_attributes_.password); // MESSAGE-INTEGRITY 추가
        binding_request.add_fingerprint(); // FINGERPRINT 속성 추가
        std::vector<uint8_t> serialized_request = binding_request.serialize();

        // Binding Request 전송
        co_await socket_.async_send_to(asio::buffer(serialized_request), pair.remote_candidate.endpoint, asio::use_awaitable);

        // 타임아웃 설정
        asio::steady_timer timer(strand_);
        timer.expires_after(connectivity_check_timeout_);

        std::vector<uint8_t> recv_buffer(2048);
        asio::ip::udp::endpoint sender_endpoint;

        // STUN 응답 또는 타임아웃 대기
        auto [ec, bytes_received] = co_await (
            (socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable))
            || (timer.async_wait(asio::use_awaitable))
        );

        if (ec) {
            if (ec == asio::error::operation_aborted) {
                log(LogLevel::WARNING, "Connectivity check timed out for " + pair.remote_candidate.to_sdp());
                entry.state = CandidatePairState::Failed;
                co_return;
            } else {
                log(LogLevel::ERROR, "Connectivity check failed: " + std::string(ec.message()));
                entry.state = CandidatePairState::Failed;
                co_return;
            }
        }

        recv_buffer.resize(bytes_received);
        StunMessage response;
        try {
            response = StunMessage::parse(recv_buffer);
        } catch (const std::exception& ex) {
            log(LogLevel::WARNING, "Failed to parse STUN response: " + std::string(ex.what()));
            entry.state = CandidatePairState::Failed;
            co_return;
        }

        // 응답 검증
        if (response.get_transaction_id() != txn_id) {
            log(LogLevel::WARNING, "STUN Transaction ID mismatch.");
            entry.state = CandidatePairState::Failed;
            co_return;
        }

        // Verify message type
        StunMessageType msg_type = response.get_type();
        if (msg_type == StunMessageType::BINDING_RESPONSE_SUCCESS) {
            // Proceed with success handling
        } else if (msg_type == StunMessageType::BINDING_RESPONSE_ERROR) {
            // Extract error code and reason
            // Assuming proper attribute types are used
            uint16_t error_code = response.get_attribute_as_uint16(StunAttributeType::ERROR_CODE);
            std::string reason = response.get_attribute_as_string(StunAttributeType::ERROR_REASON);
            log(LogLevel::WARNING, "STUN Binding Error " + std::to_string(error_code) + ": " + reason);
            entry.state = CandidatePairState::Failed;
            co_return;
        } else {
            log(LogLevel::WARNING, "Unexpected STUN message type received.");
            entry.state = CandidatePairState::Failed;
            co_return;
        }
        
        // Verify MESSAGE-INTEGRITY and FINGERPRINT
        if (!response.verify_message_integrity(ice_attributes_.password)) {
            log(LogLevel::WARNING, "Invalid MESSAGE-INTEGRITY in STUN response.");
            entry.state = CandidatePairState::Failed;
            co_return;
        }
        
        if (!response.verify_fingerprint()) {
            log(LogLevel::WARNING, "Invalid FINGERPRINT in STUN response.");
            entry.state = CandidatePairState::Failed;
            co_return;
        }

        // MAPPED-ADDRESS 추출
        std::vector<uint8_t> xma_bytes = response.get_attribute_as_bytes(StunAttributeType::XOR_MAPPED_ADDRESS);
        if (xma_bytes.empty()) {
            log(LogLevel::WARNING, "XOR-MAPPED-ADDRESS attribute missing in STUN response.");
            entry.state = CandidatePairState::Failed;
            co_return;
        }
        // Parsing XOR-MAPPED-ADDRESS according to RFC 5389
        asio::ip::udp::endpoint mapped_endpoint = StunMessage::parse_xor_mapped_address(xma_bytes);

        // 성공 처리
        entry.state = CandidatePairState::Succeeded;
        log(LogLevel::INFO, "Connectivity check succeeded with " + pair.remote_candidate.to_sdp());

        co_return;
    }
    else if (pair.remote_candidate.type == "relay") {
        // TURN Send를 사용한 릴레이 연결 검사 (데이터 전송)
        std::vector<uint8_t> data = { 'D', 'A', 'T', 'A' };
        co_await socket_.async_send_to(asio::buffer(data), pair.remote_candidate.endpoint, asio::use_awaitable);
        log(LogLevel::INFO, "Sent data via TURN relay to " +
            pair.remote_candidate.endpoint.address().to_string() + ":" +
            std::to_string(pair.remote_candidate.endpoint.port()) +
            " [Component " + std::to_string(pair.local_candidate.component_id) + "]");

        // 타임아웃 설정
        asio::steady_timer timer(strand_);
        timer.expires_after(connectivity_check_timeout_);

        std::vector<uint8_t> recv_buffer(2048);
        asio::ip::udp::endpoint sender_endpoint_recv;

        using namespace asio::experimental::awaitable_operators;
        auto [ec, bytes_transferred] = co_await (
            (socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint_recv, asio::use_awaitable))
            || (timer.async_wait(asio::use_awaitable))
        );

        if (ec) {
            if (ec == asio::error::operation_aborted) {
                log(LogLevel::WARNING, "Relay connectivity check timed out for " + pair.remote_candidate.to_sdp());
                entry.state = CandidatePairState::Failed;
                co_return;
            } else {
                log(LogLevel::ERROR, "Relay connectivity check failed: " + std::string(ec.message()));
                entry.state = CandidatePairState::Failed;
                co_return;
            }
        }

        if (bytes_transferred > 0) {
            // 성공 처리
            entry.state = CandidatePairState::Succeeded;
            log(LogLevel::INFO, "Relay connectivity check succeeded with " + pair.remote_candidate.to_sdp());
        } else {
            log(LogLevel::WARNING, "No data received from relay.");
            entry.state = CandidatePairState::Failed;
        }
    }

    co_return;
}

// Perform connectivity checks
asio::awaitable<void> IceAgent::perform_connectivity_checks(uint32_t attempts) {
    try {
        if (check_list_.empty()) {
            log(LogLevel::WARNING, "No candidate pairs to check.");
            co_return;
        }

        // Sort candidate pairs based on priority
        sort_candidate_pairs();

        // Limit the number of concurrent checks
        size_t concurrent_checks = std::min(MAX_CONCURRENT_CHECKS, check_list_.size());

        // Launch concurrent connectivity checks
        std::vector<asio::awaitable<void>> checks;
        for (size_t i = 0; i < concurrent_checks; ++i) {
            checks.emplace_back([this, i]() -> asio::awaitable<void> {
				CheckListEntry& entry = check_list_[i];

				// Exponential backoff parameters
				std::chrono::seconds backoff_delay = INITIAL_BACKOFF;
		
				while (entry.retry_count < MAX_RETRIES) {
					if (entry.state == CandidatePairState::New || (entry.state == CandidatePairState::Failed)) {
						entry.state = CandidatePairState::InProgress;
						
						co_await perform_single_connectivity_check(entry);
						
						if(entry.state == CandidatePairState::Failed) {
							entry.retry_count++;
							
							// Calculate backoff delay with jitter
							double jitter_fraction = BACKOFF_JITTER * ((double)rand() / RAND_MAX); // 0 to 0.1
							std::chrono::seconds jitter_duration = std::chrono::duration_cast<std::chrono::seconds>(
								std::chrono::duration<double>(backoff_delay.count() * jitter_fraction));
							std::chrono::seconds total_delay = backoff_delay + jitter_duration;
				
							log("Retrying connectivity check for " + entry.pair.remote_candidate.to_sdp() +
								" after " + std::to_string(total_delay.count()) + " seconds. Retry #" + std::to_string(entry.retry_count), "INFO");
				
							// Wait for backoff_delay
							asio::steady_timer timer(strand_);
							timer.expires_after(total_delay);
							co_await timer.async_wait(asio::use_awaitable);
				
							// Exponentially increase the backoff_delay
							backoff_delay = std::chrono::seconds(static_cast<int>(backoff_delay.count() * BACKOFF_MULTIPLIER));
							if (backoff_delay > MAX_BACKOFF) {
								backoff_delay = MAX_BACKOFF;
							}
						}
						else
						{
							break;
						}
					}
				}
				
                co_return;
            }());
        }

        co_await (checks.begin(), checks.end());

        // Evaluate results
        co_await evaluate_connectivity_results();

    } catch (const std::exception& ex) {
        log(LogLevel::ERROR, "Exception during connectivity checks: " + std::string(ex.what()));
        transition_to_state(IceConnectionState::Failed);
    }

    co_return;
}

// Evaluate connectivity results and nominate pairs
asio::awaitable<void> IceAgent::evaluate_connectivity_results() {
    bool any_succeeded = false;
    for (auto& entry : check_list_) {
        if (entry.state == CandidatePairState::Succeeded && !entry.is_nominated) {
            co_await nominate_pair(entry);
            any_succeeded = true;
            break; // 첫 번째 성공한 페어를 지명
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

// Implement connectivity keep-alive
asio::awaitable<void> IceAgent::perform_keep_alive() {
    while (current_state_ == IceConnectionState::Connected) {
        // Keep-Alive 간격 (예: 30초)
        keep_alive_timer_.expires_after(std::chrono::seconds(30));
        co_await keep_alive_timer_.async_wait(asio::use_awaitable);

        log(LogLevel::INFO, "Performing periodic connectivity check (Keep-Alive).");

        // Connectivity Checks 수행
        co_await perform_connectivity_checks();
    }
    co_return;
}

// Implement TURN allocation refresh
asio::awaitable<void> IceAgent::perform_turn_refresh() {
    while (current_state_ == IceConnectionState::Connected && turn_client_ && turn_client_->is_allocated()) {
        asio::steady_timer refresh_timer(strand_);
        refresh_timer.expires_after(std::chrono::seconds(300)); // 예시: 5분마다
        co_await refresh_timer.async_wait(asio::use_awaitable);

        try {
            co_await turn_client_->refresh_allocation();
            log(LogLevel::INFO, "TURN allocation refreshed.");
        } catch (const std::exception& ex) {
            log(LogLevel::ERROR, "Failed to refresh TURN allocation: " + std::string(ex.what()));
            transition_to_state(IceConnectionState::Failed);
        }
    }
    co_return;
}

// Start data reception
asio::awaitable<void> IceAgent::start_data_receive() {
    while (current_state_ == IceConnectionState::Connected || current_state_ == IceConnectionState::Completed) {
        std::vector<uint8_t> recv_buffer(2048);
        asio::ip::udp::endpoint sender_endpoint;
        std::error_code ec;
        size_t bytes_received = 0;
        try {
            bytes_received = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);
        } catch (const std::exception& ex) {
            log(LogLevel::ERROR, "Failed to receive data: " + std::string(ex.what()));
            transition_to_state(IceConnectionState::Failed);
            break;
        }

        if (bytes_received > 0) {
            recv_buffer.resize(bytes_received);
            if (data_callback_) {
                data_callback_(recv_buffer, sender_endpoint);
            }
            log(LogLevel::INFO, "Received data: " + std::to_string(bytes_received) + " bytes from " +
                sender_endpoint.address().to_string() + ":" + std::to_string(sender_endpoint.port()) +
                " (" + (sender_endpoint.address().is_v6() ? "IPv6" : "IPv4") + ")");
        }
    }
    co_return;
}

// RFC 8445에 따른 우선순위 계산
uint32_t IceAgent::calculate_priority(const Candidate& local) const {
   uint32_t type_pref;
    switch (candidate.type) {
        case CandidateType::Host:
            type_pref = 126;
            break;
        case CandidateType::PeerReflexive:
            type_pref = 110;
            break;
        case CandidateType::ServerReflexive:
            type_pref = 100;
            break;
        case CandidateType::Relay:
            type_pref = 0;
            break;
        default:
            type_pref = 0;
    }

    uint32_t local_pref = 65535; // Can be adjusted as needed
    uint32_t component_id = static_cast<uint32_t>(candidate.component_id);

    // RFC 8445 Priority Calculation: (type-preference << 24) | (local-preference << 8) | (256 - component-id)
    return (type_pref << 24) | (local_pref << 8) | (256 - component_id);
}

uint64_t IceAgent::calculate_priority_pair(const Candidate& local, const Candidate& remote) const {
	uint32_t min_priority = std::min(local.priority, remote.priority);
    uint32_t max_priority = std::max(local.priority, remote.priority);
    uint64_t pair_priority = (static_cast<uint64_t>(min_priority) << 32) |
                             (static_cast<uint64_t>(max_priority) << 1) |
                             ((local.priority > remote.priority) ? 1 : 0);
    return pair_priority;
}

// Sort candidate pairs based on priority
void IceAgent::sort_candidate_pairs() {
    std::sort(check_list_.begin(), check_list_.end(), [&](const CheckListEntry& a, const CheckListEntry& b) {
        // Higher priority first
        if (a.pair.priority != b.pair.priority){
            return a.pair.priority > b.pair.priority;
        }
        // Prefer lower component ID
        if (a.pair.local_candidate.component_id != b.pair.local_candidate.component_id){
            return a.pair.local_candidate.component_id < b.pair.local_candidate.component_id;
        }
        // Prefer host over srflx over relay
        auto type_order = [](const std::string& type) -> int {
            if(type == "host") return 3;
            if(type == "srflx") return 2;
            if(type == "relay") return 1;
            return 0;
        };
        if (type_order(a.pair.local_candidate.type) != type_order(b.pair.local_candidate.type)){
            return type_order(a.pair.local_candidate.type) > type_order(b.pair.local_candidate.type);
        }	
		// Prefer IPv4 over IPv6 if priorities are equal
		if (a.pair.remote_candidate.endpoint.address().is_v4() && b.pair.remote_candidate.endpoint.address().is_v6()){
			return true;
		}
        // Additional sorting criteria as needed
        return false;
    });
}

// Logging function with timestamp
void IceAgent::log(LogLevel level, const std::string& message) {
    if (level >= log_level_) {
        // Include thread ID for better traceability in multi-threaded environments
        std::ostringstream oss;
        oss << "[";
        switch (level) {
            case LogLevel::DEBUG: oss << "DEBUG"; break;
            case LogLevel::INFO: oss << "INFO"; break;
            case LogLevel::WARNING: oss << "WARNING"; break;
            case LogLevel::ERROR: oss << "ERROR"; break;
        }
        oss << "] ";
        // Timestamp
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        oss << "[" << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S") << "] ";
        oss << message;
        std::cout << oss.str() << std::endl;
    }
}

// Negotiate role based on remote signaling
void IceAgent::negotiate_role(uint64_t remote_tie_breaker) {
    if (ice_attributes_.tie_breaker > remote_tie_breaker) {
        role_ = IceRole::Controller;
        remote_role_ = IceRole::Controlled;
    } else {
        role_ = IceRole::Controlled;
        remote_role_ = IceRole::Controller;
    }
    log(LogLevel::INFO, "Negotiated role: " + std::to_string(static_cast<int>(role_)));
}

// Send NOMINATE message using STUN Binding Indication with USE-CANDIDATE attribute
asio::awaitable<void> IceAgent::send_nominate(const CheckListEntry& entry) {
    std::vector<uint8_t> txn_id = StunMessage::generate_transaction_id();

    StunMessage nominate_msg(StunMessageType::BINDING_INDICATION, txn_id);
    // USE-CANDIDATE 속성 추가
    nominate_msg.add_attribute(StunAttributeType::USE_CANDIDATE, std::vector<uint8_t>()); // 빈 값

    // ICE-CONTROLLING 속성 추가
    if (role_ == IceRole::Controller) {
		uint64_t tie_breaker = ice_attributes_.tie_breaker;
		std::vector<uint8_t> tie_breaker_bytes(8);
		for(int i = 0; i < 8; ++i) {
			tie_breaker_bytes[7 - i] = tie_breaker & 0xFF;
			tie_breaker >>= 8;
		}
        nominate_msg.add_attribute(StunAttributeType::ICE_CONTROLLING, tie_breaker_bytes);
    }

    // MESSAGE-INTEGRITY 추가
    std::vector<uint8_t> serialized_without_integrity = nominate_msg.serialize_without_attributes({ StunAttributeType::MESSAGE_INTEGRITY, StunAttributeType::FINGERPRINT });
    std::vector<uint8_t> hmac = HmacSha1::calculate(ice_attributes_.password, serialized_without_integrity);
    nominate_msg.add_attribute(StunAttributeType::MESSAGE_INTEGRITY, hmac);

    // FINGERPRINT 추가
    nominate_msg.add_fingerprint();
    std::vector<uint8_t> serialized_nominate = nominate_msg.serialize();

    co_await socket_.async_send_to(asio::buffer(serialized_nominate), entry.pair.remote_candidate.endpoint, asio::use_awaitable);

    log(LogLevel::INFO, "Sent NOMINATE to " +
        entry.pair.remote_candidate.endpoint.address().to_string() + ":" +
        std::to_string(entry.pair.remote_candidate.endpoint.port()) +
        " [Component " + std::to_string(entry.pair.local_candidate.component_id) + "]");

    // NOMINATE 전송 완료 알림
    if (nominate_callback_) {
        nominate_callback_(entry.pair);
    }

    co_return;
}

// Add remote candidate received via signaling
asio::awaitable<void> IceAgent::add_remote_candidate(const std::vector<Candidate>& candidates) {
    for(const auto& candidate : candidates) {
		log(LogLevel::INFO, "Added remote candidate: " + candidate.to_sdp());
		remote_candidates_.push_back(candidate);
		
		// Notify via callback
		if (candidate_callback_) {
			candidate_callback_(candidate);
		}
	
		// Create Candidate Pairs
		for (const auto& local : local_candidates_) {
			if (local.component_id == candidate.component_id) { // Pair only for the same component
				CandidatePair pair(local, candidate);
				pair.priority = calculate_priority_pair(local, candidate);
				check_list_.emplace_back(pair);
			}
		}
	}
	
	if (mode_ == IceMode::Full) {
		co_await perform_connectivity_checks();
	}
	co_return;
}

// Handle incoming signaling messages and process ICE parameters
asio::awaitable<void> IceAgent::handle_incoming_signaling_messages() {
    while (current_state_ != IceConnectionState::Failed && current_state_ != IceConnectionState::Completed) {
        try {
            std::string sdp = co_await signaling_client_->receive_sdp();
    
            // SDP 메시지 파싱
			auto [remote_ice_attributes,  remote_candidates] = signaling_client_->parse_sdp(sdp);
			remote_ice_attributes_ = remote_ice_attributes;

			// Negotiate role based on tie-breaker
			negotiate_role(remote_ice_attributes_.remote_tie_breaker);

            // 원격 후보 파싱 및 추가
			co_await add_remote_candidate(remote_candidates);

            // 역할 협상에 따른 처리
            if (remote_ice_attributes_.remote_role == IceRole::Controller && ice_attributes_.role == IceRole::Controlled) {
                // Controlled 역할에서는 Controller의 NOMINATE 메시지를 기다림
                // Binding Indication 메시지(USE-CANDIDATE)를 수신하여 처리
                // Binding Indication 수신 코루틴 시작은 이미 start()에서 수행됨
                asio::co_spawn(strand_, listen_for_binding_indications(), asio::detached);
                log(LogLevel::INFO, "Started listening for Binding Indication messages (USE-CANDIDATE) as Controlled role.");
            }
			else if (remote_ice_attributes_.role == IceRole::Controlled && ice_attributes_.role == IceRole::Controller) {
				if (mode_ == IceMode::Lite) {
					// Ice Lite 에이전트는 일반적으로 Controlled 역할만 수행하므로 이 경우 예외 처리 필요
					log(LogLevel::ERROR, "ICE Lite agent should not negotiate as Controller.");
					transition_to_state(IceConnectionState::Failed);
				}
            }
        } catch (const std::exception& ex) {
            log(LogLevel::ERROR, "Error handling signaling message: " + std::string(ex.what()));
            transition_to_state(IceConnectionState::Failed);
        }
    }
    co_return;
}

// Nominate a successful candidate pair based on role
asio::awaitable<void> IceAgent::nominate_pair(CheckListEntry& entry) {
    entry.is_nominated = true;
    nominated_pair_ = entry.pair;
    
    if (role_ == IceRole::Controller) {
        // Send NOMINATE message
        co_await send_nominate(entry);
    }
    else if (role_ == IceRole::Controlled) {
        // In Controlled role, NOMINATE is handled via received Binding Indication (USE-CANDIDATE)
        log(LogLevel::INFO, "Nominated pair based on USE-CANDIDATE from Controller: " + entry.pair.remote_candidate.to_sdp());
        
        // Trigger nomination callback
        if (nominate_callback_) {
            nominate_callback_(entry.pair);
        }
        
        // Transition to Completed state
        transition_to_state(IceConnectionState::Completed);
    }
    
    co_return;
}

// Binding Indication 메시지를 지속적으로 수신하고 처리하는 코루틴
asio::awaitable<void> IceAgent::listen_for_binding_indications() {
    log(LogLevel::DEBUG, "Started listening for Binding Indication messages (USE-CANDIDATE).");
    while (current_state_ != IceConnectionState::Failed && current_state_ != IceConnectionState::Completed) {
        try {
            std::vector<uint8_t> recv_buffer(2048);
            asio::ip::udp::endpoint sender_endpoint;
            std::error_code ec;
            size_t bytes_received = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);
            
            if (bytes_received == 0) {
                continue; // 빈 메시지는 무시
            }
            
            recv_buffer.resize(bytes_received);
            StunMessage msg = StunMessage::parse(recv_buffer);
            
            if (msg.get_type() == StunMessageType::BINDING_INDICATION) {
                log(LogLevel::DEBUG, "Received Binding Indication (USE-CANDIDATE) from " + sender_endpoint.address().to_string() + ":" + std::to_string(sender_endpoint.port()));
                co_await handle_binding_indication(msg, sender_endpoint);
            }
        } catch (const std::exception& ex) {
            log(LogLevel::ERROR, "Error receiving Binding Indication: " + std::string(ex.what()));
            transition_to_state(IceConnectionState::Failed);
            break;
        }
    }
    co_return;
}

// Handle Binding Indication messages (USE-CANDIDATE) from Controller
asio::awaitable<void> IceAgent::handle_binding_indication(const StunMessage& msg, const asio::ip::udp::endpoint& sender) {
    // USE-CANDIDATE 속성 존재 여부 확인
    if (msg.has_attribute(StunAttributeType::USE_CANDIDATE)) {
        // Controlled 역할에서는 Controller의 NOMINATE 메시지를 받으면 해당 페어를 후보로 선정
        for (auto& entry : check_list_) {
            if (entry.state == CandidatePairState::Succeeded && !entry.is_nominated) {
                co_await nominate_pair(entry); // Controlled라면 내부에서 Complete상태로 변경한다.
                break; // 첫 번째 성공한 페어를 지명
            }
        }
    }

    co_return;
}

#endif // ICE_AGENT_HPP
