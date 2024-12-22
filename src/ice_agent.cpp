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
                   std::chrono::seconds candidate_gather_timeout,
                   size_t candidate_gather_retries,
                   std::chrono::seconds connectivity_check_timeout,
                   size_t connectivity_check_retries)
    : strand_(io_context.get_executor())
	  io_context_(io_context),
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
      connectivity_checks_running_(false),
      candidate_gather_timeout_(candidate_gather_timeout),
      candidate_gather_retries_(candidate_gather_retries),
      connectivity_check_timeout_(connectivity_check_timeout),
      connectivity_check_retries_(connectivity_check_retries),
      remote_role_(IceRole::Controlled) // 기본 역할 설정
{
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

void IceAgent::set_nat_type_callback(NatTypeCallback cb) {
    on_nat_type_detected_ = cb;
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

    // Transition from New to Gathering
    if (!transition_to_state(IceConnectionState::Gathering)) {
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

                // Generate ICE credentials
                std::random_device rd;
                {
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<> dis(0, 255);
                    ice_attributes_.username_fragment = "u" + std::to_string(dis(gen)) + std::to_string(dis(gen));
                    ice_attributes_.password = "p" + std::to_string(dis(gen)) + std::to_string(dis(gen));
                }

                // Tie-breaker generation
                {
                    std::mt19937_64 gen(rd());
                    std::uniform_int_distribution<uint64_t> dis;
                    ice_attributes_.tie_breaker = dis(gen);
                }

                // Exchange ICE parameters via signaling
                if (signaling_client_) {
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
                
                if (current_state_ == IceConnectionState::Connected) {
                    // Spawn keep-alive coroutine
                    asio::co_spawn(strand_, perform_keep_alive(), asio::detached);
                
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

// Add remote candidate received via signaling
void IceAgent::add_remote_candidate(const Candidate& candidate) {
    // Spawn the remote candidate handling coroutine using a lambda and strand_
    asio::co_spawn(strand_,
        [this, self = shared_from_this(), candidate]() -> asio::awaitable<void> {
            remote_candidates_.push_back(candidate);
            log(LogLevel::INFO, "Added remote candidate: " + candidate.to_sdp());

            // Notify via callback
            if (candidate_callback_) {
                candidate_callback_(candidate);
            }

            // Create Candidate Pairs
            for (const auto& local : local_candidates_) {
                if (local.component_id == candidate.component_id) { // Pair only for the same component
                    CandidatePair pair(local, candidate);
                    pair.priority = calculate_priority(local, candidate);
                    check_list_.emplace_back(pair);
                }
            }

            // Perform connectivity checks if not already running (Full ICE mode)
            if (mode_ == IceMode::Full && !connectivity_checks_running_) {
                connectivity_checks_running_ = true;
                co_await perform_connectivity_checks();
                connectivity_checks_running_ = false;
            }
            co_return;
        },
        asio::detached
    );
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

// Gather Candidates with Timeout and Retry Logic
asio::awaitable<void> IceAgent::gather_candidates(uint32_t attempts) {
    try {
        // 후보 수집과 타임아웃을 병렬로 처리
        asio::steady_timer gather_timer(strand_);
        gather_timer.expires_after(candidate_gather_timeout_);

        bool gather_completed = false;
        std::exception_ptr gather_exception = nullptr;

        // 후보 수집 코루틴
        auto gather_coroutine = [this, &gather_completed, &gather_exception]() -> asio::awaitable<void> {
            try {
                // 로컬 후보 수집
                co_await gather_local_candidates();

                // srflx 후보 수집
                co_await gather_srflx_candidates();

                // NAT 타입 기반 후보 수집
                NatType nat_type = co_await detect_nat_type();

                // 콜백 알림
                if (on_nat_type_detected_) {
                    on_nat_type_detected_(nat_type);
                }

                switch (nat_type) {
                    case NatType::FullCone:
                    case NatType::RestrictedCone:
                    case NatType::PortRestrictedCone:
                        log(LogLevel::INFO, "Detected NAT type supports direct peer-to-peer connections.");
                        break;
                    case NatType::Symmetric:
                        log(LogLevel::INFO, "Detected Symmetric NAT. Gathering relay candidates via TURN.");
                        if (turn_client_) {
                            co_await gather_relay_candidates();
                        } else {
                            log(LogLevel::WARNING, "TURN server not configured. Relay candidates cannot be gathered.");
                        }
                        break;
                    case NatType::OpenInternet:
                        log(LogLevel::INFO, "No NAT detected. Direct peer-to-peer connections are straightforward.");
                        break;
                    default:
                        log(LogLevel::WARNING, "Unknown NAT type. Proceeding with default candidate gathering.");
                        break;
                }
            } catch (...) {
                gather_exception = std::current_exception();
            }
            gather_completed = true;
        };

        // 병렬로 후보 수집과 타임아웃 대기
        co_await (
            (gather_coroutine() && asio::use_awaitable) ||
            (gather_timer.async_wait(asio::use_awaitable))
        );

        if (gather_completed) {
            gather_timer.cancel(); // 타이머 취소
        }

        if (!gather_completed || gather_exception) {
            if(gather_completed) {
                log(LogLevel::WARNING, "Candidate gathering attempt " + std::to_string(attempts) + " failed.");
            }
            else {
                // 타임아웃 발생
                log(LogLevel::ERROR, "Candidate gathering timed out after " + std::to_string(candidate_gather_timeout_.count()) + " seconds.");
            }
            
            attempts++;
            if (attempts >= candidate_gather_retries_) {
                log(LogLevel::ERROR, "Maximum candidate gathering retries exceeded.");
                throw std::runtime_error("Candidate gathering timed out after maximum retries.");
            } else {
                log(LogLevel::INFO, "Retrying candidate gathering...");
                remote_candidates_.clear();
                check_list_.clear();
                local_candidates_.clear();
                co_await gather_candidates(attempts); // 재귀 호출로 재시도
            }
        }

        co_return;
    } catch (...) {
        log(LogLevel::ERROR, "Exception during candidate gathering: " + std::string(std::current_exception() ? "Unknown exception" : "No exception"));
        transition_to_state(IceConnectionState::Failed);
    }
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
            candidate.priority = 65535; // 높은 우선순위
            candidate.type = "host";
            candidate.foundation = "1";
            candidate.component_id = component;
            candidate.transport = "UDP";

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
                srflx_candidate.priority = 1000000; // Host 후보보다 높은 우선순위
                srflx_candidate.type = "srflx";
                srflx_candidate.foundation = "SRFLX1";
                srflx_candidate.component_id = component;
                srflx_candidate.transport = "UDP";

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
                    srflx_candidate_v6.priority = 1000000; // Host 후보보다 높은 우선순위
                    srflx_candidate_v6.type = "srflx";
                    srflx_candidate_v6.foundation = "SRFLX2";
                    srflx_candidate_v6.component_id = component;
                    srflx_candidate_v6.transport = "UDP";

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
            relay_candidate.priority = 900000; // Host 및 srflx 후보보다 낮은 우선순위
            relay_candidate.type = "relay";
            relay_candidate.foundation = "RELAY1";
            relay_candidate.component_id = component;
            relay_candidate.transport = "UDP";

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
                relay_candidate_v6.priority = 900000; // Host 및 srflx 후보보다 낮은 우선순위
                relay_candidate_v6.type = "relay";
                relay_candidate_v6.foundation = "RELAY2";
                relay_candidate_v6.component_id = component;
                relay_candidate_v6.transport = "UDP";

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
        StunMessage binding_request(STUN_BINDING_REQUEST, txn_id);
        binding_request.add_attribute(StunAttributeType::PRIORITY, serialize_uint32(pair.local_candidate.priority));
        binding_request.add_attribute(StunAttributeType::USERNAME, ice_attributes_.username_fragment);
        binding_request.add_message_integrity(ice_attributes_.password); // StunMessage가 이 기능을 지원해야 함
        binding_request.add_fingerprint(); // FINGERPRINT 속성 추가
        std::vector<uint8_t> serialized_request = binding_request.serialize();

        // Binding Request 전송
        co_await socket_.async_send_to(asio::buffer(serialized_request), pair.remote_candidate.endpoint, asio::use_awaitable);

        // 타임아웃 설정
        asio::steady_timer timer(strand_);
        timer.expires_after(connectivity_check_timeout_);

        std::vector<uint8_t> recv_buffer(2048);
        asio::ip::udp::endpoint sender_endpoint;

        using namespace asio::experimental::awaitable_operators;
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
                if (entry.state == CandidatePairState::New) {
                    entry.state = CandidatePairState::InProgress;
                    co_await perform_single_connectivity_check(entry);
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

// Infer NAT Type based on mapped endpoints
NatType IceAgent::infer_nat_type(const std::vector<asio::ip::udp::endpoint>& mapped_endpoints) {
    // 기본 검사
    if (mapped_endpoints.empty()) {
        return NatType::Symmetric;
    }

    // 고유한 IP와 포트 수 집계
    std::vector<asio::ip::address_v4> unique_ips;
    std::vector<uint16_t> unique_ports;

    for (const auto& ep : mapped_endpoints) {
        // 고유한 IP 확인
        if (std::find(unique_ips.begin(), unique_ips.end(), ep.address().to_v4()) == unique_ips.end()) {
            unique_ips.push_back(ep.address().to_v4());
        }

        // 고유한 포트 확인
        if (std::find(unique_ports.begin(), unique_ports.end(), ep.port()) == unique_ports.end()) {
            unique_ports.push_back(ep.port());
        }
    }

    // 고유한 IP와 포트를 기반으로 NAT 타입 분석
    if (unique_ips.size() == 1) {
        if (unique_ports.size() == 1) {
            // 모든 STUN 서버에서 동일한 IP와 포트
            return NatType::FullCone;
        } else {
            // 동일한 IP지만 포트가 다른 경우
            return NatType::RestrictedCone;
        }
    } else {
        if (unique_ports.size() == 1) {
            // 서로 다른 IP지만 동일한 포트
            return NatType::PortRestrictedCone;
        } else {
            // 서로 다른 IP와 포트
            return NatType::Symmetric;
        }
    }

    // 기본값
    return NatType::Unknown;
}

// RFC 8445에 따른 우선순위 계산
uint32_t IceAgent::calculate_priority(const Candidate& local, const Candidate& remote) const {
    uint32_t type_pref;
    if (local.type == "host") type_pref = 126;
    else if (local.type == "srflx") type_pref = 100;
    else if (local.type == "relay") type_pref = 0;
    else type_pref = 0; // Default

    // Local preference can be dynamic or configurable
    uint32_t local_pref = 65535; // Typically, host candidates have higher local preference
    if (local.type == "srflx") {
        local_pref = 10000;
    } else if (local.type == "relay") {
        local_pref = 5000;
    }

    uint32_t component_id = static_cast<uint32_t>(local.component_id);

    // RFC8445 Priority Calculation: (Type Preference << 24) + (Local Preference << 8) + (256 - Component ID)
    return (type_pref << 24) | (local_pref << 8) | (256 - component_id);
}

// Sort candidate pairs based on priority
void IceAgent::sort_candidate_pairs() {
    std::sort(check_list_.begin(), check_list_.end(), [&](const CheckListEntry& a, const CheckListEntry& b) {
        // Higher priority first
        if(a.pair.priority != b.pair.priority){
            return a.pair.priority > b.pair.priority;
        }
        // Prefer IPv4 over IPv6 if priorities are equal
        if(a.pair.remote_candidate.endpoint.address().is_v4() && b.pair.remote_candidate.endpoint.address().is_v6()){
            return true;
        }
        if(a.pair.remote_candidate.endpoint.address().is_v6() && b.pair.remote_candidate.endpoint.address().is_v4()){
            return false;
        }
        return false;
    });
}

// Logging function with timestamp
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
        // 타임스탬프 추가
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::cout << "[" << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S") << "] " << message << std::endl;
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

// Negotiate role based on remote signaling
void IceAgent::negotiate_role(IceRole remote_role, uint64_t remote_tie_breaker) {
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
asio::awaitable<void> IceAgent::send_nominate(const CandidatePair& pair) {
    std::vector<uint8_t> txn_id = StunMessage::generate_transaction_id();

    StunMessage nominate_msg(StunMessageType::BINDING_INDICATION, txn_id);
    // USE-CANDIDATE 속성 추가
    nominate_msg.add_attribute(StunAttributeType::USE_CANDIDATE, std::vector<uint8_t>()); // 빈 값

    // Controller 역할인 경우 ICE-CONTROLLING 속성 추가
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

    co_await socket_.async_send_to(asio::buffer(serialized_nominate), pair.remote_candidate.endpoint, asio::use_awaitable);

    log(LogLevel::INFO, "Sent NOMINATE to " +
        pair.remote_candidate.endpoint.address().to_string() + ":" +
        std::to_string(pair.remote_candidate.endpoint.port()) +
        " [Component " + std::to_string(pair.local_candidate.component_id) + "]");

    // NOMINATE 전송 완료 알림
    if (nominate_callback_) {
        nominate_callback_(pair);
    }

    co_return;
}

// Handle incoming signaling messages and process ICE parameters
asio::awaitable<void> IceAgent::handle_incoming_signaling_messages() {
    while (current_state_ != IceConnectionState::Failed) {
        try {
            std::string sdp = co_await signaling_client_->receive_sdp();

            // SDP 메시지 파싱
            std::vector<std::string> remote_candidates;
            std::string remote_ufrag;
            std::string remote_pwd;
            uint64_t remote_tie_breaker;
            std::tie(remote_ufrag, remote_pwd, remote_tie_breaker) = signaling_client_->parse_sdp(sdp, remote_candidates);

            // Update ICE attributes
          	ice_attributes_.username_fragment = remote_ufrag;
            ice_attributes_.password = remote_pwd;

            // 원격 후보 파싱 및 추가
            for(const auto& cand_str : remote_candidates) {
                Candidate remote_candidate = Candidate::from_sdp(cand_str);
                co_await add_remote_candidate(remote_candidate);
            }

            // ICE-CONTROLLING 및 ICE-CONTROLLED에 따른 역할 결정
            IceRole remote_role;
            if (sdp.find("ICE-CONTROLLING") != std::string::npos) {
                remote_role = IceRole::Controller;
            }
            else if (sdp.find("ICE-CONTROLLED") != std::string::npos) {
                remote_role = IceRole::Controlled;
            }
            else {
                remote_role = IceRole::Controlled; // 기본값
            }

            negotiate_role(remote_role, remote_tie_breaker);

            // 역할 협상에 따른 처리
            if (remote_role_ == IceRole::Controller && role_ == IceRole::Controlled) {
                // Controlled 역할에서는 Controller의 NOMINATE 메시지를 기다림
                // Binding Indication 메시지(USE-CANDIDATE)를 수신하여 처리
                // 지속적으로 메시지를 수신하도록 소켓을 설정
                std::vector<uint8_t> recv_buffer(2048);
                asio::ip::udp::endpoint sender_endpoint;
                std::error_code ec;
                size_t bytes_received = 0;
                try {
                    bytes_received = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);
                } catch (const std::exception& ex) {
                    log(LogLevel::ERROR, "Failed to receive binding indication: " + std::string(ex.what()));
                    transition_to_state(IceConnectionState::Failed);
                    break;
                }

                if (bytes_received > 0) {
                    recv_buffer.resize(bytes_received);
                    try {
                        StunMessage msg = StunMessage::parse(recv_buffer);
                        if (msg.get_type() == StunMessageType::BINDING_INDICATION) {
                            // Binding Indication 처리 (USE-CANDIDATE)
                            co_await handle_binding_indication(msg, sender_endpoint);
                        }
                    } catch (const std::exception& ex) {
                        log(LogLevel::WARNING, "Failed to parse incoming STUN message: " + std::string(ex.what()));
                    }
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
awaitable<void> IceAgent::nominate_pair(CheckListEntry& entry) {
	entry.is_nominated = true;
	nominated_pair_ = entry.pair;
	
	if (role_ == IceRole::Controller) {
		// Send NOMINATE message
		co_await send_nominate(entry.pair);
	}
	else {
		log(LogLevel::INFO, "Nominated pair " + ((role_ == IceRole::Controller) ? "(Controlling)" : "(Controlled)") + "role with " +
	    entry.pair.remote_candidate.endpoint.address().to_string() + ":" +
	    std::to_string(entry.pair.remote_candidate.endpoint.port()) +
	    " [Component " + std::to_string(entry.pair.local_candidate.component_id) + "]");
	    
	
		// Trigger nomination callback
		if (nominate_callback_) {
	    	nominate_callback_(entry.pair);
	}
	
	// Transition to Connected state
	transition_to_state(IceConnectionState::Connected);
	co_return;
}

// Handle Binding Indication messages (USE-CANDIDATE) from Controller
asio::awaitable<void> IceAgent::handle_binding_indication(const StunMessage& msg, const asio::ip::udp::endpoint& sender) {
    // USE-CANDIDATE 속성 존재 여부 확인
    if (msg.has_attribute(StunAttributeType::USE_CANDIDATE)) {
        // Controlled 역할에서는 NOMINATE 메시지를 받으면 해당 페어를 후보로 선정
        for (auto& entry : check_list_) {
            if (entry.state == CandidatePairState::Succeeded && !entry.is_nominated) {
                entry.is_nominated = true;
                nominated_pair_ = entry.pair;

                log(LogLevel::INFO, "Nominated pair based on USE-CANDIDATE from Controller.");

                // Connected 상태로 전환
                transition_to_state(IceConnectionState::Connected);

                // 콜백 알림
                if (nominate_callback_) {
                    nominate_callback_(entry.pair);
                }

                break;
            }
        }
    }

    co_return;
}

#endif // ICE_AGENT_HPP
