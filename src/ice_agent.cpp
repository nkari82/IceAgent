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

// Constants
constexpr int NUM_COMPONENTS = 1; // ICE 컴포넌트 수 (예: RTP, RTCP)
constexpr size_t MAX_CONCURRENT_CHECKS = 5; // 최대 동시 연결 검사 수

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
        auto stun_client = std::make_shared<StunClient>(io_context_, host, port, ""); // 필요 시 키 제공
        stun_clients_.push_back(stun_client);
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
            turn_client_ = std::make_shared<TurnClient>(io_context_, host, port, turn_username_, turn_password_);
        }
    }

    // Thread pool 초기화
    initialize_thread_pool();
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

    // io_context 종료 및 스레드 조인
    io_context_.stop();
    for(auto& thread : thread_pool_) {
        if(thread.joinable()) {
            thread.join();
        }
    }
}

// Initialize thread pool
void IceAgent::initialize_thread_pool(size_t num_threads) {
    if(num_threads == 0) num_threads = 2; // 최소 2개 스레드
    for(size_t i = 0; i < num_threads; ++i) {
        thread_pool_.emplace_back([this]() {
            io_context_.run();
        });
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
asio::awaitable<void> IceAgent::start() {
    if (!transition_to_state(IceConnectionState::Gathering)) {
        co_return;
    }

    try {
        // Step 1: Gather Candidates
        co_await gather_candidates();

        // Generate ICE credentials
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        ice_attributes_.username_fragment = "u" + std::to_string(dis(gen)) + std::to_string(dis(gen));
        ice_attributes_.password = "p" + std::to_string(dis(gen)) + std::to_string(dis(gen));

        // Exchange ICE parameters via signaling
        if (signaling_client_) {
            // Create SDP message
            std::vector<std::string> cand_strings;
            for(const auto& cand : local_candidates_) {
                cand_strings.push_back("a=" + cand.to_sdp());
            }
            std::string sdp = signaling_client_->create_sdp(ice_attributes_.username_fragment, ice_attributes_.password, cand_strings, mode_);
            co_await signaling_client_->send_sdp(sdp);
            
            // Spawn a coroutine to handle incoming signaling messages
            co_spawn(io_context_, handle_incoming_signaling_messages(), asio::detached);
        }

        if (mode_ == IceMode::Full) {
            if (!transition_to_state(IceConnectionState::Checking)) {
                co_return;
            }

            // Perform connectivity checks with retry logic
            co_await perform_connectivity_checks();
        }
        else {
            // ICE Lite 모드에서는 Connectivity Checks를 수행하지 않음
            log(LogLevel::INFO, "ICE Lite mode: Skipping connectivity checks.");
            transition_to_state(IceConnectionState::Connected); // 직접 연결 상태로 전환
            // **ICE Lite**는 상대방이 **Full ICE**를 수행한다고 가정하므로, **Nominated Pair**를 기다립니다.
            // 따라서, **Nominated Pair**를 받으면 add_remote_candidate를 통해 처리하게 됩니다.
        }
        
        if (current_state_ == IceConnectionState::Connected) {
            // Spawn keep-alive coroutine
            co_spawn(io_context_, perform_keep_alive(), asio::detached);
        
            // Spawn TURN allocation refresh coroutine if TURN is used
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

// ICE Restart initiation
asio::awaitable<void> IceAgent::restart_ice() {
    if (mode_ == IceMode::Lite) {
        log(LogLevel::WARNING, "ICE Restart is not supported in ICE Lite mode.");
        co_return;
    }

    log(LogLevel::INFO, "Restarting ICE process...");

    // Reset state
    current_state_ = IceConnectionState::New;
    nominated_pair_ = CandidatePair();
    check_list_.clear();
    remote_candidates_.clear();
    local_candidates_.clear();
    log(LogLevel::INFO, "ICE state reset.");

    // Generate new ICE credentials
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    ice_attributes_.username_fragment = "u" + std::to_string(dis(gen)) + std::to_string(dis(gen));
    ice_attributes_.password = "p" + std::to_string(dis(gen)) + std::to_string(dis(gen));

    // Exchange new ICE parameters via signaling
    if (signaling_client_) {
        // Create new SDP message
        std::vector<std::string> cand_strings;
        for(const auto& cand : local_candidates_) {
            cand_strings.push_back("a=" + cand.to_sdp());
        }
        std::string sdp = signaling_client_->create_sdp(ice_attributes_.username_fragment, ice_attributes_.password, cand_strings, mode_);
        co_await signaling_client_->send_sdp(sdp);
    }

    // Restart ICE process
    co_await start();

    co_return;
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
    remote_candidates_.push_back(candidate);
    log(LogLevel::INFO, "Added remote candidate: " + candidate.to_sdp());

    // Notify via callback
    if (candidate_callback_) {
        candidate_callback_(candidate);
    }

    // Create Candidate Pairs
    for (const auto& local : local_candidates_) {
        if (local.component_id == candidate.component_id) { // 동일한 컴포넌트에 대해만 쌍을 만듦
            CandidatePair pair(local, candidate);
            pair.priority = calculate_priority(local, candidate);
            check_list_.emplace_back(pair);
        }
    }

    // Perform connectivity checks if not already running (Full ICE mode)
    if (mode_ == IceMode::Full && !connectivity_checks_running_) {
        connectivity_checks_running_ = true;
        asio::co_spawn(io_context_, [this]() -> asio::awaitable<void> {
            co_await perform_connectivity_checks();
            connectivity_checks_running_ = false;
        }, asio::detached);
    }
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
    // 후보 수집 프로세스와 타임아웃 간의 경쟁
    asio::steady_timer gather_timer(io_context_);
    gather_timer.expires_after(candidate_gather_timeout_);

    // 후보 수집 코루틴
    auto gather_coroutine = [this]() -> asio::awaitable<void> {
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
                // 이 NAT 타입들은 일반적으로 피어 투 피어 연결을 허용함
                log(LogLevel::INFO, "Detected NAT type supports direct peer-to-peer connections.");
                // 이미 srflx 후보를 수집함
                break;
            case NatType::Symmetric:
                // Symmetric NAT는 TURN을 통한 릴레이 후보가 필요할 수 있음
                log(LogLevel::INFO, "Detected Symmetric NAT. Gathering relay candidates via TURN.");
                if (turn_client_) {
                    co_await gather_relay_candidates();
                } else {
                    log(LogLevel::WARNING, "TURN server not configured. Relay candidates cannot be gathered.");
                }
                break;
            case NatType::OpenInternet:
                // NAT 없음; 직접 연결이 용이함
                log(LogLevel::INFO, "No NAT detected. Direct peer-to-peer connections are straightforward.");
                break;
            default:
                log(LogLevel::WARNING, "Unknown NAT type. Proceeding with default candidate gathering.");
                break;
        }
        co_return;
    };

    // 후보 수집과 타임아웃 간의 경쟁
    auto [gather_ec, gather_res] = co_await (
        (gather_coroutine() && asio::use_awaitable)
        || (gather_timer.async_wait(asio::use_awaitable))
    );

    if (gather_ec == asio::error::operation_aborted) {
        // 수집이 타임아웃 전에 완료됨
        log(LogLevel::INFO, "Candidate gathering completed successfully.");
    } else {
		if (!gather_ec) {
			// Timeout occurred before gathering completed
			log(LogLevel::ERROR, "Candidate gathering timed out after " + std::to_string(candidate_gather_timeout_.count()) + " seconds.");
		}
		else {
			// Some other error occurred
			log(LogLevel::ERROR, "Error during candidate gathering: " + gather_ec.message());
		}
		
		attempts++;
        log(LogLevel::WARNING, "Candidate gathering attempt " + std::to_string(attempts) + " failed: " + ex.what());
        if (attempts >= candidate_gather_retries_) {
            log(LogLevel::ERROR, "Maximum candidate gathering retries exceeded.");
            throw; // 최종 실패 시 예외 전파
        } else {
            log(LogLevel::INFO, "Retrying candidate gathering...");
            // Reset state
            remote_candidates_.clear();
            check_list_.clear();
            local_candidates_.clear();
            // Optionally, re-initialize clients or other state
            co_await gather_candidates(attempts); // 재귀 호출로 재시도
        }
    }

    co_return;
}

// Gather local host candidates
asio::awaitable<void> IceAgent::gather_local_candidates() {
    log(LogLevel::INFO, "Gathering local candidates...");
    asio::ip::udp::resolver resolver(io_context_);
    asio::ip::udp::resolver::results_type results = co_await resolver.async_resolve("0.0.0.0", "0", asio::use_awaitable);

    for (const auto& entry : results) {
        for (int component = 1; component <= NUM_COMPONENTS; ++component) { // 다중 컴포넌트 지원
            Candidate candidate;
            candidate.endpoint = entry.endpoint();
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
    }
    co_return;
}

// Gather srflx candidates using STUN clients
asio::awaitable<void> IceAgent::gather_srflx_candidates() {
    // 모든 STUN 클라이언트를 사용하여 srflx 후보 수집
    if (stun_clients_.empty()) {
        log(LogLevel::WARNING, "No STUN clients available to gather srflx candidates.");
        co_return;
    }

    for (auto& stun_client : stun_clients_) {
        try {
            asio::ip::udp::endpoint mapped_endpoint = co_await stun_client->send_binding_request();

            for (int component = 1; component <= NUM_COMPONENTS; ++component) { // 다중 컴포넌트 지원
                // srflx 후보 생성
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

                // 콜백 알림
                if (candidate_callback_) {
                    candidate_callback_(srflx_candidate);
                }

                // Candidate Pair 생성
                CandidatePair pair(srflx_candidate, Candidate());
                check_list_.emplace_back(pair);
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
        // 릴레이 엔드포인트 할당
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

            // 콜백 알림
            if (candidate_callback_) {
                candidate_callback_(relay_candidate);
            }

            // Candidate Pair 생성
            CandidatePair pair(relay_candidate, Candidate());
            check_list_.emplace_back(pair);
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
        std::vector<uint8_t> txn_id = generate_transaction_id();
        StunMessage binding_request(STUN_BINDING_REQUEST, txn_id);
        binding_request.add_attribute("PRIORITY", std::to_string(pair.local_candidate.priority));
        binding_request.add_attribute("USERNAME", ice_attributes_.username_fragment);
        binding_request.add_message_integrity(ice_attributes_.password); // StunMessage가 이 기능을 지원해야 함
        binding_request.add_fingerprint(); // FINGERPRINT 속성 추가
        std::vector<uint8_t> serialized_request = binding_request.serialize();

        // Binding Request 전송
        co_await socket_.async_send_to(asio::buffer(serialized_request), pair.remote_candidate.endpoint, asio::use_awaitable);

        // 타임아웃 설정
        asio::steady_timer timer(io_context_);
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
                throw std::runtime_error("Connectivity check timed out.");
            } else {
                throw std::runtime_error("Connectivity check failed: " + std::string(ec.message()));
            }
        }

        recv_buffer.resize(bytes_received);
        StunMessage response = StunMessage::parse(recv_buffer);

        // 응답 검증
        if (response.get_transaction_id() != txn_id) {
            throw std::runtime_error("STUN Transaction ID mismatch.");
        }

        if (response.get_type() != STUN_BINDING_RESPONSE_SUCCESS) {
            throw std::runtime_error("Invalid STUN Binding Response type.");
        }

        // MESSAGE-INTEGRITY 검증
        if (!response.verify_message_integrity(ice_attributes_.password)) {
            throw std::runtime_error("Invalid MESSAGE-INTEGRITY in STUN response.");
        }

        // FINGERPRINT 검증
        if (!response.verify_fingerprint()) {
            throw std::runtime_error("Invalid FINGERPRINT in STUN response.");
        }

        // MAPPED-ADDRESS 추출
        std::string mapped_address = response.get_attribute("MAPPED-ADDRESS");
        if (mapped_address.empty()) {
            throw std::runtime_error("MAPPED-ADDRESS attribute missing in STUN response.");
        }

        // MAPPED-ADDRESS 파싱
        size_t colon_pos = mapped_address.find(':');
        if (colon_pos == std::string::npos) {
            throw std::runtime_error("Invalid MAPPED-ADDRESS format.");
        }
        std::string ip = mapped_address.substr(0, colon_pos);
        uint16_t port = static_cast<uint16_t>(std::stoi(mapped_address.substr(colon_pos + 1)));

        asio::ip::udp::endpoint mapped_endpoint(asio::ip::make_address(ip), port);

        // 성공 처리
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
        asio::steady_timer timer(io_context_);
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
                throw std::runtime_error("Relay connectivity check timed out.");
            } else {
                throw std::runtime_error("Relay connectivity check failed: " + std::string(ec.message()));
            }
        }

        if (bytes_transferred > 0) {
            co_return; // 성공
        } else {
            throw std::runtime_error("No data received from relay.");
        }
    }

    co_return;
}

// Evaluate connectivity results and nominate pairs
void IceAgent::evaluate_connectivity_results() {
    bool any_succeeded = false;
    for (auto& entry : check_list_) {
        if (entry.state == CandidatePairState::Succeeded && !entry.is_nominated) {
            nominate_pair(entry);
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
        asio::steady_timer refresh_timer(io_context_);
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
        size_t bytes_received = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);
        if (!ec) {
            recv_buffer.resize(bytes_received);
            if (data_callback_) {
                data_callback_(recv_buffer, sender_endpoint);
            }
            log(LogLevel::INFO, "Received data: " + std::to_string(bytes_received) + " bytes from " +
                sender_endpoint.address().to_string() + ":" + std::to_string(sender_endpoint.port()));
        } else {
            log(LogLevel::ERROR, "Failed to receive data: " + ec.message());
            transition_to_state(IceConnectionState::Failed);
            break;
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
    else type_pref = 0; // 기본값

    uint32_t local_pref = 65535; // Host 후보의 고유한 로컬 선호도
    uint32_t component_id = static_cast<uint32_t>(local.component_id);

    // Priority = (Type Preference << 24) | (Local Preference << 8) | (256 - Component ID)
    return (type_pref << 24) | (local_pref << 8) | (256 - component_id);
}

// Sort candidate pairs based on priority
void IceAgent::sort_candidate_pairs() {
    std::sort(check_list_.begin(), check_list_.end(), [&](const CheckListEntry& a, const CheckListEntry& b) {
        return a.pair.priority > b.pair.priority; // 내림차순 정렬
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
void IceAgent::negotiate_role(IceRole remote_role) {
    remote_role_ = remote_role;
    log(LogLevel::INFO, "Negotiated role: " + std::to_string(static_cast<int>(remote_role_)));
}

// Send NOMINATE message using STUN Binding Indication with USE-CANDIDATE attribute
asio::awaitable<void> IceAgent::send_nominate(const CandidatePair& pair) {
    std::vector<uint8_t> txn_id = generate_transaction_id();

    StunMessage nominate_msg(STUN_BINDING_INDICATION, txn_id);
    // RFC8445에 따른 USE-CANDIDATE 속성 추가
    nominate_msg.add_attribute("USE-CANDIDATE", "");

    // Controller 역할인 경우 ICE-CONTROLLING 속성 추가
    if (role_ == IceRole::Controller) {
        // 고유한 tie-breaker 값 생성
        std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
        std::random_device rd;
        std::mt19937 gen(rd());
        uint32_t tie_breaker = dist(gen);
        nominate_msg.add_attribute("ICE-CONTROLLING", std::to_string(tie_breaker));
    }

    // MESSAGE-INTEGRITY 추가
    std::vector<uint8_t> serialized = nominate_msg.serialize_without_attributes({ "MESSAGE-INTEGRITY", "FINGERPRINT" });
    std::vector<uint8_t> hmac = HmacSha1::calculate(ice_attributes_.password, serialized);
    nominate_msg.add_attribute("MESSAGE-INTEGRITY", hmac);

    // FINGERPRINT 추가
    nominate_msg.add_fingerprint();
    std::vector<uint8_t> serialized_nominate = nominate_msg.serialize();
    co_await socket_.async_send_to(asio::buffer(serialized_nominate), pair.remote_candidate.endpoint, asio::use_awaitable);

    log(LogLevel::INFO, "Sent NOMINATE to " +
        pair.remote_candidate.endpoint.address().to_string() + ":" +
        std::to_string(pair.remote_candidate.endpoint.port()) +
        " [Component " + std::to_string(pair.local_candidate.component_id) + "]");

    // **응답 처리 제거:** NOMINATE 메시지에 대한 응답은 필요하지 않음

    // **콜백 트리거:** NOMINATE 전송 완료 알림
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
            std::tie(remote_ufrag, remote_pwd) = signaling_client_->parse_sdp(sdp, remote_candidates);

            ice_attributes_.username_fragment = remote_ufrag;
            ice_attributes_.password = remote_pwd;

            // 원격 후보 파싱 및 추가
            for(const auto& cand_str : remote_candidates) {
                Candidate remote_candidate = Candidate::from_sdp(cand_str);
                add_remote_candidate(remote_candidate);
            }

            // ICE-CONTROLLING 및 ICE-CONTROLLED에 따른 역할 결정
            if (sdp.find("ICE-CONTROLLING") != std::string::npos) {
                negotiate_role(IceRole::Controlled);
            }
            else if (sdp.find("ICE-CONTROLLED") != std::string::npos) {
                negotiate_role(IceRole::Controller);
            }

            // 역할 협상에 따른 처리
            if (remote_role_ == IceRole::Controller && role_ == IceRole::Controlled) {
                // Controlled 역할에서는 Controller의 NOMINATE 메시지를 기다림
                // Binding Indication 메시지(USE-CANDIDATE)를 수신하여 처리
                // 지속적으로 메시지를 수신하도록 소켓을 설정
                asio::ip::udp::endpoint sender_endpoint;
                std::vector<uint8_t> recv_buffer(2048);
                std::error_code ec;
                size_t bytes_received = co_await socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable);
                if (!ec && bytes_received > 0) {
                    recv_buffer.resize(bytes_received);
                    try {
                        StunMessage msg = StunMessage::parse(recv_buffer);
                        if (msg.get_type() == STUN_BINDING_INDICATION) {
                            // Binding Indication 처리 (예: USE-CANDIDATE)
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

// Generate transaction ID using StunMessage's method
std::vector<uint8_t> IceAgent::generate_transaction_id() {
    return StunMessage::generate_transaction_id();
}

// Nominate a successful candidate pair based on role
void IceAgent::nominate_pair(CheckListEntry& entry) {
    if (role_ == IceRole::Controller) {
        entry.is_nominated = true;
        nominated_pair_ = entry.pair;

        // NOMINATE 메시지 전송
        asio::co_spawn(io_context_, send_nominate(entry.pair), asio::detached);

        log(LogLevel::INFO, "Nominated pair with " +
            entry.pair.remote_candidate.endpoint.address().to_string() + ":" +
            std::to_string(entry.pair.remote_candidate.endpoint.port()) +
            " [Component " + std::to_string(entry.pair.local_candidate.component_id) + "]");

        // 콜백 트리거
        if (nominate_callback_) {
            nominate_callback_(entry.pair);
        }
    }
    // Controlled 역할은 NOMINATE를 수행하지 않음
}

// Handle Binding Indication messages (USE-CANDIDATE) from Controller
asio::awaitable<void> IceAgent::handle_binding_indication(const StunMessage& msg, const asio::ip::udp::endpoint& sender) {
    // USE-CANDIDATE 속성 추출
    if (msg.has_attribute("USE-CANDIDATE")) {
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
