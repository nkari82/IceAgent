// src/ice_agent.cpp

#include "ice_agent.hpp"
#include <iostream>
#include <thread>
#include <cstdlib>
#include <random>
#include <asio/ssl.hpp>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <zlib.h> // For CRC32

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
      connectivity_checks_running_(false) 
{
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

    // Initialize thread pool
    initialize_thread_pool();
}

// Destructor
IceAgent::~IceAgent() {
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
            std::string sdp = signaling_client_->create_sdp(ice_attributes_.username_fragment, ice_attributes_.password, cand_strings);
            co_await signaling_client_->send_sdp(sdp);
            
            // Spawn a coroutine to handle incoming signaling messages
            co_spawn(io_context_, handle_incoming_signaling_messages(), asio::detached);
        }

        if (!transition_to_state(IceConnectionState::Checking)) {
            co_return;
        }

        // Perform connectivity checks
        co_await perform_connectivity_checks();
        
        if (current_state_ == IceConnectionState::Connected) {
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
    candidate_pairs_.clear();
    remote_candidates_.clear();
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
        std::string sdp = signaling_client_->create_sdp(ice_attributes_.username_fragment, ice_attributes_.password, cand_strings);
        co_await signaling_client_->send_sdp(sdp);
    }

    // Restart connectivity checks
    if (!transition_to_state(IceConnectionState::Checking)) {
        co_return;
    }

    co_await perform_connectivity_checks();

    if (current_state_ == IceConnectionState::Connected) {
        // Spawn perform_keep_alive coroutine
        co_spawn(io_context_, perform_keep_alive(), asio::detached);
    
        // Spawn perform_turn_refresh coroutine if TURN is used
        if (turn_client_ && turn_client_->is_allocated()) {
            co_spawn(io_context_, perform_turn_refresh(), asio::detached);
        }

        // Start data reception
        asio::co_spawn(io_context_, start_data_receive(), asio::detached);
    }

    co_return;
}

// Negotiate role based on remote signaling
void IceAgent::negotiate_role(IceRole remote_role) {
    remote_role_ = remote_role;
    log(LogLevel::INFO, "Negotiated role: " + std::to_string(static_cast<int>(remote_role_)));
}

// Convert transaction_id to string for debugging
#if 0
std::string vector_to_string(const std::vector<uint8_t>& vec) {
    std::ostringstream oss;
    for(auto byte : vec) {
        oss << std::hex << static_cast<int>(byte);
    }
    return oss.str();
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
uint32_t IceAgent::calculate_priority(const Candidate& local, const Candidate& remote) const {
    uint32_t type_pref;
    if (local.type == "host") type_pref = 126;
    else if (local.type == "srflx") type_pref = 100;
    else if (local.type == "relay") type_pref = 0;
    else type_pref = 0; // 기본값

    uint32_t local_pref = 65535; // 고유한 로컬 선호도 설정 가능
    uint32_t component_id = static_cast<uint32_t>(local.component_id);

    return (type_pref << 24) | (local_pref << 8) | (256 - component_id);
}

// Sort candidate pairs based on priority
void IceAgent::sort_candidate_pairs() {
    std::sort(check_list_.begin(), check_list_.end(), [&](const CheckListEntry& a, const CheckListEntry& b) {
        return a.pair.priority > b.pair.priority; // Descending order
    });
}

// Generate random transaction ID
std::vector<uint8_t> IceAgent::generate_transaction_id() {
    std::vector<uint8_t> txn_id(12);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for(auto& byte : txn_id) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    return txn_id;
}

// Calculate HMAC-SHA1 for MESSAGE-INTEGRITY
std::vector<uint8_t> IceAgent::calculate_hmac_sha1(const Stun::StunMessage& message, const std::string& key) {
    unsigned char* result;
    unsigned int len = SHA_DIGEST_LENGTH;
    std::vector<uint8_t> hmac(len);

    // Prepare the message for HMAC calculation (before MESSAGE-INTEGRITY and FINGERPRINT)
    std::vector<uint8_t> msg = message.serialize_without_attributes({"MESSAGE-INTEGRITY", "FINGERPRINT"});

    result = HMAC(EVP_sha1(), key.c_str(), key.length(), msg.data(), msg.size(), nullptr, nullptr);
    if (result == nullptr) {
        throw std::runtime_error("HMAC calculation failed.");
    }
    std::copy(result, result + len, hmac.begin());
    return hmac;
}

// Calculate CRC32 for FINGERPRINT
uint32_t IceAgent::calculate_crc32(const Stun::StunMessage& message) {
    // Prepare the message for CRC calculation (up to the last attribute before FINGERPRINT)
    std::vector<uint8_t> msg = message.serialize_without_attribute("FINGERPRINT");
    uint32_t crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, msg.data(), msg.size());
    return crc ^ 0x5354554E;
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

// Infer NAT Type based on mapped endpoints
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
    co_await gather_srflx_candidates();
    
    // NAT Type Based Candidate Gathering
    NatType nat_type = co_await detect_nat_type();

    // Notify via callback
    if (on_nat_type_detected_) {
        on_nat_type_detected_(nat_type);
    }
    
    switch (nat_type) {
        case NatType::FullCone:
        case NatType::RestrictedCone:
        case NatType::PortRestrictedCone:
            // These NAT types generally allow for successful peer-to-peer connections.
            // Prioritize gathering server reflexive (srflx) candidates.
            log(LogLevel::INFO, "Detected NAT type supports direct peer-to-peer connections.");
            // Already gathered srflx candidates
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
    // Assuming all STUN clients are used for srflx candidates
    if (stun_clients_.empty()) {
        log(LogLevel::WARNING, "No STUN clients available to gather srflx candidates.");
        co_return;
    }

    for (auto& stun_client : stun_clients_) {
        try {
            asio::ip::udp::endpoint mapped_endpoint = co_await stun_client->send_binding_request();

            for (int component = 1; component <= NUM_COMPONENTS; ++component) { // 다중 컴포넌트 지원
                // Create srflx candidate
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

                // Notify via callback
                if (candidate_callback_) {
                    candidate_callback_(srflx_candidate);
                }

                // Create Candidate Pair with srflx Candidate
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
        // Allocate a relay endpoint
        asio::ip::udp::endpoint relay_endpoint = co_await turn_client_->allocate_relay();
        log(LogLevel::INFO, "Allocated relay endpoint: " + relay_endpoint.address().to_string() + ":" + std::to_string(relay_endpoint.port()));

        for (int component = 1; component <= NUM_COMPONENTS; ++component) { // 다중 컴포넌트 지원
            // Create Relay Candidate
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

            // Notify via callback
            if (candidate_callback_) {
                candidate_callback_(relay_candidate);
            }

            // Create Candidate Pair with Relay Candidate
            CandidatePair pair(relay_candidate, Candidate());
            check_list_.emplace_back(pair);
        }
    } catch (const std::exception& ex) {
        log(LogLevel::ERROR, "Failed to allocate relay via TURN: " + std::string(ex.what()));
    }

    co_return;
}

// Perform connectivity checks with enhanced Check List management
asio::awaitable<void> IceAgent::perform_connectivity_checks() {
    log(LogLevel::INFO, "Performing connectivity checks...");
    
    sort_candidate_pairs();

    // Semaphore-like concurrency control using atomic
    std::atomic<size_t> active_checks{0};
    
    while (true) {
        bool any_pending = false;
        for (auto& entry : check_list_) {
            if (entry.state == CandidatePairState::New && !entry.in_progress) {
                if (active_checks.load() >= MAX_CONCURRENT_CHECKS) {
                    break;
                }
                entry.in_progress = true;
                active_checks++;
                any_pending = true;
                
                // Spawn a coroutine for each connectivity check
                co_spawn(io_context_, [this, &entry, &active_checks]() -> asio::awaitable<void> {
                    try {
                        co_await perform_single_connectivity_check(entry);
                        entry.state = CandidatePairState::Succeeded;
                        log(LogLevel::INFO, "Connectivity succeeded for pair.");
                        // Nominate if Controller
                        if (role_ == IceRole::Controller) {
                            entry.is_nominated = true;
                            co_await send_nominate(entry.pair);
                        }
                    } catch (const std::exception& ex) {
                        entry.state = CandidatePairState::Failed;
                        log(LogLevel::WARNING, "Connectivity check failed: " + std::string(ex.what()));
                    }
                    entry.in_progress = false;
                    active_checks--;
                }, asio::detached);
            }
        }
        
        if (!any_pending && active_checks.load() == 0) {
            break; // 모든 검사 완료
        }
        
        // 잠시 대기
        co_await asio::steady_timer(io_context_, std::chrono::milliseconds(100)).async_wait(asio::use_awaitable);
    }
    
    // Evaluate results
    evaluate_connectivity_results();
    co_return;
}

// Perform a single connectivity check
asio::awaitable<void> IceAgent::perform_single_connectivity_check(CheckListEntry& entry) {
    const CandidatePair& pair = entry.pair;

    if (pair.remote_candidate.type == "srflx" || pair.remote_candidate.type == "host") {
        // Connectivity check using STUN Binding Request
        std::vector<uint8_t> txn_id = generate_transaction_id();
        Stun::StunMessage binding_request(STUN_BINDING_REQUEST, txn_id);
        binding_request.add_attribute("PRIORITY", std::to_string(pair.local_candidate.priority));
        binding_request.add_attribute("USERNAME", ice_attributes_.username_fragment);
        binding_request.add_attribute("MESSAGE-INTEGRITY", calculate_hmac_sha1(binding_request, ice_attributes_.password));
        binding_request.add_attribute("FINGERPRINT", calculate_crc32(binding_request));
        std::vector<uint8_t> serialized_request = binding_request.serialize();

        // Send Binding Request
        co_await socket_.async_send_to(asio::buffer(serialized_request), pair.remote_candidate.endpoint, asio::use_awaitable);

        // Set timeout
        asio::steady_timer timer(io_context_);
        timer.expires_after(std::chrono::seconds(2));

        std::vector<uint8_t> recv_buffer(2048);
        asio::ip::udp::endpoint sender_endpoint;

        using namespace asio::experimental::awaitable_operators;
        auto [ec, bytes_received] = co_await (
            socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable)
            || timer.async_wait(asio::use_awaitable)
        );

        if (ec == asio::error::operation_aborted) {
            throw std::runtime_error("Connectivity check timed out.");
        } else if (ec) {
            throw std::runtime_error("Connectivity check failed: " + std::string(ec.message()));
        }

        recv_buffer.resize(bytes_received);
        Stun::StunMessage response = Stun::StunMessage::parse(recv_buffer);

        // Verify response
        if (response.get_transaction_id() != txn_id) {
            throw std::runtime_error("STUN Transaction ID mismatch.");
        }

        if (response.get_type() != STUN_BINDING_RESPONSE_SUCCESS) {
            throw std::runtime_error("Invalid STUN Binding Response type.");
        }

        // Verify MESSAGE-INTEGRITY
        if (!response.verify_message_integrity(ice_attributes_.password)) {
            throw std::runtime_error("Invalid MESSAGE-INTEGRITY in STUN response.");
        }

        // Verify FINGERPRINT
        if (!response.verify_fingerprint()) {
            throw std::runtime_error("Invalid FINGERPRINT in STUN response.");
        }

        // Extract MAPPED-ADDRESS
        std::string mapped_address = response.get_attribute("MAPPED-ADDRESS");
        if (mapped_address.empty()) {
            throw std::runtime_error("MAPPED-ADDRESS attribute missing in STUN response.");
        }

        // Parse MAPPED-ADDRESS
        size_t colon_pos = mapped_address.find(':');
        if (colon_pos == std::string::npos) {
            throw std::runtime_error("Invalid MAPPED-ADDRESS format.");
        }
        std::string ip = mapped_address.substr(0, colon_pos);
        uint16_t port = static_cast<uint16_t>(std::stoi(mapped_address.substr(colon_pos + 1)));

        asio::ip::udp::endpoint mapped_endpoint(asio::ip::make_address(ip), port);

        // 연결 성공 처리
        co_return;
    }
    else if (pair.remote_candidate.type == "relay") {
        // Relay connectivity check using TURN Send (data transmission)
        std::vector<uint8_t> data = { 'D', 'A', 'T', 'A' };
        co_await socket_.async_send_to(asio::buffer(data), pair.remote_candidate.endpoint, asio::use_awaitable);
        log(LogLevel::INFO, "Sent data via TURN relay to " +
            pair.remote_candidate.endpoint.address().to_string() + ":" +
            std::to_string(pair.remote_candidate.endpoint.port()) +
            " [Component " + std::to_string(pair.local_candidate.component_id) + "]");

        // Set timeout
        asio::steady_timer timer(io_context_);
        timer.expires_after(std::chrono::seconds(2));

        std::vector<uint8_t> recv_buffer(2048);
        asio::ip::udp::endpoint sender_endpoint_recv;

        using namespace asio::experimental::awaitable_operators;
        auto [ec, bytes_transferred] = co_await (
            socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint_recv, asio::use_awaitable)
            || timer.async_wait(asio::use_awaitable)
        );

        if (ec == asio::error::operation_aborted) {
            throw std::runtime_error("Relay connectivity check timed out.");
        } else if (ec) {
            throw std::runtime_error("Relay connectivity check failed: " + std::string(ec.message()));
        }

        if (bytes_transferred > 0) {
            co_return; // Success
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
            break; // Nominate the first successful pair
        }
    }

    if (any_succeeded) {
        transition_to_state(IceConnectionState::Connected);
    } else {
        log(LogLevel::ERROR, "No valid candidate pairs found after connectivity checks.");
        transition_to_state(IceConnectionState::Failed);
    }
}

// Nominate a successful candidate pair based on role
void IceAgent::nominate_pair(CheckListEntry& entry) {
    if (role_ == IceRole::Controller) {
        entry.is_nominated = true;
        nominated_pair_ = entry.pair;

        // Send NOMINATE message to the remote peer
        asio::co_spawn(io_context_, send_nominate(entry.pair), asio::detached);

        log(LogLevel::INFO, "Nominated pair with " +
            entry.pair.remote_candidate.endpoint.address().to_string() + ":" +
            std::to_string(entry.pair.remote_candidate.endpoint.port()) +
            " [Component " + std::to_string(entry.pair.local_candidate.component_id) + "]");

        // Trigger nominate callback if set
        if (nominate_callback_) {
            nominate_callback_(entry.pair);
        }
    }
}

// Send NOMINATE message using STUN Binding Indication with USE-CANDIDATE attribute
asio::awaitable<void> IceAgent::send_nominate(const CandidatePair& pair) {
    std::vector<uint8_t> txn_id = generate_transaction_id();

    Stun::StunMessage nominate_msg(STUN_BINDING_INDICATION, txn_id);
    // Add USE-CANDIDATE attribute as per RFC 8445
    nominate_msg.add_attribute("USE-CANDIDATE", "");
    // Add ICE-CONTROLLING if Controller
    if (role_ == IceRole::Controller) {
        nominate_msg.add_attribute("ICE-CONTROLLING", "tie-breaker-value"); // 고유한 tie-breaker 값 필요
    }

    // Add MESSAGE-INTEGRITY
    nominate_msg.add_attribute("MESSAGE-INTEGRITY", calculate_hmac_sha1(nominate_msg, ice_attributes_.password));

    // Add FINGERPRINT
    nominate_msg.add_attribute("FINGERPRINT", calculate_crc32(nominate_msg));

    std::vector<uint8_t> serialized_nominate = nominate_msg.serialize();
    co_await socket_.async_send_to(asio::buffer(serialized_nominate), pair.remote_candidate.endpoint, asio::use_awaitable);

    log(LogLevel::INFO, "Sent NOMINATE to " +
        pair.remote_candidate.endpoint.address().to_string() + ":" +
        std::to_string(pair.remote_candidate.endpoint.port()) +
        " [Component " + std::to_string(pair.local_candidate.component_id) + "]");

    // Trigger nominate callback if set
    if (nominate_callback_) {
        nominate_callback_(pair);
    }
}

// Implement connectivity keep-alive
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

// Implement TURN allocation refresh
asio::awaitable<void> IceAgent::perform_turn_refresh() {
    while (current_state_ == IceConnectionState::Connected && turn_client_ && turn_client_->is_allocated()) {
        keep_alive_timer_.expires_after(std::chrono::seconds(300)); // 예시: 5분마다
        co_await keep_alive_timer_.async_wait(asio::use_awaitable);

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

// Nominate a successful candidate pair based on role
void IceAgent::nominate_pair(CheckListEntry& entry) {
    if (role_ == IceRole::Controller) {
        entry.is_nominated = true;
        nominated_pair_ = entry.pair;

        // Send NOMINATE message to the remote peer
        asio::co_spawn(io_context_, send_nominate(entry.pair), asio::detached);

        log(LogLevel::INFO, "Nominated pair with " +
            entry.pair.remote_candidate.endpoint.address().to_string() + ":" +
            std::to_string(entry.pair.remote_candidate.endpoint.port()) +
            " [Component " + std::to_string(entry.pair.local_candidate.component_id) + "]");

        // Trigger nominate callback if set
        if (nominate_callback_) {
            nominate_callback_(entry.pair);
        }
    }
}

// Send NOMINATE message using STUN Binding Indication with USE-CANDIDATE attribute
asio::awaitable<void> IceAgent::send_nominate(const CandidatePair& pair) {
    std::vector<uint8_t> txn_id = generate_transaction_id();

    Stun::StunMessage nominate_msg(STUN_BINDING_INDICATION, txn_id);
    // Add USE-CANDIDATE attribute as per RFC 8445
    nominate_msg.add_attribute("USE-CANDIDATE", "");
    // Add ICE-CONTROLLING if Controller
    if (role_ == IceRole::Controller) {
        // Generate a unique tie-breaker value
        std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
        std::random_device rd;
        std::mt19937 gen(rd());
        uint32_t tie_breaker = dist(gen);
        nominate_msg.add_attribute("ICE-CONTROLLING", std::to_string(tie_breaker));
    }

    // Add MESSAGE-INTEGRITY
    nominate_msg.add_attribute("MESSAGE-INTEGRITY", calculate_hmac_sha1(nominate_msg, ice_attributes_.password));

    // Add FINGERPRINT
    nominate_msg.add_attribute("FINGERPRINT", calculate_crc32(nominate_msg));

    std::vector<uint8_t> serialized_nominate = nominate_msg.serialize();
    co_await socket_.async_send_to(asio::buffer(serialized_nominate), pair.remote_candidate.endpoint, asio::use_awaitable);

    log(LogLevel::INFO, "Sent NOMINATE to " +
        pair.remote_candidate.endpoint.address().to_string() + ":" +
        std::to_string(pair.remote_candidate.endpoint.port()) +
        " [Component " + std::to_string(pair.local_candidate.component_id) + "]");

    // Trigger nominate callback if set
    if (nominate_callback_) {
        nominate_callback_(pair);
    }
}

// ICE Restart initiation (사용하는 곳이 없다._
void IceAgent::initiate_ice_restart() {
    if (mode_ == IceMode::Lite) {
        log(LogLevel::WARNING, "ICE Restart is not supported in ICE Lite mode.");
        return;
    }

    log(LogLevel::INFO, "Initiating ICE Restart...");

    // Reset existing state
    current_state_ = IceConnectionState::New;
    nominated_pair_ = CandidatePair();
    check_list_.clear();
    candidate_pairs_.clear();
    remote_candidates_.clear();

    // Gather new candidates and restart ICE
    asio::co_spawn(io_context_, start(), asio::detached);

    // Inform remote peer via signaling (e.g., SDP with new ICE credentials)
    if (signaling_client_) {
        signaling_client_->send_ice_restart();
    }
}

// Handle incoming signaling messages and process ICE parameters
asio::awaitable<void> IceAgent::handle_incoming_signaling_messages() {
    while (current_state_ != IceConnectionState::Failed) {
        std::string sdp = co_await signaling_client_->receive_sdp();

        // Parse SDP message
        std::vector<std::string> remote_candidates;
        std::string remote_ufrag;
        std::string remote_pwd;
        std::tie(remote_ufrag, remote_pwd) = signaling_client_->parse_sdp(sdp, remote_candidates);

        ice_attributes_.username_fragment = remote_ufrag;
        ice_attributes_.password = remote_pwd;

        // Parse and add remote candidates
        for(const auto& cand_str : remote_candidates) {
            Candidate remote_candidate = Candidate::from_sdp(cand_str);
            add_remote_candidate(remote_candidate);
        }

        // Determine role based on ICE-CONTROLLING and ICE-CONTROLLED
        if (sdp.find("ICE-CONTROLLING") != std::string::npos) {
            negotiate_role(IceRole::Controlled);
        }
        else if (sdp.find("ICE-CONTROLLED") != std::string::npos) {
            negotiate_role(IceRole::Controller);
        }
    }
    co_return;
}

// Handle incoming USE-CANDIDATE for nomination in Controlled role
#if 0
asio::awaitable<void> IceAgent::handle_incoming_stun_messages() {
    while (current_state_ != IceConnectionState::Failed) {
        std::vector<uint8_t> buffer(2048);
        asio::ip::udp::endpoint sender_endpoint;
        try {
            size_t bytes_received = co_await socket_.async_receive_from(asio::buffer(buffer), sender_endpoint, asio::use_awaitable);
            buffer.resize(bytes_received);
            Stun::StunMessage received_message = Stun::StunMessage::parse(buffer);
            
            // Process USE-CANDIDATE attribute for nomination
            if (received_message.has_attribute("USE-CANDIDATE")) {
                // Identify the corresponding candidate pair
                bool found = false;
                for (auto& entry : check_list_) {
                    if (entry.pair.remote_candidate.endpoint == sender_endpoint &&
                        entry.pair.local_candidate.endpoint == received_message.get_attribute("MAPPED-ADDRESS")) { // 수정됨
                        entry.nominated = true;
                        nominated_pair_ = entry.pair;
                        transition_to_state(IceConnectionState::Connected);
                        log(LogLevel::INFO, "Received USE-CANDIDATE, nominated pair with " +
                            sender_endpoint.address().to_string() + ":" +
                            std::to_string(sender_endpoint.port()) +
                            " [Component " + std::to_string(entry.pair.local_candidate.component_id) + "]");
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    log(LogLevel::WARNING, "Received USE-CANDIDATE for unknown candidate pair.");
                }
            }
            
            // Handle other STUN messages as needed
            
        } catch (const std::exception& ex) {
            log(LogLevel::ERROR, "Error handling incoming STUN message: " + std::string(ex.what()));
            transition_to_state(IceConnectionState::Failed);
        }
    }
    co_return;
}
#endif

// Perform a single connectivity check
asio::awaitable<void> IceAgent::perform_single_connectivity_check(CheckListEntry& entry) {
    const CandidatePair& pair = entry.pair;

    if (pair.remote_candidate.type == "srflx" || pair.remote_candidate.type == "host") {
        // Connectivity check using STUN Binding Request
        std::vector<uint8_t> txn_id = generate_transaction_id();
        Stun::StunMessage binding_request(STUN_BINDING_REQUEST, txn_id);
        binding_request.add_attribute("PRIORITY", std::to_string(pair.local_candidate.priority));
        binding_request.add_attribute("USERNAME", ice_attributes_.username_fragment);
        binding_request.add_attribute("MESSAGE-INTEGRITY", calculate_hmac_sha1(binding_request, ice_attributes_.password));
        binding_request.add_attribute("FINGERPRINT", calculate_crc32(binding_request));
        std::vector<uint8_t> serialized_request = binding_request.serialize();

        // Send Binding Request
        co_await socket_.async_send_to(asio::buffer(serialized_request), pair.remote_candidate.endpoint, asio::use_awaitable);

        // Set timeout
        asio::steady_timer timer(io_context_);
        timer.expires_after(std::chrono::seconds(2));

        std::vector<uint8_t> recv_buffer(2048);
        asio::ip::udp::endpoint sender_endpoint;

        using namespace asio::experimental::awaitable_operators;
        auto [ec, bytes_received] = co_await (
            socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint, asio::use_awaitable)
            || timer.async_wait(asio::use_awaitable)
        );

        if (ec == asio::error::operation_aborted) {
            throw std::runtime_error("Connectivity check timed out.");
        } else if (ec) {
            throw std::runtime_error("Connectivity check failed: " + std::string(ec.message()));
        }

        recv_buffer.resize(bytes_received);
        Stun::StunMessage response = Stun::StunMessage::parse(recv_buffer);

        // Verify response
        if (response.get_transaction_id() != txn_id) {
            throw std::runtime_error("STUN Transaction ID mismatch.");
        }

        if (response.get_type() != STUN_BINDING_RESPONSE_SUCCESS) {
            throw std::runtime_error("Invalid STUN Binding Response type.");
        }

        // Verify MESSAGE-INTEGRITY
        if (!response.verify_message_integrity(ice_attributes_.password)) {
            throw std::runtime_error("Invalid MESSAGE-INTEGRITY in STUN response.");
        }

        // Verify FINGERPRINT
        if (!response.verify_fingerprint()) {
            throw std::runtime_error("Invalid FINGERPRINT in STUN response.");
        }

        // Extract MAPPED-ADDRESS
        std::string mapped_address = response.get_attribute("MAPPED-ADDRESS");
        if (mapped_address.empty()) {
            throw std::runtime_error("MAPPED-ADDRESS attribute missing in STUN response.");
        }

        // Parse MAPPED-ADDRESS
        size_t colon_pos = mapped_address.find(':');
        if (colon_pos == std::string::npos) {
            throw std::runtime_error("Invalid MAPPED-ADDRESS format.");
        }
        std::string ip = mapped_address.substr(0, colon_pos);
        uint16_t port = static_cast<uint16_t>(std::stoi(mapped_address.substr(colon_pos + 1)));

        asio::ip::udp::endpoint mapped_endpoint(asio::ip::make_address(ip), port);

        // 연결 성공 처리
        co_return;
    }
    else if (pair.remote_candidate.type == "relay") {
        // Relay connectivity check using TURN Send (data transmission)
        std::vector<uint8_t> data = { 'D', 'A', 'T', 'A' };
        co_await socket_.async_send_to(asio::buffer(data), pair.remote_candidate.endpoint, asio::use_awaitable);
        log(LogLevel::INFO, "Sent data via TURN relay to " +
            pair.remote_candidate.endpoint.address().to_string() + ":" +
            std::to_string(pair.remote_candidate.endpoint.port()) +
            " [Component " + std::to_string(pair.local_candidate.component_id) + "]");

        // Set timeout
        asio::steady_timer timer(io_context_);
        timer.expires_after(std::chrono::seconds(2));

        std::vector<uint8_t> recv_buffer(2048);
        asio::ip::udp::endpoint sender_endpoint_recv;

        using namespace asio::experimental::awaitable_operators;
        auto [ec, bytes_transferred] = co_await (
            socket_.async_receive_from(asio::buffer(recv_buffer), sender_endpoint_recv, asio::use_awaitable)
            || timer.async_wait(asio::use_awaitable)
        );

        if (ec == asio::error::operation_aborted) {
            throw std::runtime_error("Relay connectivity check timed out.");
        } else if (ec) {
            throw std::runtime_error("Relay connectivity check failed: " + std::string(ec.message()));
        }

        if (bytes_transferred > 0) {
            co_return; // Success
        } else {
            throw std::runtime_error("No data received from relay.");
        }
    }

    co_return;
}

// Nominate a successful candidate pair based on role
void IceAgent::nominate_pair(CheckListEntry& entry) {
    if (role_ == IceRole::Controller) {
        entry.nominated = true;
        nominated_pair_ = entry.pair;
        
        // Send NOMINATE message to the remote peer
        asio::co_spawn(io_context_, send_nominate(entry.pair), asio::detached);
        
        log(LogLevel::INFO, "Nominated pair with " +
            entry.pair.remote_candidate.endpoint.address().to_string() + ":" +
            std::to_string(entry.pair.remote_candidate.endpoint.port()) +
            " [Component " + std::to_string(entry.pair.local_candidate.component_id) + "]");
    }
}

// Evaluate connectivity results and nominate pairs
void IceAgent::evaluate_connectivity_results() {
    bool any_succeeded = false;
    for (auto& entry : check_list_) {
        if (entry.state == CandidatePairState::Succeeded && !entry.is_nominated) {
            nominate_pair(entry);
            any_succeeded = true;
            break; // Nominate the first successful pair
        }
    }

    if (any_succeeded) {
        transition_to_state(IceConnectionState::Connected);
    } else {
        log(LogLevel::ERROR, "No valid candidate pairs found after connectivity checks.");
        transition_to_state(IceConnectionState::Failed);
    }
}

#endif // ICE_AGENT_HPP
