#pragma once
#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/experimental/parallel_group.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <functional>
#include <memory>
#include <atomic>
#include <chrono>
#include <string>
#include <vector>
#include <set>
#include <random>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <optional>
#include "stun_message.hpp"
#include "signaling_client.hpp"

// -------------------- ENUMS / STRUCTS --------------------
enum class IceMode {
    Full,
    Lite
};

enum class IceRole {
    Controller,
    Controlled
};

enum class IceConnectionState {
    New,
    Gathering,
    Checking,
    Connected,
    Completed,
    Failed
};

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

enum class CandidateType {
    Host,
    PeerReflexive,
    ServerReflexive,
    Relay
};

// Candidate
struct Candidate {
    asio::ip::udp::endpoint endpoint;
    CandidateType type;
    uint32_t priority;
    int component_id;
    std::string foundation;
    std::string transport;

    // SDP 변환
    std::string to_sdp() const {
        std::ostringstream oss;
        oss << "a=candidate:" << foundation << " " << component_id << " " 
            << transport << " " << priority << " "
            << endpoint.address().to_string() << " " << endpoint.port()
            << " typ ";
        switch(type){
            case CandidateType::Host: oss<<"host"; break;
            case CandidateType::PeerReflexive: oss<<"prflx"; break;
            case CandidateType::ServerReflexive: oss<<"srflx"; break;
            case CandidateType::Relay: oss<<"relay"; break;
        }
        return oss.str();
    }

    static Candidate from_sdp(const std::string& sdp_line) {
        Candidate c;
        std::istringstream iss(sdp_line);
        std::string prefix; 
        iss >> prefix; // "a=candidate:..."
        size_t colon = prefix.find(':');
        if (colon!=std::string::npos) {
            c.foundation = prefix.substr(colon+1);
        }
        iss >> c.component_id;
        iss >> c.transport;
        iss >> c.priority;
        std::string ip; uint16_t port;
        iss >> ip >> port;
        c.endpoint = asio::ip::udp::endpoint(asio::ip::make_address(ip), port);

        std::string typ; iss >> typ; // "typ"
        std::string type_str; iss >> type_str;
        if (type_str=="host") c.type = CandidateType::Host;
        else if (type_str=="prflx") c.type = CandidateType::PeerReflexive;
        else if (type_str=="srflx") c.type = CandidateType::ServerReflexive;
        else if (type_str=="relay") c.type = CandidateType::Relay;

        return c;
    }
};

struct CandidatePair {
    Candidate local_candidate;
    Candidate remote_candidate;
    uint64_t priority;
    CandidatePair() = default;
    CandidatePair(const Candidate& l, const Candidate& r)
        : local_candidate(l), remote_candidate(r), priority(0) {}
};

enum class CandidatePairState {
    New,
    InProgress,
    Failed,
    Succeeded,
    Nominated
};

struct CheckListEntry {
    CandidatePair pair;
    CandidatePairState state;
    bool is_nominated;

    CheckListEntry(const CandidatePair& cp)
        : pair(cp), state(CandidatePairState::New), is_nominated(false) {}
};

// 콜백
using StateCallback = std::function<void(IceConnectionState)>;
using CandidateCallback = std::function<void(const Candidate&)>;
using DataCallback = std::function<void(const std::vector<uint8_t>&, const asio::ip::udp::endpoint&)>;
using NominateCallback = std::function<void(const CandidatePair&)>;

// ICE Attributes
struct IceAttributes {
    std::string ufrag;
    std::string pwd;
    IceRole role;
    uint64_t tie_breaker;
    std::string session_id; // 로컬 또는 원격 세션 ID
    std::set<std::string> options; // {"ice-lite","ice2","trickle"}
};

// -------------------- ICE AGENT --------------------
class IceAgent : public std::enable_shared_from_this<IceAgent> {
public:
    IceAgent(asio::io_context& io_context,
             IceRole role,
             IceMode mode,
             const std::vector<std::string>& stun_servers,
             const std::string& turn_server="",
             const std::string& turn_username="",
             const std::string& turn_password="",
             std::chrono::seconds connectivity_check_timeout=std::chrono::seconds(3),
             size_t connectivity_check_retries=3)
    : strand_(io_context.get_executor()),
      socket_(strand_),
      role_(role),
      mode_(mode),
      tie_breaker_(0),
      stun_servers_(stun_servers),
      turn_server_(turn_server),
      turn_username_(turn_username),
      turn_password_(turn_password),
      current_state_(IceConnectionState::New),
      log_level_(LogLevel::INFO),
      connectivity_check_timeout_(connectivity_check_timeout),
      connectivity_check_retries_(connectivity_check_retries)
    {
        // Random session id
        session_id_ = generate_random_string(12);

        // Resolve STUN servers and store endpoints
        asio::ip::udp::resolver resolver(io_context);
        for (const auto& s: stun_servers_) {
            size_t pos = s.find(':');
            if (pos != std::string::npos) {
                std::string host = s.substr(0, pos);
                std::string port_str = s.substr(pos+1);
                try {
                    auto results = resolver.resolve(asio::ip::udp::v4(), host, port_str);
                    for (const auto& r : results) {
                        stun_endpoints_.push_back(r.endpoint());
                        log(LogLevel::DEBUG, "Resolved STUN server: " + r.endpoint().address().to_string() + ":" + std::to_string(r.endpoint().port()));
                    }
                } catch(const std::exception& ex) {
                    log(LogLevel::WARNING, "Failed to resolve STUN server '" + s + "': " + ex.what());
                }
            }
        }

        // Resolve TURN server and store endpoint
        if (!turn_server_.empty()) {
            size_t pos = turn_server_.find(':');
            if (pos != std::string::npos) {
                std::string host = turn_server_.substr(0, pos);
                std::string port_str = turn_server_.substr(pos+1);
                try {
                    asio::ip::udp::resolver resolver_turn(io_context);
                    auto results = resolver_turn.resolve(asio::ip::udp::v4(), host, port_str);
                    if (!results.empty()) {
                        turn_endpoints_.push_back(results.begin()->endpoint());
                        log(LogLevel::DEBUG, "Resolved TURN server: " + results.begin()->endpoint().address().to_string() + ":" + std::to_string(results.begin()->endpoint().port()));
                    }
                } catch(const std::exception& ex) {
                    log(LogLevel::WARNING, "Failed to resolve TURN server '" + turn_server_ + "': " + ex.what());
                }
            }
        }

        // Initialize TURN allocation endpoint (initially unset)
        relay_endpoint_ = asio::ip::udp::endpoint();

        // Open socket (dual-stack)
        std::error_code ec;
        socket_.open(asio::ip::udp::v6(), ec);
        if (!ec) {
            asio::ip::v6_only opt(false);
            socket_.set_option(opt, ec);
        }
        if (ec) {
            // fallback IPv4
            socket_.open(asio::ip::udp::v4(), ec);
        }
        if (!ec) {
            socket_.bind(asio::ip::udp::endpoint(socket_.local_endpoint().protocol(), 0), ec);
            if (!ec) {
                log(LogLevel::DEBUG, "Socket bound to " + socket_.local_endpoint().address().to_string() + ":" + std::to_string(socket_.local_endpoint().port()));
            }
        }
        if (ec) {
            log(LogLevel::ERROR, "Failed to bind socket: " + ec.message());
            transition_to_state(IceConnectionState::Failed);
        }
    }

    ~IceAgent() {
        std::error_code ec;
        socket_.close(ec);
    }

    // 콜백 설정
    void set_on_state_change_callback(StateCallback cb) { state_callback_ = std::move(cb); }
    void set_candidate_callback(CandidateCallback cb) { candidate_callback_ = std::move(cb); }
    void set_data_callback(DataCallback cb) { data_callback_ = std::move(cb); }
    void set_nominate_callback(NominateCallback cb) { nominate_callback_ = std::move(cb); }
    void set_signaling_client(std::shared_ptr<SignalingClient> sc) { signaling_client_ = sc; }

    // 로그
    void set_log_level(LogLevel level) { log_level_ = level; }

    // ICE 시작
    void start() {
        if (current_state_==IceConnectionState::New) return;
        local_ice_attributes_ = generate_ice_attributes();

        asio::co_spawn(strand_,
            [this, self=shared_from_this()]() -> asio::awaitable<void> {
                try {
                    nominated_pair_ = CandidatePair();
                    check_list_.clear();
                    remote_candidates_.clear();
                    local_candidates_.clear();

                    // 후보 수집
                    co_await gather_candidates();

                    // 시그널링 송신
                    if (signaling_client_) {
                        std::string sdp = signaling_client_->create_sdp(local_ice_attributes_, local_candidates_);
                        co_await signaling_client_->send_sdp(sdp);

                        // 수신 대기
                        asio::co_spawn(strand_, handle_incoming_signaling_messages(), asio::detached);
                    }

                    if (mode_ == IceMode::Full) {
                        transition_to_state(IceConnectionState::Checking);
                        co_await perform_connectivity_checks();
                    } else {
                        // Lite
                        log(LogLevel::INFO, "ICE Lite mode => skipping local checks, waiting for remote side to check.");
                        transition_to_state(IceConnectionState::Connected);
                    }

                    if (current_state_ == IceConnectionState::Connected || current_state_ == IceConnectionState::Completed) {
                        // Keep-alive
                        if (mode_ == IceMode::Full) {
                            asio::co_spawn(strand_, perform_consent_freshness(), asio::detached);
                        }
                        // TURN refresh
                        if (!relay_endpoint_.address().is_unspecified()) { // [**Modified**] Check if TURN allocation exists
                            asio::co_spawn(strand_, perform_turn_refresh(), asio::detached);
                        }
                        // 수신
                        asio::co_spawn(strand_, start_data_receive(), asio::detached);
                    }
                } catch (const std::exception& ex) {
                    log(LogLevel::ERROR, std::string("start() exception: ")+ex.what());
                    transition_to_state(IceConnectionState::Failed);
                }
                co_return;
            }, asio::detached
        );
    }

    // ICE 재시작
    void restart_ice() {
        log(LogLevel::INFO, "Restarting ICE...");
        start();
    }

    // 데이터 전송
    void send_data(const std::vector<uint8_t>& data) {
        if (current_state_ != IceConnectionState::Connected && current_state_ != IceConnectionState::Completed) {
            log(LogLevel::WARNING,"send_data() => not connected");
            return;
        }
        asio::ip::udp::endpoint target = nominated_pair_.remote_candidate.endpoint;

        // If relay is allocated, use relay endpoint
        if (!relay_endpoint_.address().is_unspecified()) {
            target = relay_endpoint_;
        }

        socket_.async_send_to(asio::buffer(data),
                              target,
        [this](std::error_code ec, std::size_t){
            if (ec) {
                log(LogLevel::ERROR, "send_data failed: " + ec.message());
            }
        });
    }

private:
    // 멤버들
    asio::strand<asio::io_context::executor_type> strand_;
    asio::ip::udp::socket socket_;
    IceRole role_;
    IceMode mode_;
    uint64_t tie_breaker_;
    std::vector<std::string> stun_servers_;
    std::vector<asio::ip::udp::endpoint> stun_endpoints_; // Resolved STUN server endpoints
    std::vector<asio::ip::udp::endpoint> turn_endpoints_; // Resolved TURN server endpoints
    std::string turn_server_;
    std::string turn_username_;
    std::string turn_password_;
    std::atomic<IceConnectionState> current_state_;
    LogLevel log_level_;

    std::vector<Candidate> local_candidates_;
    std::vector<Candidate> remote_candidates_;
    std::vector<CheckListEntry> check_list_;

    asio::ip::udp::endpoint relay_endpoint_; // Allocated relay endpoint

    std::shared_ptr<SignalingClient> signaling_client_;

    StateCallback state_callback_;
    CandidateCallback candidate_callback_;
    DataCallback data_callback_;
    NominateCallback nominate_callback_;

    CandidatePair nominated_pair_;
    std::chrono::seconds connectivity_check_timeout_;
    size_t connectivity_check_retries_;

    // ICE 자격
    IceAttributes local_ice_attributes_;
    IceAttributes remote_ice_attributes_;

    // ---------- 내부 함수들 ----------
    bool transition_to_state(IceConnectionState new_state) {
        if (current_state_ == new_state) return false;
        current_state_ = new_state;
        if (state_callback_) {
            state_callback_(new_state);
        }
        log(LogLevel::INFO, "ICE State => " + std::to_string(static_cast<int>(new_state)));
        return true;
    }

    // 로컬 ICE 자격 생성
    IceAttributes generate_ice_attributes() {
        IceAttributes attrs;
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist;
        tie_breaker_ = dist(gen);
        attrs.tie_breaker = tie_breaker_;
        attrs.ufrag = generate_random_string(8);
        attrs.pwd = generate_random_string(24);
        attrs.role = role_;
        if (mode_ == IceMode::Lite) {
            attrs.options.insert("ice-lite");
        } else {
            attrs.options.insert("ice2");
            attrs.options.insert("trickle");
        }
        return attrs;
    }

    // gather_candidates()
    asio::awaitable<void> gather_candidates() {
        transition_to_state(IceConnectionState::Gathering);
        co_await gather_local_candidates();
        co_await gather_srflx_candidates();
        co_await gather_relay_candidates();
        co_return;
    }

    asio::awaitable<void> gather_local_candidates() {
        asio::ip::udp::resolver resolver(strand_);
        auto results4 = co_await resolver.async_resolve(asio::ip::udp::v4(), "0.0.0.0","0", asio::use_awaitable);
        auto results6 = co_await resolver.async_resolve(asio::ip::udp::v6(), "::","0", asio::use_awaitable);

        auto add_candidate = [&](const asio::ip::udp::endpoint& ep){
            Candidate c;
            c.endpoint = ep;
            c.type = CandidateType::Host;
            c.foundation = "host";
            c.transport = "UDP";
            c.component_id = 1;
            c.priority = calculate_priority(c);
            local_candidates_.push_back(c);
            if (candidate_callback_) {
                candidate_callback_(c);
            }
            log(LogLevel::DEBUG, "Gathered local candidate: " + c.to_sdp());
        };
        for (auto& r: results4) add_candidate(r.endpoint());
        for (auto& r: results6) add_candidate(r.endpoint());
        co_return;
    }

    asio::awaitable<void> gather_srflx_candidates() {
        for (const auto& stun_ep : stun_endpoints_) { // Iterate over resolved STUN endpoints
            try {
                // Create a binding request STUN message
                StunMessage req(StunMessageType::BINDING_REQUEST, StunMessage::generate_transaction_id());
                // Add necessary attributes
                req.add_attribute(StunAttributeType::PRIORITY, serialize_uint32(calculate_priority(local_candidates_[0])));
                req.add_attribute(StunAttributeType::USERNAME, remote_ice_attributes_.ufrag + ":" + local_ice_attributes_.ufrag);
                if (role_ == IceRole::Controller) {
                    req.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
                } else {
                    req.add_attribute(StunAttributeType::ICE_CONTROLLED, serialize_uint64(local_ice_attributes_.tie_breaker));
                }
                req.add_message_integrity(remote_ice_attributes_.pwd);
                req.add_fingerprint();

                // Send STUN request and await response
                auto resp_opt = co_await send_stun_request_with_retransmit(req, remote_ice_attributes_.pwd, stun_ep,
                                                                         std::chrono::milliseconds(500),
                                                                         7);
                if (resp_opt.has_value()) {
                    StunMessage resp = resp_opt.value();
                    // Extract mapped address from response
                    // Assuming StunMessage has a method to get mapped address
                    asio::ip::udp::endpoint mapped = resp.get_mapped_address(); // Implement this method as needed
                    Candidate c;
                    c.endpoint = mapped;
                    c.type = CandidateType::ServerReflexive;
                    c.foundation = "srflx";
                    c.transport = "UDP";
                    c.component_id = 1;
                    c.priority = calculate_priority(c);
                    local_candidates_.push_back(c);
                    if (candidate_callback_){
                        candidate_callback_(c);
                    }
                    log(LogLevel::DEBUG, "Gathered SRFLX candidate: " + c.to_sdp());
                }
            } catch(const std::exception& ex) {
                log(LogLevel::WARNING, "Failed to gather SRFLX candidate from " + stun_ep.address().to_string() + ":" + std::to_string(stun_ep.port()) + " | " + ex.what());
            }
        }
        co_return;
    }

    asio::awaitable<void> gather_relay_candidates() {
        // Handle TURN allocation if TURN servers are available
        if (!turn_endpoints_.empty()) {
            for (const auto& turn_ep : turn_endpoints_) { // Iterate over resolved TURN endpoints
                try {
                    // Create TURN Allocate request (a type of STUN request with specific attributes)
                    StunMessage alloc_req(StunMessageType::ALLOCATE, StunMessage::generate_transaction_id());
                    // Add necessary attributes for TURN allocation
                    alloc_req.add_attribute(StunAttributeType::USERNAME, turn_username_);
                    alloc_req.add_attribute(StunAttributeType::REALM, "example.com"); // Replace with actual realm
                    alloc_req.add_attribute(StunAttributeType::NONCE, "nonce"); // Replace with actual nonce
                    // Add message integrity using TURN password
                    alloc_req.add_message_integrity(turn_password_);
                    alloc_req.add_fingerprint();

                    // Send Allocate request and await response
                    auto resp_opt = co_await send_stun_request_with_retransmit(alloc_req, turn_password_, turn_ep,
                                                                             std::chrono::milliseconds(1000),
                                                                             5);
                    if (resp_opt.has_value()) {
                        StunMessage resp = resp_opt.value();
                        // Extract relay endpoint from response
                        // Assuming StunMessage has a method to get relay address
                        asio::ip::udp::endpoint relay = resp.get_relay_address(); // Implement this method as needed
                        relay_endpoint_ = relay;
                        log(LogLevel::DEBUG, "Allocated TURN relay: " + relay.address().to_string() + ":" + std::to_string(relay.port()));
                        
                        // Create Relay candidate
                        Candidate c;
                        c.endpoint = relay;
                        c.type = CandidateType::Relay;
                        c.foundation = "relay";
                        c.transport = "UDP";
                        c.component_id = 1;
                        c.priority = calculate_priority(c);
                        local_candidates_.push_back(c);
                        if (candidate_callback_){
                            candidate_callback_(c);
                        }
                        log(LogLevel::DEBUG, "Gathered Relay candidate: " + c.to_sdp());

                        // Start periodic refresh
                        asio::co_spawn(strand_, perform_turn_refresh(), asio::detached);
                        break; // Assume one TURN server for simplicity
                    }
                } catch(const std::exception& ex) {
                    log(LogLevel::WARNING, "Failed to allocate TURN relay from " + turn_ep.address().to_string() + ":" + std::to_string(turn_ep.port()) + " | " + ex.what());
                }
            }
        }
        co_return;
    }

    // ConnCheck
    asio::awaitable<void> perform_connectivity_checks() {
        // Pair 생성
        check_list_.clear();
        for (auto& rc : remote_candidates_) {
            for (auto& lc : local_candidates_) {
                if (lc.component_id == rc.component_id) {
                    CandidatePair cp(lc, rc);
                    cp.priority = calculate_priority_pair(lc, rc);
                    check_list_.emplace_back(cp);
                }
            }
        }
        // 정렬
        sort_candidate_pairs();

        // 병렬 검사
        try {
            std::vector<asio::awaitable<void>> tasks;
            size_t concurrency = std::min<size_t>(5, check_list_.size());
            for (size_t i=0; i<concurrency; ++i) {
                tasks.emplace_back([this, i]() -> asio::awaitable<void>{
                    CheckListEntry& entry = check_list_[i];

                    if (entry.state == CandidatePairState::New || entry.state == CandidatePairState::Failed) {
                        entry.state = CandidatePairState::InProgress;
                        co_await perform_single_connectivity_check(entry);
                    }

                    co_return;
                }());
            }
            co_await (tasks.begin(), tasks.end());
            co_await evaluate_connectivity_results();
        } catch(...) {
            transition_to_state(IceConnectionState::Failed);
        }

        co_return;
    }

    asio::awaitable<void> perform_single_connectivity_check(CheckListEntry& entry) {
        const auto& pair = entry.pair;
        bool is_relay = (pair.remote_candidate.type == CandidateType::Relay);

        // STUN Binding Request
        StunMessage req(StunMessageType::BINDING_REQUEST, StunMessage::generate_transaction_id());
        // priority
        req.add_attribute(StunAttributeType::PRIORITY, serialize_uint32(pair.local_candidate.priority));
        // username => remoteUfrag:localUfrag
        std::string uname = remote_ice_attributes_.ufrag + ":" + local_ice_attributes_.ufrag;
        req.add_attribute(StunAttributeType::USERNAME, uname);
        // role
        if (role_ == IceRole::Controller) {
            req.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
        } else {
            req.add_attribute(StunAttributeType::ICE_CONTROLLED, serialize_uint64(local_ice_attributes_.tie_breaker));
        }
        // message integrity(송신자는 remote pwd)
        req.add_message_integrity(remote_ice_attributes_.pwd);
        req.add_fingerprint();

        asio::ip::udp::endpoint dest = pair.remote_candidate.endpoint;

        std::optional<StunMessage> resp_opt;
        try {
            if (is_relay && !relay_endpoint_.address().is_unspecified()) {
                // Send STUN request via TURN relay
                resp_opt = co_await send_stun_request_with_retransmit(req, remote_ice_attributes_.pwd, relay_endpoint_,
                                                                         std::chrono::milliseconds(500),
                                                                         7);
            } else {
                // Send direct STUN request
                resp_opt = co_await send_stun_request_with_retransmit(req, remote_ice_attributes_.pwd, dest,
                                                                     std::chrono::milliseconds(500),
                                                                     7);
            }

            if (resp_opt.has_value()) {
                entry.state = CandidatePairState::Succeeded;
                log(LogLevel::DEBUG, "Connectivity check succeeded for pair: " + pair.local_candidate.to_sdp() + " <-> " + pair.remote_candidate.to_sdp());
            } else {
                entry.state = CandidatePairState::Failed;
                log(LogLevel::DEBUG, "Connectivity check failed for pair: " + pair.local_candidate.to_sdp() + " <-> " + pair.remote_candidate.to_sdp());
            }
        } catch(const std::exception& ex) {
            entry.state = CandidatePairState::Failed;
            log(LogLevel::WARNING, "Connectivity check exception for pair: " + pair.local_candidate.to_sdp() + " <-> " + pair.remote_candidate.to_sdp() + " | " + ex.what());
        }

        co_return;
    }

    // STUN 재전송 및 응답 반환
    asio::awaitable<std::optional<StunMessage>> send_stun_request_with_retransmit(
        const StunMessage& request,
        const std::string& remote_pwd,
        const asio::ip::udp::endpoint& dest,
        std::chrono::milliseconds initial_timeout,
        int max_tries)
    {
        using namespace asio::experimental::awaitable_operators;

        auto data = request.serialize();
        auto txn_id = request.get_transaction_id();

        std::chrono::milliseconds timeout = initial_timeout;
        for (int attempt = 0; attempt < max_tries; ++attempt) {
            co_await socket_.async_send_to(asio::buffer(data), dest, asio::use_awaitable);
            log(LogLevel::DEBUG, "Sent STUN request to " + dest.address().to_string() + ":" + std::to_string(dest.port()) + " | Attempt: " + std::to_string(attempt + 1));

            asio::steady_timer timer(strand_);
            timer.expires_after(timeout);

            std::vector<uint8_t> buf(2048);
            asio::ip::udp::endpoint sender;

            std::optional<StunMessage> response = std::nullopt;

            co_await (
                (
                    [&]() -> asio::awaitable<void> {
                        try {
                            std::size_t bytes = co_await socket_.async_receive_from(asio::buffer(buf), sender, asio::use_awaitable);
                            buf.resize(bytes);
                            StunMessage resp = StunMessage::parse(buf);
                            if (resp.get_transaction_id() == txn_id &&
                                resp.get_type() == StunMessageType::BINDING_RESPONSE_SUCCESS) {
                                // Verify message integrity and fingerprint
                                if (resp.verify_message_integrity(local_ice_attributes_.pwd) &&
                                    resp.verify_fingerprint()) {
                                    response = resp;
                                }
                            }
                        } catch(...) {
                            // Parsing failed or other errors; ignore and continue
                        }
                    }()
                )
                ||
                (
                    [&]() -> asio::awaitable<void> {
                        try {
                            co_await timer.async_wait(asio::use_awaitable);
                        } catch(...) {
                            // Ignore timer cancellation
                        }
                    }()
                )
            );

            if (response.has_value()) {
                log(LogLevel::DEBUG, "Received valid STUN response from " + sender.address().to_string() + ":" + std::to_string(sender.port()));
                co_return response;
            }

            // Backoff
            timeout = std::min(timeout * 2, std::chrono::milliseconds(1600));
            log(LogLevel::DEBUG, "STUN retransmit attempt " + std::to_string(attempt + 1) + " failed. Retrying with timeout " + std::to_string(timeout.count()) + "ms.");
        }

        log(LogLevel::WARNING, "STUN request to " + dest.address().to_string() + ":" + std::to_string(dest.port()) + " failed after " + std::to_string(max_tries) + " attempts.");
        co_return std::nullopt;
    }

    asio::awaitable<void> evaluate_connectivity_results() {
        bool any_success = false;
        for (auto& e: check_list_) {
            if (e.state == CandidatePairState::Succeeded && !e.is_nominated) {
                co_await nominate_pair(e);
                any_success = true;
                break;
            }
        }
        if (!any_success) {
            transition_to_state(IceConnectionState::Failed);
            log(LogLevel::ERROR, "All connectivity checks failed.");
        } else {
            transition_to_state(IceConnectionState::Connected);
            log(LogLevel::INFO, "ICE connection established.");
        }
        co_return;
    }

    // Nomination
    asio::awaitable<void> nominate_pair(CheckListEntry& entry) {
        entry.is_nominated = true;
        nominated_pair_ = entry.pair;

        asio::ip::udp::endpoint target = entry.pair.remote_candidate.endpoint;
        // If relay is allocated and pair uses relay, use relay endpoint
        if (entry.pair.remote_candidate.type == CandidateType::Relay && !relay_endpoint_.address().is_unspecified()) {
            target = relay_endpoint_;
        }

        if (role_ == IceRole::Controller) {
            // Binding Indication w/ USE-CANDIDATE
            StunMessage ind(StunMessageType::BINDING_INDICATION, StunMessage::generate_transaction_id());
            ind.add_attribute(StunAttributeType::USE_CANDIDATE, {});
            ind.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
            ind.add_message_integrity(remote_ice_attributes_.pwd);
            ind.add_fingerprint();

            co_await socket_.async_send_to(asio::buffer(ind.serialize()),
                                           target,
                                           asio::use_awaitable);
            log(LogLevel::DEBUG, "Sent BINDING_INDICATION with USE-CANDIDATE to " + target.to_string());
            if (nominate_callback_) {
                nominate_callback_(entry.pair);
            }
        } else {
            // Controlled
            if (nominate_callback_) {
                nominate_callback_(entry.pair);
            }
            transition_to_state(IceConnectionState::Completed);
            log(LogLevel::INFO, "ICE connection completed.");
        }
        co_return;
    }

    // Consent Freshness
    asio::awaitable<void> perform_consent_freshness() {
        while (current_state_ == IceConnectionState::Connected
            || current_state_ == IceConnectionState::Completed) 
        {
            asio::steady_timer t(strand_);
            t.expires_after(std::chrono::seconds(15));
            co_await t.async_wait(asio::use_awaitable);
            if (!co_await send_consent_binding_request()) {
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::ERROR, "Consent freshness failed.");
                co_return;
            }
        }
        co_return;
    }

    asio::awaitable<bool> send_consent_binding_request() {
        asio::ip::udp::endpoint target = nominated_pair_.remote_candidate.endpoint;
        // If relay is allocated, use relay endpoint
        if (nominated_pair_.remote_candidate.type == CandidateType::Relay && !relay_endpoint_.address().is_unspecified()) {
            target = relay_endpoint_;
        }

        if (target.address().is_unspecified()) {
            co_return false;
        }
        // BINDING_REQUEST
        StunMessage req(StunMessageType::BINDING_REQUEST, StunMessage::generate_transaction_id());
        req.add_attribute(StunAttributeType::USERNAME, remote_ice_attributes_.ufrag + ":" + local_ice_attributes_.ufrag);
        if (role_ == IceRole::Controller) {
            req.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
        } else {
            req.add_attribute(StunAttributeType::ICE_CONTROLLED, serialize_uint64(local_ice_attributes_.tie_breaker));
        }
        req.add_message_integrity(remote_ice_attributes_.pwd);
        req.add_fingerprint();

        bool ok = false;
        try {
            std::optional<StunMessage> resp_opt = co_await send_stun_request_with_retransmit(
                req, remote_ice_attributes_.pwd,
                target,
                std::chrono::milliseconds(500),
                5
            );
            ok = resp_opt.has_value();
            if (ok) {
                log(LogLevel::DEBUG, "Consent binding request succeeded.");
            } else {
                log(LogLevel::WARNING, "Consent binding request timed out.");
            }
        } catch(const std::exception& ex) {
            log(LogLevel::ERROR, std::string("Consent binding request exception: ") + ex.what());
        }
        co_return ok;
    }

    // TURN refresh
    asio::awaitable<void> perform_turn_refresh() {
        while (current_state_ == IceConnectionState::Connected && !relay_endpoint_.address().is_unspecified()) {
            asio::steady_timer timer(strand_);
            timer.expires_after(std::chrono::seconds(300)); // Refresh every 5 minutes
            co_await timer.async_wait(asio::use_awaitable);
            try {
                // Create TURN Refresh request (similar to Allocate but with REFRESH attribute)
                StunMessage refresh_req(StunMessageType::ALLOCATE, StunMessage::generate_transaction_id());
                // Add necessary attributes
                refresh_req.add_attribute(StunAttributeType::USERNAME, turn_username_);
                refresh_req.add_attribute(StunAttributeType::REALM, "example.com"); // Replace with actual realm
                refresh_req.add_attribute(StunAttributeType::NONCE, "nonce"); // Replace with actual nonce
                refresh_req.add_attribute(StunAttributeType::REFRESH, {}); // Indicate it's a refresh
                refresh_req.add_message_integrity(turn_password_);
                refresh_req.add_fingerprint();

                // Send Refresh request and await response
                auto resp_opt = co_await send_stun_request_with_retransmit(refresh_req, turn_password_, turn_endpoints_[0],
                                                                         std::chrono::milliseconds(1000),
                                                                         5);
                if (resp_opt.has_value()) {
                    StunMessage resp = resp_opt.value();
                    // Validate response if necessary
                    log(LogLevel::DEBUG, "TURN allocation refreshed.");
                } else {
                    throw std::runtime_error("TURN allocation refresh timed out.");
                }
            } catch(const std::exception& ex) {
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::ERROR, std::string("TURN refresh failed: ") + ex.what());
            }
        }
        co_return;
    }

    // 데이터 수신
    asio::awaitable<void> start_data_receive() {
        while (current_state_ == IceConnectionState::Connected
            || current_state_ == IceConnectionState::Completed)
        {
            std::vector<uint8_t> buf(2048);
            asio::ip::udp::endpoint sender;
            size_t bytes=0;
            try {
                bytes = co_await socket_.async_receive_from(asio::buffer(buf), sender, asio::use_awaitable);
            } catch(...) {
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::ERROR, "Data receive failed.");
                break;
            }
            if (bytes > 0) {
                buf.resize(bytes);
                // STUN vs Application data
                try {
                    StunMessage sm = StunMessage::parse(buf);
                    // handle inbound STUN
                    co_await handle_inbound_stun(sm, sender);
                } catch(...) {
                    // not STUN => app data
                    if (data_callback_) {
                        data_callback_(buf, sender);
                        log(LogLevel::DEBUG, "Received application data from " + sender.address().to_string() + ":" + std::to_string(sender.port()));
                    }
                }
            }
        }
        co_return;
    }

    // STUN 수신 처리
    asio::awaitable<void> handle_inbound_stun(const StunMessage& sm, const asio::ip::udp::endpoint& sender) {
        switch(sm.get_type()) {
            case StunMessageType::BINDING_REQUEST:
                co_await handle_inbound_binding_request(sm, sender);
                break;
            case StunMessageType::BINDING_INDICATION:
                co_await handle_binding_indication(sm, sender);
                break;
            default:
                break;
        }
        co_return;
    }

    // Binding Request => Triggered Check
    asio::awaitable<void> handle_inbound_binding_request(const StunMessage& req, const asio::ip::udp::endpoint& sender) {
        // username => "ourUfrag:theirUfrag"
        auto uname = req.get_attribute_as_string(StunAttributeType::USERNAME);
        auto delim = uname.find(':');
        if (delim == std::string::npos) co_return;
        std::string rcv_ufrag = uname.substr(0, delim);
        std::string snd_ufrag = uname.substr(delim+1);

        // 우리가 수신자 => rcv_ufrag == local_ice_attributes_.ufrag
        if (rcv_ufrag != local_ice_attributes_.ufrag) co_return;

        // 무결성 => local pwd로 검증
        if (!req.verify_message_integrity(local_ice_attributes_.pwd)) {
            log(LogLevel::WARNING, "Invalid message integrity in inbound binding request.");
            co_return;
        }
        if (!req.verify_fingerprint()) {
            log(LogLevel::WARNING, "Invalid fingerprint in inbound binding request.");
            co_return;
        }

        // PeerReflexive Candidate 생성 가능
        Candidate prflx;
        prflx.type = CandidateType::PeerReflexive;
        prflx.endpoint = sender;
        prflx.component_id = 1; 
        prflx.foundation = "prflx";
        prflx.transport = "UDP";
        prflx.priority = (110 << 24);

        // check list에 페어 없으면 추가 ...
        bool found_pair = false;
        for (auto& e: check_list_) {
            if (e.pair.remote_candidate.endpoint == sender) {
                found_pair = true;
                break;
            }
        }
        if (!found_pair && !sender.address().is_unspecified()) {
            // local candidate 선택
            Candidate local_cand;
            // 임시로 첫 host candidate 사용 (실제론 family·component matching)
            if (!local_candidates_.empty()) {
                local_cand = local_candidates_[0];
            }
            CandidatePair newp(local_cand, prflx);
            newp.priority = calculate_priority_pair(local_cand, prflx);
            check_list_.emplace_back(newp);
            log(LogLevel::DEBUG, "Added new PeerReflexive pair: " + local_cand.to_sdp() + " <-> " + prflx.to_sdp());

            // Optionally, trigger connectivity check for the new pair
            // For simplicity, not implemented here
        }

        // BINDING RESPONSE
        StunMessage resp(StunMessageType::BINDING_RESPONSE_SUCCESS, req.get_transaction_id());
        resp.add_message_integrity(remote_ice_attributes_.pwd);
        resp.add_fingerprint();

        co_await socket_.async_send_to(asio::buffer(resp.serialize()), sender, asio::use_awaitable);
        log(LogLevel::DEBUG, "Sent BINDING_RESPONSE_SUCCESS to " + sender.address().to_string() + ":" + std::to_string(sender.port()));

        co_return;
    }

    // Binding Indication => USE-CANDIDATE
    asio::awaitable<void> handle_binding_indication(const StunMessage& ind, const asio::ip::udp::endpoint& sender) {
        if (ind.has_attribute(StunAttributeType::USE_CANDIDATE)) {
            // 첫 Succeeded & 미지명 Pair nominate
            for (auto& e: check_list_) {
                if (e.state == CandidatePairState::Succeeded && !e.is_nominated) {
                    co_await nominate_pair(e);
                    break;
                }
            }
            log(LogLevel::DEBUG, "Processed BINDING_INDICATION with USE-CANDIDATE from " + sender.address().to_string() + ":" + std::to_string(sender.port()));
        }
        co_return;
    }

    // 신호 메시지 받기
    asio::awaitable<void> handle_incoming_signaling_messages() {
        while (current_state_ != IceConnectionState::Failed && current_state_ != IceConnectionState::Completed) {
            try {
                std::string sdp = co_await signaling_client_->receive_sdp();
                auto [rattr, rcands] = signaling_client_->parse_sdp(sdp);
                remote_ice_attributes_ = rattr;
                negotiate_role(rattr.tie_breaker);

                if (mode_ == IceMode::Lite && role_ == IceRole::Controller) {
                    log(LogLevel::ERROR, "Lite agent cannot be Controller => fail");
                    transition_to_state(IceConnectionState::Failed);
                    co_return;
                }

                if (rattr.role == IceRole::Controller && role_ == IceRole::Controller) {
                    log(LogLevel::ERROR, "Both sides are Controller => fail");
                    transition_to_state(IceConnectionState::Failed);
                    co_return;
                }

                co_await add_remote_candidate(rcands);

                // If trickle ICE is enabled, handle additional candidates as they arrive
                if (local_ice_attributes_.options.find("trickle") != local_ice_attributes_.options.end()) {
                    if (mode_ == IceMode::Full) {
                        co_await perform_connectivity_checks();
                    }
                }
            } catch(const std::exception& ex) {
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::ERROR, std::string("handle_incoming_signaling_messages exception: ") + ex.what());
            }
        }
        co_return;
    }

    asio::awaitable<void> add_remote_candidate(const std::vector<Candidate>& cands) {
        for (auto& c: cands) {
            remote_candidates_.push_back(c);
            if (candidate_callback_){
                candidate_callback_(c);
            }
            log(LogLevel::DEBUG, "Added remote candidate: " + c.to_sdp());
        }
        if (mode_ == IceMode::Full) {
            co_await perform_connectivity_checks();
        }
        co_return;
    }

    // role 협상
    void negotiate_role(uint64_t remote_tie_breaker) {
        if (tie_breaker_ > remote_tie_breaker) {
            role_=IceRole::Controller;
        } else {
            role_=IceRole::Controlled;
        }
        log(LogLevel::INFO, "Negotiated role => " + std::to_string(static_cast<int>(role_)));
    }

    uint32_t calculate_priority(const Candidate& c) const {
        // RFC 8445
        uint32_t type_pref=0;
        switch(c.type){
            case CandidateType::Host: type_pref=126; break;
            case CandidateType::PeerReflexive: type_pref=110; break;
            case CandidateType::ServerReflexive: type_pref=100; break;
            case CandidateType::Relay: type_pref=0; break;
        }
        uint32_t local_pref=65535;
        uint32_t comp = static_cast<uint32_t>(c.component_id);
        return (type_pref << 24) | (local_pref << 8) | (256 - comp);
    }

    uint64_t calculate_priority_pair(const Candidate& l, const Candidate& r) const {
        uint32_t min_priority = std::min(l.priority, r.priority);
        uint32_t max_priority = std::max(l.priority, r.priority);
        return (static_cast<uint64_t>(min_priority) << 32) + (static_cast<uint64_t>(max_priority) * 2) + ((l.priority > r.priority) ? 1 : 0);
    }

    void sort_candidate_pairs() {
        std::sort(check_list_.begin(), check_list_.end(), [&](auto& a, auto& b){
            return a.pair.priority > b.pair.priority;
        });
    }

    // 로깅
    void log(LogLevel lvl, const std::string& msg) {
        if (lvl < log_level_) return;
        std::cout << "[IceAgent][" << static_cast<int>(lvl) << "] " << msg << std::endl;
    }

    // 랜덤 스트링
    static std::string generate_random_string(size_t len){
        static const char* chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> dist(0,61);
        std::string s; s.reserve(len);
        for(size_t i=0;i<len;++i){
            s.push_back(chars[dist(gen)]);
        }
        return s;
    }

    // 직렬화 uint32
    std::vector<uint8_t> serialize_uint32(uint32_t val) {
        std::vector<uint8_t> out(4);
        for(int i=0;i<4;++i){
            out[3-i]=(val & 0xFF);
            val >>=8;
        }
        return out;
    }

    // 직렬화 uint64
    std::vector<uint8_t> serialize_uint64(uint64_t val) {
        std::vector<uint8_t> out(8);
        for(int i=0;i<8;++i){
            out[7-i]=(val & 0xFF);
            val >>=8;
        }
        return out;
    }

    // ---------- TURN Operations Integrated ----------

    // Allocate TURN relay
    asio::awaitable<void> allocate_turn_relay() {
        if (turn_endpoints_.empty()) {
            log(LogLevel::WARNING, "No TURN servers available for allocation.");
            co_return;
        }

        asio::ip::udp::endpoint turn_ep = turn_endpoints_[0]; // Use first TURN server

        try {
            // Create TURN Allocate request
            StunMessage alloc_req(StunMessageType::ALLOCATE, StunMessage::generate_transaction_id());
            // Add necessary attributes
            alloc_req.add_attribute(StunAttributeType::USERNAME, turn_username_);
            alloc_req.add_attribute(StunAttributeType::REALM, "example.com"); // Replace with actual realm
            alloc_req.add_attribute(StunAttributeType::NONCE, "nonce"); // Replace with actual nonce
            // Indicate it's an allocation request
            // This might require specific TURN attributes not covered here
            alloc_req.add_message_integrity(turn_password_);
            alloc_req.add_fingerprint();

            // Send Allocate request and await response
            auto resp_opt = co_await send_stun_request_with_retransmit(alloc_req, turn_password_, turn_ep,
                                                                     std::chrono::milliseconds(1000),
                                                                     5);
            if (resp_opt.has_value()) {
                StunMessage resp = resp_opt.value();
                // Extract relay endpoint from response
                asio::ip::udp::endpoint relay = resp.get_relay_address(); // Implement this method as needed
                relay_endpoint_ = relay;
                log(LogLevel::DEBUG, "Allocated TURN relay: " + relay.address().to_string() + ":" + std::to_string(relay.port()));
                
                // Create Relay candidate
                Candidate c;
                c.endpoint = relay;
                c.type = CandidateType::Relay;
                c.foundation = "relay";
                c.transport = "UDP";
                c.component_id = 1;
                c.priority = calculate_priority(c);
                local_candidates_.push_back(c);
                if (candidate_callback_){
                    candidate_callback_(c);
                }
                log(LogLevel::DEBUG, "Gathered Relay candidate: " + c.to_sdp());

                // Start periodic refresh
                asio::co_spawn(strand_, perform_turn_refresh(), asio::detached);
            }
        } catch(const std::exception& ex) {
            log(LogLevel::WARNING, "Failed to allocate TURN relay from " + turn_ep.address().to_string() + ":" + std::to_string(turn_ep.port()) + " | " + ex.what());
        }

        co_return;
    }

    // ---------- END TURN Operations Integrated ----------
};
