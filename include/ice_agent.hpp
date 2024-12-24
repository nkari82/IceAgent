#pragma once
#include <asio.hpp>
#include <asio/awaitable.hpp>
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
#include "stun_message.hpp"
#include "stun_client.hpp"
#include "turn_client.hpp"
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

        // STUN Client들 생성
        for (auto& s: stun_servers_) {
            size_t pos = s.find(':');
            if (pos!=std::string::npos) {
                std::string host = s.substr(0,pos);
                uint16_t port = (uint16_t)std::stoi(s.substr(pos+1));
                auto sc = std::make_shared<StunClient>(strand_, host, port, "");
                stun_clients_.push_back(sc);
            }
        }
        // TURN Client
        if (!turn_server_.empty()) {
            size_t pos = turn_server_.find(':');
            if (pos!=std::string::npos) {
                std::string host = turn_server_.substr(0,pos);
                uint16_t port = (uint16_t)std::stoi(turn_server_.substr(pos+1));
                turn_client_ = std::make_shared<TurnClient>(strand_, host, port, turn_username_, turn_password_);
            }
        }

        // 소켓 오픈(dual-stack 시도)
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
        }
        if (ec) {
            log(LogLevel::ERROR, "Failed to bind: " + ec.message());
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
        if (current_state_==IceConnectionState::Gathering) return;
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

                    if (mode_==IceMode::Full) {
                        transition_to_state(IceConnectionState::Checking);
                        co_await perform_connectivity_checks();
                    } else {
                        // Lite
                        log(LogLevel::INFO, "ICE Lite mode => skipping local checks, waiting for remote side to check.");
                        transition_to_state(IceConnectionState::Connected);
                    }

                    if (current_state_==IceConnectionState::Connected || current_state_==IceConnectionState::Completed) {
                        // Keep-alive
                        if (mode_==IceMode::Full) {
                            asio::co_spawn(strand_, perform_consent_freshness(), asio::detached);
                        }
                        // TURN refresh
                        if (turn_client_ && turn_client_->is_allocated()) {
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
        session_id_ = generate_random_string(12);
        local_ice_attributes_ = generate_ice_attributes();
        check_list_.clear();
        nominated_pair_ = CandidatePair();
        transition_to_state(IceConnectionState::New);

        if (signaling_client_) {
            asio::co_spawn(strand_,
                [this, self=shared_from_this()]() -> asio::awaitable<void> {
                    remote_candidates_.clear();
                    local_candidates_.clear();
                    co_await gather_candidates();

                    std::string sdp = signaling_client_->create_sdp(local_ice_attributes_, local_candidates_);
                    co_await signaling_client_->send_sdp(sdp);

                    if (mode_==IceMode::Full) {
                        transition_to_state(IceConnectionState::Checking);
                        co_await perform_connectivity_checks();
                    } else {
                        transition_to_state(IceConnectionState::Connected);
                    }
                    co_return;
                }, asio::detached
            );
        }
    }

    // 데이터 전송
    void send_data(const std::vector<uint8_t>& data) {
        if (current_state_!=IceConnectionState::Connected && current_state_!=IceConnectionState::Completed) {
            log(LogLevel::WARNING,"send_data() => not connected");
            return;
        }
        socket_.async_send_to(asio::buffer(data),
                              nominated_pair_.remote_candidate.endpoint,
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
    std::string turn_server_;
    std::string turn_username_;
    std::string turn_password_;
    std::atomic<IceConnectionState> current_state_;
    LogLevel log_level_;

    std::vector<Candidate> local_candidates_;
    std::vector<Candidate> remote_candidates_;
    std::vector<CheckListEntry> check_list_;

    std::vector<std::shared_ptr<StunClient>> stun_clients_;
    std::shared_ptr<TurnClient> turn_client_;
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

    // 세션 식별 (ICE Credential 경합 방지용)
    std::string session_id_;

    // ---------- 내부 함수들 ----------
    bool transition_to_state(IceConnectionState new_state) {
        if (current_state_==new_state) return false;
        current_state_ = new_state;
        if (state_callback_) {
            state_callback_(new_state);
        }
        log(LogLevel::INFO, "ICE State => " + std::to_string((int)new_state));
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
        if (mode_==IceMode::Lite) {
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
            c.foundation="host";
            c.transport="UDP";
            c.component_id=1;
            c.priority = calculate_priority(c);
            local_candidates_.push_back(c);
            if (candidate_callback_) {
                candidate_callback_(c);
            }
        };
        for (auto& r: results4) add_candidate(r.endpoint());
        for (auto& r: results6) add_candidate(r.endpoint());
        co_return;
    }

    asio::awaitable<void> gather_srflx_candidates() {
        for (auto& sc : stun_clients_) {
            try {
                auto mapped = co_await sc->send_binding_request();
                Candidate c;
                c.endpoint=mapped;
                c.type=CandidateType::ServerReflexive;
                c.foundation="srflx";
                c.transport="UDP";
                c.component_id=1;
                c.priority=calculate_priority(c);
                local_candidates_.push_back(c);
                if (candidate_callback_){
                    candidate_callback_(c);
                }
            } catch(...) {}
        }
        co_return;
    }

    asio::awaitable<void> gather_relay_candidates() {
        if (turn_client_) {
            try {
                auto relay_ep = co_await turn_client_->allocate_relay();
                Candidate c;
                c.endpoint=relay_ep;
                c.type=CandidateType::Relay;
                c.foundation="relay";
                c.transport="UDP";
                c.component_id=1;
                c.priority=calculate_priority(c);
                local_candidates_.push_back(c);
                if (candidate_callback_){
                    candidate_callback_(c);
                }
            } catch(...) {}
        }
        co_return;
    }

    // ConnCheck
    asio::awaitable<void> perform_connectivity_checks() {
        // Pair 생성
        check_list_.clear();
        for (auto& rc : remote_candidates_) {
            for (auto& lc : local_candidates_) {
                if (lc.component_id==rc.component_id) {
                    CandidatePair cp(lc, rc);
                    cp.priority = calculate_priority_pair(lc,rc);
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
                tasks.push_back([this, i]() -> asio::awaitable<void>{
                    CheckListEntry& entry = check_list_[i];
                    
                    if (entry.state==CandidatePairState::New || entry.state==CandidatePairState::Failed) {
                        entry.state=CandidatePairState::InProgress;
                        co_await perform_single_connectivity_check(entry);
                    } else {
                        break;
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
        bool is_relay = (pair.remote_candidate.type==CandidateType::Relay);

        // STUN Binding Request
        StunMessage req(StunMessageType::BINDING_REQUEST, StunMessage::generate_transaction_id());
        // priority
        req.add_attribute(StunAttributeType::PRIORITY, serialize_uint32(pair.local_candidate.priority));
        // username => remoteUfrag:localUfrag
        std::string uname = remote_ice_attributes_.ufrag + ":" + local_ice_attributes_.ufrag;
        req.add_attribute(StunAttributeType::USERNAME, uname);
        // role
        if (role_==IceRole::Controller) {
            req.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
        } else {
            req.add_attribute(StunAttributeType::ICE_CONTROLLED, serialize_uint64(local_ice_attributes_.tie_breaker));
        }
        // message integrity(송신자는 remote pwd)
        req.add_message_integrity(remote_ice_attributes_.pwd);
        req.add_fingerprint();

        asio::ip::udp::endpoint dest = pair.remote_candidate.endpoint;

        bool success = false;
        try {
            if (is_relay && turn_client_) {
                // TURN 통해 전송
                success = co_await turn_client_->send_stun_request_with_retransmit(req, remote_ice_attributes_.pwd, dest);
            } else {
                success = co_await send_stun_request_with_retransmit(req, remote_ice_attributes_.pwd, dest,
                                                                     std::chrono::milliseconds(500),
                                                                     7);
            }
        } catch(...) { success=false; }

        if (success) {
            entry.state=CandidatePairState::Succeeded;
        } else {
            entry.state=CandidatePairState::Failed;
        }
        co_return;
    }

    // STUN 재전송
    asio::awaitable<bool> send_stun_request_with_retransmit(const StunMessage& request,
                                                            const std::string& remote_pwd,
                                                            const asio::ip::udp::endpoint& dest,
                                                            std::chrono::milliseconds initial_timeout,
                                                            int max_tries)
    {
        auto data = request.serialize();
        auto txn_id = request.get_transaction_id();

        std::chrono::milliseconds timeout=initial_timeout;
        for (int attempt=0; attempt<max_tries; ++attempt) {
            co_await socket_.async_send_to(asio::buffer(data), dest, asio::use_awaitable);

            // Timeout or receive
            asio::steady_timer timer(strand_);
            timer.expires_after(timeout);
            std::vector<uint8_t> buf(2048);
            asio::ip::udp::endpoint sender;
            auto [ec, bytes] = co_await(
                socket_.async_receive_from(asio::buffer(buf), sender, asio::use_awaitable)
                || timer.async_wait(asio::use_awaitable)
            );
            if (!ec && bytes>0) {
                buf.resize(bytes);
                try {
                    StunMessage resp = StunMessage::parse(buf);
                    if (resp.get_transaction_id()==txn_id
                        && resp.get_type()==StunMessageType::BINDING_RESPONSE_SUCCESS) {
                        // 검증(로컬 pwd)
                        if (!resp.verify_message_integrity(local_ice_attributes_.pwd)) {
                            co_return false;
                        }
                        if (!resp.verify_fingerprint()) {
                            co_return false;
                        }
                        co_return true;
                    }
                } catch(...) {
                }
            }
            // backoff
            timeout = std::min(timeout*2, std::chrono::milliseconds(1600));
        }

        co_return false;
    }

    asio::awaitable<void> evaluate_connectivity_results() {
        bool any_success=false;
        for (auto& e: check_list_) {
            if (e.state==CandidatePairState::Succeeded && !e.is_nominated) {
                co_await nominate_pair(e);
                any_success=true;
                break;
            }
        }
        if (!any_success) {
            transition_to_state(IceConnectionState::Failed);
        } else {
            transition_to_state(IceConnectionState::Connected);
        }
        co_return;
    }

    // Nomination
    asio::awaitable<void> nominate_pair(CheckListEntry& entry) {
        entry.is_nominated=true;
        nominated_pair_ = entry.pair;

        if (role_==IceRole::Controller) {
            // Binding Indication w/ USE-CANDIDATE
            StunMessage ind(StunMessageType::BINDING_INDICATION, StunMessage::generate_transaction_id());
            ind.add_attribute(StunAttributeType::USE_CANDIDATE, {});
            ind.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
            ind.add_message_integrity(remote_ice_attributes_.pwd);
            ind.add_fingerprint();

            co_await socket_.async_send_to(asio::buffer(ind.serialize()),
                                           entry.pair.remote_candidate.endpoint,
                                           asio::use_awaitable);
            if (nominate_callback_) {
                nominate_callback_(entry.pair);
            }
        } else {
            // Controlled
            if (nominate_callback_) {
                nominate_callback_(entry.pair);
            }
            transition_to_state(IceConnectionState::Completed);
        }
        co_return;
    }
	
    // Consent Freshness
    asio::awaitable<void> perform_consent_freshness() {
        while (current_state_==IceConnectionState::Connected
            || current_state_==IceConnectionState::Completed) 
        {
            asio::steady_timer t(strand_);
            t.expires_after(std::chrono::seconds(15));
            co_await t.async_wait(asio::use_awaitable);
            if (!co_await send_consent_binding_request()) {
                transition_to_state(IceConnectionState::Failed);
                co_return;
            }
        }
        co_return;
    }

    asio::awaitable<bool> send_consent_binding_request() {
        if (nominated_pair_.remote_candidate.endpoint.address().is_unspecified()) {
            co_return false;
        }
        // BINDING_REQUEST
        StunMessage req(StunMessageType::BINDING_REQUEST, StunMessage::generate_transaction_id());
        req.add_attribute(StunAttributeType::USERNAME, remote_ice_attributes_.ufrag + ":" + local_ice_attributes_.ufrag);
        if (role_==IceRole::Controller) {
            req.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
        } else {
            req.add_attribute(StunAttributeType::ICE_CONTROLLED, serialize_uint64(local_ice_attributes_.tie_breaker));
        }
        req.add_message_integrity(remote_ice_attributes_.pwd);
        req.add_fingerprint();

        bool ok = co_await send_stun_request_with_retransmit(
            req, remote_ice_attributes_.pwd,
            nominated_pair_.remote_candidate.endpoint,
            std::chrono::milliseconds(500),
            5
        );
        co_return ok;
    }

    // TURN refresh
    asio::awaitable<void> perform_turn_refresh() {
        while (current_state_==IceConnectionState::Connected && turn_client_ && turn_client_->is_allocated()) {
            asio::steady_timer timer(strand_);
            timer.expires_after(std::chrono::seconds(300));
            co_await timer.async_wait(asio::use_awaitable);
            try {
                co_await turn_client_->refresh_allocation();
            } catch(...) {
                transition_to_state(IceConnectionState::Failed);
            }
        }
        co_return;
    }

    // 데이터 수신
    asio::awaitable<void> start_data_receive() {
        while (current_state_==IceConnectionState::Connected
            || current_state_==IceConnectionState::Completed)
        {
            std::vector<uint8_t> buf(2048);
            asio::ip::udp::endpoint sender;
            size_t bytes=0;
            try {
                bytes = co_await socket_.async_receive_from(asio::buffer(buf), sender, asio::use_awaitable);
            } catch(...) {
                transition_to_state(IceConnectionState::Failed);
                break;
            }
            if (bytes>0) {
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
        if (delim==std::string::npos) co_return;
        std::string rcv_ufrag = uname.substr(0, delim);
        std::string snd_ufrag = uname.substr(delim+1);

        // 우리가 수신자 => rcv_ufrag == local_ice_attributes_.ufrag
        if (rcv_ufrag!=local_ice_attributes_.ufrag) co_return;

        // 무결성 => local pwd로 검증
        if (!req.verify_message_integrity(local_ice_attributes_.pwd)) {
            co_return;
        }
        if (!req.verify_fingerprint()) {
            co_return;
        }

        // PeerReflexive Candidate 생성 가능
        Candidate prflx;
        prflx.type=CandidateType::PeerReflexive;
        prflx.endpoint=sender;
        prflx.component_id=1; 
        prflx.foundation="prflx";
        prflx.transport="UDP";
        prflx.priority=(110<<24);

        // check list에 페어 없으면 추가 ...
        bool found_pair=false;
        for (auto& e: check_list_) {
            if (e.pair.remote_candidate.endpoint==sender) {
                found_pair=true;
                break;
            }
        }
        if (!found_pair && !sender.address().is_unspecified()) {
            // local candidate 선택
            Candidate local_cand;
            // 임시로 첫 host candidate 사용 (실제론 family·component matching)
            if (!local_candidates_.empty()) {
                local_cand= local_candidates_[0];
            }
            CandidatePair newp(local_cand, prflx);
            newp.priority = calculate_priority_pair(local_cand, prflx);
            check_list_.emplace_back(newp);
        }

        // BINDING RESPONSE
        StunMessage resp(StunMessageType::BINDING_RESPONSE_SUCCESS, req.get_transaction_id());
        resp.add_message_integrity(remote_ice_attributes_.pwd);
        resp.add_fingerprint();

        co_await socket_.async_send_to(asio::buffer(resp.serialize()), sender, asio::use_awaitable);

        co_return;
    }

    // Binding Indication => USE-CANDIDATE
    asio::awaitable<void> handle_binding_indication(const StunMessage& ind, const asio::ip::udp::endpoint& sender) {
        if (ind.has_attribute(StunAttributeType::USE_CANDIDATE)) {
            // 첫 Succeeded & 미지명 Pair nominate
            for (auto& e: check_list_) {
                if (e.state==CandidatePairState::Succeeded && !e.is_nominated) {
                    co_await nominate_pair(e);
                    break;
                }
            }
        }
        co_return;
    }

    // 신호 메시지 받기
    asio::awaitable<void> handle_incoming_signaling_messages() {
        while (current_state_!=IceConnectionState::Failed && current_state_!=IceConnectionState::Completed) {
            try {
                std::string sdp = co_await signaling_client_->receive_sdp();
                auto [rattr, rcands] = signaling_client_->parse_sdp(sdp);
                remote_ice_attributes_ = rattr;
                negotiate_role(rattr.tie_breaker);

                if (mode_==IceMode::Lite && role_==IceRole::Controller) {
                    log(LogLevel::ERROR, "Lite agent cannot be Controller => fail");
                    transition_to_state(IceConnectionState::Failed);
                    co_return;
                }

                if (rattr.role==IceRole::Controller && role_==IceRole::Controller) {
                    log(LogLevel::ERROR, "Both sides are Controller => fail");
                    transition_to_state(IceConnectionState::Failed);
                    co_return;
                }

                co_await add_remote_candidate(rcands);
            } catch(...) {
                transition_to_state(IceConnectionState::Failed);
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
        }
        if (mode_==IceMode::Full) {
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
        log(LogLevel::INFO, "Negotiated role => " + std::to_string((int)role_));
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
        uint32_t comp = (uint32_t)c.component_id;
        return (type_pref<<24) | (local_pref<<8) | (256-comp);
    }

    uint64_t calculate_priority_pair(const Candidate& l, const Candidate& r) const {
        uint32_t g = std::max(l.priority, r.priority);
        uint32_t d = std::min(l.priority, r.priority);
        // (g<<32) + d*2 + (l>r?1:0)
        return ((uint64_t)g<<32) + (d*2) + ((l.priority>r.priority)?1:0);
    }

    void sort_candidate_pairs() {
        std::sort(check_list_.begin(), check_list_.end(), [&](auto& a, auto& b){
            return a.pair.priority> b.pair.priority;
        });
    }

    // 로깅
    void log(LogLevel lvl, const std::string& msg) {
        if (lvl<log_level_) return;
        std::cout << "[IceAgent]["<<(int)lvl<<"] " << msg << std::endl;
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

    // 직렬화 uint64
    std::vector<uint8_t> serialize_uint64(uint64_t val) {
        std::vector<uint8_t> out(8);
        for(int i=0;i<8;++i){
            out[7-i]=(val&0xFF);
            val>>=8;
        }
        return out;
    }

}; // class IceAgent
