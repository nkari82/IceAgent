#pragma once
#include <algorithm>
#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <atomic>
#include <bitset>
#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "stun_message.hpp"

// -------------------- ENUMS / STRUCTS --------------------
enum class IceMode { Full, Lite };

enum class IceRole { Controller, Controlled };

enum class IceOption { None = 1 << 0, IceLite = 1 << 1, Ice2 = 1 << 2, Trickle = 1 << 3 };

enum class IceConnectionState {
    New,        // 어떤 액션이 취해지기 전의 초기 상태입니다.
    Gathering,  // 지역 후보자를 수집합니다.
    Checking,   // 로컬 후보와 원격 후보 간의 연결성 검사를 수행합니다.
    Connected,  // 하나 이상의 후보 쌍이 성공했지만 검사가 아직 진행 중일 수 있습니다.
    Completed,  // 모든 후보 쌍이 확인되었으며 하나 이상의 쌍이 성공했습니다.
    Failed,     // 유효한 후보 쌍을 설정할 수 없습니다.
    Disconnected,  // 이전에 연결되었던 경로가 끊어진 상태로, 재시도를 통해 복구를 시도할 수 있습니다.
    Closed  // ICE 프로세스가 완전히 종료되어 더 이상 동작하지 않는 상태입니다.
};

enum class LogLevel { Debug = 0, Info, Warning, Error };

enum class CandidateType { Host, PeerReflexive, ServerReflexive, Relay };

enum class Transport {
    Unknown,  // 알 수 없는 전송 프로토콜
    UDP,      // User Datagram Protocol
    TCP,      // Transmission Control Protocol
    TLS       // Transport Layer Security
};

// Candidate Structure
struct Candidate {
    asio::ip::udp::endpoint endpoint;
    CandidateType type;
    uint32_t priority;
    uint32_t component_id;
    Transport transport;
    std::string foundation;

    Candidate(const asio::ip::udp::endpoint &ep, CandidateType type, uint32_t comp_id = 1,
              Transport tp = Transport::UDP, const std::string &fnd = "")
        : endpoint(ep), type(type), component_id(comp_id), transport(tp) {
        // RFC 8445 Section 5.7.1에 따른 후보자 우선순위 계산
        uint32_t type_pref = 0;
        switch (type) {
            case CandidateType::Host:
                foundation = fnd.empty() ? "host" : fnd;
                type_pref = 126;
                break;
            case CandidateType::PeerReflexive:
                foundation = fnd.empty() ? "prflx" : fnd;
                type_pref = 110;
                break;
            case CandidateType::ServerReflexive:
                foundation = fnd.empty() ? "srflx" : fnd;
                type_pref = 100;
                break;
            case CandidateType::Relay:
                foundation = fnd.empty() ? "relay" : fnd;
                type_pref = 0;
                break;
        }
        uint32_t local_pref = 65535;
        priority = (type_pref << 24) | (local_pref << 8) | (256 - component_id);
    }

    // SDP 형식으로 변환
    std::string to_sdp() const {
        std::ostringstream oss;
        oss << "a=candidate:" << foundation << " " << component_id << " " << transport_to_string(transport) << " "
            << priority << " " << endpoint.address().to_string() << " " << endpoint.port() << " typ ";
        switch (type) {
            case CandidateType::Host:
                oss << "host";
                break;
            case CandidateType::PeerReflexive:
                oss << "prflx";
                break;
            case CandidateType::ServerReflexive:
                oss << "srflx";
                break;
            case CandidateType::Relay:
                oss << "relay";
                break;
        }
        return oss.str();
    }

    static std::optional<Candidate> from_sdp(const std::string &sdp_line) {
        std::istringstream iss(sdp_line);
        std::string prefix;
        iss >> prefix;  // "a=candidate:..."
        size_t colon = prefix.find(':');
        if (colon == std::string::npos || prefix.substr(0, colon) != "a=candidate") {
            return std::nullopt;  // 잘못된 candidate 라인
        }
        if (colon + 1 >= prefix.size())
            return std::nullopt;  // foundation 누락

        std::string foundation = prefix.substr(colon + 1);
        asio::ip::udp::endpoint endpoint;
        CandidateType type;
        uint32_t component_id, transport, priority;
        iss >> component_id;
        iss >> transport;
        iss >> priority;
        std::string ip;
        uint16_t port;
        iss >> ip >> port;
        try {
            endpoint = asio::ip::udp::endpoint(asio::ip::make_address(ip), port);
        } catch (const std::exception &) {
            return std::nullopt;  // 잘못된 IP 주소
        }

        std::string typ;
        iss >> typ;  // "typ"
        if (typ != "typ")
            return std::nullopt;  // 예상되는 "typ" 키워드
        std::string type_str;

        iss >> type_str;
        switch (type_str[0]) {
            case 'h':
                type = CandidateType::Host;
                break;
            case 'p':
                type = CandidateType::PeerReflexive;
                break;
            case 's':
                type = CandidateType::ServerReflexive;
                break;
            case 'r':
                type = CandidateType::Relay;
                break;
            default:
                return std::nullopt;  // 알 수 없는 candidate 타입
        }
        return Candidate(endpoint, type, component_id, (Transport)transport, foundation);
    }

    static std::string transport_to_string(Transport tp) {
        switch (tp) {
            case Transport::UDP:
                return "UDP";
            case Transport::TCP:
                return "TCP";
            case Transport::TLS:
                return "TLS";
            default:
                return "Unknown";
        }
    }

    static std::string type_to_string(CandidateType type) {
        switch (type) {
            case CandidateType::Host:
                return "host";
            case CandidateType::PeerReflexive:
                return "prflx";
            case CandidateType::ServerReflexive:
                return "srflx";
            case CandidateType::Relay:
                return "relay";
            default:
                return "unknown";
        }
    }

    bool operator==(const Candidate &other) const {
        return endpoint == other.endpoint && type == other.type && foundation == other.foundation &&
               priority == other.priority && transport == other.transport && component_id == other.component_id;
    }

    bool operator!=(const Candidate &other) const { return !(*this == other); }

    operator std::string() const { return to_sdp(); }
};

struct CandidatePair {
    Candidate local_candidate;
    Candidate remote_candidate;
    uint64_t priority;
    CandidatePair() = default;
    CandidatePair(const Candidate &l, const Candidate &r) : local_candidate(l), remote_candidate(r), priority(0) {}
};

enum class CandidatePairState { New, InProgress, Failed, Succeeded, Nominated };

struct CheckListEntry {
    CandidatePair pair;
    CandidatePairState state;
    bool is_nominated;

    CheckListEntry(const CandidatePair &cp) : pair(cp), state(CandidatePairState::New), is_nominated(false) {}
};

// Callbacks
using StateCallback = std::function<void(IceConnectionState)>;
using CandidateCallback = std::function<void(const Candidate &)>;
using DataCallback = std::function<void(const std::vector<uint8_t> &, const asio::ip::udp::endpoint &)>;
using NominateCallback = std::function<void(const CandidatePair &)>;

// ICE Attributes
struct IceAttributes {
    std::string ufrag;  // ICE의 ufrag는 상대방과의 연결을 식별하기 위해 사용됩니다.
    std::string pwd;  // 메시지 무결성과 인증(예: STUN 메시지의 MESSAGE-INTEGRITY 계산)에 사용됩니다.
    IceRole role;
    uint32_t options;
    uint64_t tie_breaker;

    void add_option(IceOption option) { options |= static_cast<uint32_t>(option); }

    bool has_option(IceOption option) const { return (options & static_cast<uint32_t>(option)) != 0; }
};

// -------------------- ICE AGENT --------------------
class IceAgent : public std::enable_shared_from_this<IceAgent> {
   public:
    // 수정된 생성자: 시그널링 서버 주소 및 포트 추가
    IceAgent(asio::io_context &io_context, IceRole role, IceMode mode, const std::vector<std::string> &stun_servers,
             const std::vector<std::string> &turn_servers,  // Changed to vector
             const std::string &turn_username = "", const std::string &turn_password = "",
             const std::string &signaling_server_address = "", unsigned short signaling_server_port = 0)
        : io_context_(io_context),
          strand_(io_context.get_executor()),
          udp_socket_(strand_),
          tcp_socket_(strand_),
          mode_(mode),
          stun_servers_(stun_servers),
          turn_servers_(turn_servers),
          turn_username_(turn_username),
          turn_password_(turn_password),
          signaling_server_address_(signaling_server_address),
          signaling_server_port_(signaling_server_port),
          current_state_(IceConnectionState::New),
          log_level_(LogLevel::Info) {
        // Generate random ICE credentials
        local_ice_attributes_ = generate_ice_attributes();
        local_ice_attributes_.role = role;

        // Resolve STUN servers and store endpoints
        asio::ip::udp::resolver resolver(io_context);
        for (const auto &s : stun_servers_) {
            size_t pos = s.find(':');
            if (pos != std::string::npos) {
                std::string host = s.substr(0, pos);
                std::string port_str = s.substr(pos + 1);
                try {
                    auto results = resolver.resolve(asio::ip::udp::v4(), host, port_str);
                    for (const auto &r : results) {
                        stun_endpoints_.push_back(r.endpoint());
                        log(LogLevel::Debug, "Resolved STUN server: " + r.endpoint().address().to_string() + ":" +
                                                 std::to_string(r.endpoint().port()));
                    }
                } catch (const std::exception &ex) {
                    log(LogLevel::Warning, "Failed to resolve STUN server '" + s + "': " + ex.what());
                }
            }
        }

        // Resolve TURN servers and store endpoints
        for (const auto &s : turn_servers_) {
            size_t pos = s.find(':');
            if (pos != std::string::npos) {
                std::string host = s.substr(0, pos);
                std::string port_str = s.substr(pos + 1);
                try {
                    asio::ip::udp::resolver resolver_turn(io_context);
                    auto results = resolver_turn.resolve(asio::ip::udp::v4(), host, port_str);
                    for (const auto &r : results) {
                        turn_endpoints_.push_back(r.endpoint());
                        log(LogLevel::Debug, "Resolved TURN server: " + r.endpoint().address().to_string() + ":" +
                                                 std::to_string(r.endpoint().port()));
                    }
                } catch (const std::exception &ex) {
                    log(LogLevel::Warning, "Failed to resolve TURN server '" + s + "': " + ex.what());
                }
            }
        }

        // Initialize TURN allocation endpoint (initially unset)
        relay_endpoint_ = asio::ip::udp::endpoint();

        // Open UDP socket (dual-stack)
        std::error_code ec;
        udp_socket_.open(asio::ip::udp::v6(), ec);
        if (!ec) {
            asio::ip::v6_only opt(false);
            udp_socket_.set_option(opt, ec);
        }
        if (ec) {
            // Fallback to IPv4 if IPv6 fails
            udp_socket_.open(asio::ip::udp::v4(), ec);
        }
        if (!ec) {
            udp_socket_.bind(asio::ip::udp::endpoint(udp_socket_.local_endpoint().protocol(), 0), ec);
            if (!ec) {
                log(LogLevel::Debug, "UDP Socket bound to " + udp_socket_.local_endpoint().address().to_string() + ":" +
                                         std::to_string(udp_socket_.local_endpoint().port()));
            }
        }
        if (ec) {
            log(LogLevel::Error, "Failed to bind UDP socket: " + ec.message());
            transition_to_state(IceConnectionState::Failed);
        }

        // Initialize TCP components for signaling server
        if (!signaling_server_address_.empty() && signaling_server_port_ != 0) {
            asio::ip::tcp::resolver tcp_resolver(io_context);
            try {
                auto results = tcp_resolver.resolve(signaling_server_address_, std::to_string(signaling_server_port_));
                asio::async_connect(
                    tcp_socket_, results,
                    asio::bind_executor(
                        strand_, [this](const std::error_code &ec, const asio::ip::tcp::endpoint & /*endpoint*/) {
                            if (!ec) {
                                log(LogLevel::Debug, "Connected to signaling server.");
                                start_signaling_communication();
                            } else {
                                log(LogLevel::Error, "Failed to connect to signaling server: " + ec.message());
                                transition_to_state(IceConnectionState::Failed);
                            }
                        }));
            } catch (const std::exception &ex) {
                log(LogLevel::Error, "Exception resolving signaling server: " + std::string(ex.what()));
                transition_to_state(IceConnectionState::Failed);
            }
        }
    }

    ~IceAgent() {
        std::error_code ec;
        udp_socket_.close(ec);
        tcp_socket_.close(ec);
    }

    // Set Callbacks
    void set_on_state_change_callback(StateCallback cb) { state_callback_ = std::move(cb); }
    void set_candidate_callback(CandidateCallback cb) { candidate_callback_ = std::move(cb); }
    void set_data_callback(DataCallback cb) { data_callback_ = std::move(cb); }
    void set_nominate_callback(NominateCallback cb) { nominate_callback_ = std::move(cb); }

    // Set Log Level
    void set_log_level(LogLevel level) { log_level_ = level; }

    // Start ICE Process
    void start() {
        if (current_state_ != IceConnectionState::New) {
            log(LogLevel::Warning, "ICE is already started");
            return;
        }

        asio::co_spawn(
            strand_,
            [this, self = shared_from_this()]() -> asio::awaitable<void> {
                try {
                    // 상태 초기화
                    nominated_pair_ = std::nullopt;

                    check_list_.clear();
                    remote_candidates_.clear();
                    local_candidates_.clear();
                    relay_endpoint_ = asio::ip::udp::endpoint();

                    // 후보자 수집
                    co_await gather_candidates();

                    // 수집된 후보자를 시그널링을 통해 전송
                    if (signaling_server_connected_) {
                        std::string sdp = create_sdp();
                        co_await send_sdp(sdp);

                        // 수신 시그널링 메시지 처리
                        asio::co_spawn(strand_, handle_incoming_signaling_messages(), asio::detached);
                    } else {
                        if (mode_ == IceMode::Full) {
                            co_await perform_connectivity_checks();
                        } else {
                            // Lite 모드: 로컬 검사를 건너뜀
                            log(LogLevel::Info,
                                "ICE Lite mode => skipping local checks, waiting for remote side to check.");
                            transition_to_state(IceConnectionState::Connected);
                        }

                        if (current_state_ == IceConnectionState::Connected ||
                            current_state_ == IceConnectionState::Completed) {
                            // Full ICE 모드의 경우, 동의 갱신 시작
                            if (mode_ == IceMode::Full) {
                                asio::co_spawn(strand_, perform_consent_freshness(), asio::detached);
                            }
                            // 할당된 TURN 릴레이가 있는 경우, 주기적인 갱신 시작
                            if (!relay_endpoint_.address().is_unspecified()) {
                                asio::co_spawn(strand_, perform_turn_refresh(), asio::detached);
                            }
                            // 데이터 수신 시작
                            asio::co_spawn(strand_, start_data_receive(), asio::detached);
                        }
                    }
                } catch (const std::exception &ex) {
                    log(LogLevel::Error, std::string("start() exception: ") + ex.what());
                    transition_to_state(IceConnectionState::Failed);
                }
            },
            asio::detached);
    }

    // Restart ICE Process
    void restart_ice() {
        log(LogLevel::Info, "Restarting ICE...");
        transition_to_state(IceConnectionState::New);
        start();
    }

    // Send Data
    void send_data(const std::vector<uint8_t> &data) {
        if (current_state_ != IceConnectionState::Connected && current_state_ != IceConnectionState::Completed) {
            log(LogLevel::Warning, "send_data() => not connected");
            return;
        }
        const auto &pair = nominated_pair_.value();
        asio::ip::udp::endpoint target = pair.remote_candidate.endpoint;

        // If relay is allocated and the nominated pair uses relay, use relay endpoint
        if (pair.remote_candidate.type == CandidateType::Relay && !relay_endpoint_.address().is_unspecified()) {
            target = relay_endpoint_;
        }

        udp_socket_.async_send_to(asio::buffer(data), target, [this](std::error_code ec, std::size_t) {
            if (ec) {
                log(LogLevel::Error, "send_data failed: " + ec.message());
            }
        });
    }

   private:
    // Members
    asio::io_context &io_context_;
    asio::strand<asio::io_context::executor_type> strand_;
    asio::ip::udp::socket udp_socket_;
    asio::ip::tcp::socket tcp_socket_;  // TCP socket for signaling
    IceMode mode_;
    std::vector<std::string> stun_servers_;
    std::vector<asio::ip::udp::endpoint> stun_endpoints_;  // Resolved STUN server endpoints
    std::vector<std::string> turn_servers_;                // List of TURN servers
    std::string turn_username_;
    std::string turn_password_;
    std::vector<asio::ip::udp::endpoint> turn_endpoints_;  // Resolved TURN server endpoints
    std::atomic<IceConnectionState> current_state_;
    LogLevel log_level_;

    // TURN 서버로부터 받은 REALM과 NONCE를 저장
    std::string turn_realm_;
    std::string turn_nonce_;

    std::vector<Candidate> local_candidates_;
    std::vector<Candidate> remote_candidates_;
    std::vector<CheckListEntry> check_list_;
    std::atomic<bool> connectivity_check_in_progress_{false};  // 중복 호출 방지 변수

    asio::ip::udp::endpoint relay_endpoint_;  // Allocated relay endpoint

    // 시그널링 서버 관련 멤버 변수
    std::string signaling_server_address_;
    unsigned short signaling_server_port_;
    bool signaling_server_connected_ = false;
    asio::streambuf signaling_buffer_;

    StateCallback state_callback_;
    CandidateCallback candidate_callback_;
    DataCallback data_callback_;
    NominateCallback nominate_callback_;

    std::optional<CandidatePair> nominated_pair_;

    // ICE Attributes
    IceAttributes local_ice_attributes_;
    IceAttributes remote_ice_attributes_;

    // ---------- Internal Functions ----------

    // Transition to a new state
    bool transition_to_state(IceConnectionState new_state) {
        if (current_state_ == new_state)
            return false;
        current_state_ = new_state;
        if (state_callback_) {
            state_callback_(new_state);
        }
        log(LogLevel::Info, "ICE State => " + ice_state_to_string(new_state));
        return true;
    }

    // Convert IceConnectionState to string for logging
    std::string ice_state_to_string(IceConnectionState state) const {
        switch (state) {
            case IceConnectionState::New:
                return "New";
            case IceConnectionState::Gathering:
                return "Gathering";
            case IceConnectionState::Checking:
                return "Checking";
            case IceConnectionState::Connected:
                return "Connected";
            case IceConnectionState::Completed:
                return "Completed";
            case IceConnectionState::Failed:
                return "Failed";
            default:
                return "Unknown";
        }
    }

    // Generate random ICE attributes
    IceAttributes generate_ice_attributes() {
        IceAttributes attrs;
        attrs.tie_breaker = generate_random_uint64();
        attrs.ufrag = generate_random_string(8);
        attrs.pwd = generate_random_string(24);
        if (mode_ == IceMode::Lite) {
            attrs.add_option(IceOption::IceLite);
        } else {
            attrs.add_option(IceOption::Ice2);
            attrs.add_option(IceOption::Trickle);
        }
        return attrs;
    }

    // Gather all candidates
    asio::awaitable<void> gather_candidates() {
        if (!transition_to_state(IceConnectionState::Gathering))
            co_return;
        co_await gather_local_candidates();
        co_await gather_srflx_candidates();
        co_await gather_relay_candidates();
    }

    // Gather local host candidates
    asio::awaitable<void> gather_local_candidates() {
        asio::ip::udp::resolver resolver(strand_);
        auto results4 = co_await resolver.async_resolve(asio::ip::udp::v4(), "0.0.0.0", "0", asio::use_awaitable);
        auto results6 = co_await resolver.async_resolve(asio::ip::udp::v6(), "::", "0", asio::use_awaitable);

        auto add_candidate = [&](const asio::ip::udp::endpoint &ep) {
            const auto &c = local_candidates_.emplace_back((ep, CandidateType::Host));
            if (candidate_callback_) {
                candidate_callback_(c);
            }
            log(LogLevel::Debug, "Gathered local candidate: " + c.to_sdp());
        };
        for (auto &r : results4) add_candidate(r.endpoint());
        for (auto &r : results6) add_candidate(r.endpoint());
    }

    // STUN을 통한 서버 반사형 후보자 수집
    asio::awaitable<void> gather_srflx_candidates() {
        for (const auto &stun_ep : stun_endpoints_) {  // 해상된 STUN 엔드포인트 순회
            try {
                // 메시지 무결성 없이 바인딩 요청 STUN 메시지 생성
                StunMessage req(StunMessageType::BINDING_REQUEST, StunMessage::generate_transaction_id());
                req.add_fingerprint();

                // STUN 요청 전송 및 응답 대기
                auto resp_opt = co_await send_stun_request(stun_ep, req);
                if (resp_opt.has_value()) {
                    StunMessage resp = resp_opt.value();
                    // 응답에서 매핑된 주소 추출
                    auto mapped_opt = resp.get_mapped_address();  // 필요에 따라 구현
                    if (mapped_opt.has_value()) {
                        const auto &c =
                            local_candidates_.emplace_back((mapped_opt.value(), CandidateType::ServerReflexive));
                        if (candidate_callback_) {
                            candidate_callback_(c);
                        }
                        log(LogLevel::Debug, "Gathered SRFLX candidate: " + c.to_sdp());
                    }
                }
            } catch (const std::exception &ex) {
                log(LogLevel::Warning, "Failed to gather SRFLX candidate from " + stun_ep.address().to_string() + ":" +
                                           std::to_string(stun_ep.port()) + " | " + ex.what());
            }
        }
    }

    // Gather relay candidates via TURN
    asio::awaitable<void> gather_relay_candidates() {
        // Handle TURN allocation if TURN servers are available
        if (!turn_endpoints_.empty()) {
            co_await allocate_turn_relay();
        }
    }

    // 연결성 검사 수행
    asio::awaitable<void> perform_connectivity_checks() {
        if (connectivity_check_in_progress_.exchange(true)) {
            co_return;  // 이미 실행 중이면 종료
        }

        check_list_.clear();
        for (auto &rc : remote_candidates_) {
            for (auto &lc : local_candidates_) {
                if (lc.component_id == rc.component_id) {
                    CandidatePair cp(lc, rc);
                    cp.priority = calculate_priority_pair(lc, rc);
                    check_list_.emplace_back(cp);
                }
            }
        }

        sort_candidate_pairs();

        size_t next_pair = 0;                 // 단순히 증가만 하므로 atomic 필요 없음
        std::atomic<size_t> active_tasks{0};  // 경합 방지를 위해 atomic 사용
        const size_t max_concurrency = 5;

        try {
            while (true) {
                bool progress = false;

                while (active_tasks < max_concurrency) {
                    if (next_pair >= check_list_.size()) {
                        break;
                    }

                    CheckListEntry &entry = check_list_[next_pair++];
                    if (entry.state == CandidatePairState::New || entry.state == CandidatePairState::Failed) {
                        entry.state = CandidatePairState::InProgress;
                        active_tasks.fetch_add(1, std::memory_order_relaxed);  // 작업 증가
                        progress = true;

                        asio::co_spawn(io_context_, perform_single_connectivity_check(entry),
                                       [&, index = next_pair - 1](std::exception_ptr eptr) {
                                           if (!eptr && check_list_[index].state == CandidatePairState::Succeeded) {
                                               transition_to_state(IceConnectionState::Connected);
                                           }
                                           active_tasks.fetch_sub(1, std::memory_order_relaxed);  // 작업 감소
                                       });
                    }
                }

                // 새 항목 추가 확인
                if (next_pair < check_list_.size()) {
                    progress = true;  // 새 항목이 추가되었으므로 다시 시도
                }

                if (!progress && active_tasks == 0) {
                    break;  // 더 이상 처리할 항목이 없고 활성 작업이 없으면 종료
                }

                co_await asio::steady_timer(co_await asio::this_coro::executor, std::chrono::milliseconds(10))
                    .async_wait();
            }

            // Evaluate connectivity results after checks
            bool any_success = false;
            for (auto &e : check_list_) {
                if (e.state == CandidatePairState::Succeeded && !e.is_nominated) {
                    if (co_await nominate_pair(e)) {
                        any_success = true;
                        break;
                    }
                }
            }
            if (any_success) {
                transition_to_state(IceConnectionState::Completed);
                log(LogLevel::Info, "ICE completed established.");

            } else {
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::Error, "All connectivity checks failed.");
            }
        } catch (...) {
            transition_to_state(IceConnectionState::Failed);
        }
        connectivity_check_in_progress_ = false;  // 실행 완료 표시
    }

    // Perform a single connectivity check
    asio::awaitable<void> perform_single_connectivity_check(CheckListEntry &entry) {
        const auto &pair = entry.pair;
        bool is_relay = (pair.remote_candidate.type == CandidateType::Relay);

        // Create STUN Binding Request using local ICE credentials
        StunMessage req(StunMessageType::BINDING_REQUEST, StunMessage::generate_transaction_id());
        // Add necessary attributes using local ICE credentials
        req.add_attribute(StunAttributeType::PRIORITY, serialize_uint32(pair.local_candidate.priority));
        std::string uname = local_ice_attributes_.ufrag;  // Use local ufrag only
        req.add_attribute(StunAttributeType::USERNAME, uname);
        if (local_ice_attributes_.role == IceRole::Controller) {
            req.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
        } else {
            req.add_attribute(StunAttributeType::ICE_CONTROLLED, serialize_uint64(local_ice_attributes_.tie_breaker));
        }
        req.add_message_integrity(local_ice_attributes_.pwd);  // Use local pwd
        req.add_fingerprint();

        asio::ip::udp::endpoint dest = pair.remote_candidate.endpoint;

        std::optional<StunMessage> resp_opt;
        try {
            if (is_relay && !relay_endpoint_.address().is_unspecified()) {
                // Send STUN request via TURN relay
                resp_opt = co_await send_stun_request(relay_endpoint_, req, remote_ice_attributes_.pwd);
            } else {
                // Send direct STUN request
                resp_opt = co_await send_stun_request(dest, req, remote_ice_attributes_.pwd);
            }

            if (resp_opt.has_value()) {
                entry.state = CandidatePairState::Succeeded;
                log(LogLevel::Debug, "Connectivity check succeeded for pair: {} <-> {}", pair.local_candidate.to_sdp(),
                    pair.remote_candidate.to_sdp());

                StunMessage resp = resp_opt.value();
                auto mapped_opt = resp.get_mapped_address();

                if (mapped_opt.has_value()) {
                    add_remote_candidate({mapped_opt.value(), CandidateType::PeerReflexive});
                }
            } else {
                entry.state = CandidatePairState::Failed;
                log(LogLevel::Debug, "Connectivity check failed for pair: " + pair.local_candidate.to_sdp() + " <-> " +
                                         pair.remote_candidate.to_sdp());
            }
        } catch (const std::exception &ex) {
            entry.state = CandidatePairState::Failed;
            log(LogLevel::Warning, "Connectivity check exception for pair: " + pair.local_candidate.to_sdp() + " <-> " +
                                       pair.remote_candidate.to_sdp() + " | " + ex.what());
        }
    }

    // Send STUN request with optional message integrity verification
    asio::awaitable<std::optional<StunMessage>> send_stun_request(
        const asio::ip::udp::endpoint &dest, const StunMessage &request, const std::string &remote_pwd = "",
        std::chrono::milliseconds initial_timeout = std::chrono::milliseconds(500), int max_tries = 7) {
        // 메시지 타입에 따라 응답을 기다릴지 결정
        bool expect_response =
            (request.get_type() == StunMessageType::BINDING_REQUEST || request.get_type() == StunMessageType::ALLOCATE);

        using namespace asio::experimental::awaitable_operators;

        auto data = request.serialize();
        auto txn_id = request.get_transaction_id();

        if (!expect_response) {
            // 응답을 기다리지 않고 메시지 전송
            co_await udp_socket_.async_send_to(asio::buffer(data), dest, asio::use_awaitable);
            log(LogLevel::Debug, "Sent STUN message to " + dest.address().to_string() + ":" +
                                     std::to_string(dest.port()) + " | Not expecting response");
            co_return std::nullopt;
        }

        std::chrono::milliseconds timeout = initial_timeout;
        for (int attempt = 0; attempt < max_tries; ++attempt) {
            // STUN 요청 전송
            co_await udp_socket_.async_send_to(asio::buffer(data), dest, asio::use_awaitable);
            log(LogLevel::Debug, "Sent STUN request to " + dest.address().to_string() + ":" +
                                     std::to_string(dest.port()) + " | Attempt: " + std::to_string(attempt + 1));

            // 응답 타이머 설정
            asio::steady_timer timer(strand_);
            timer.expires_after(timeout);

            std::vector<uint8_t> buf(2048);
            asio::ip::udp::endpoint sender;

            std::optional<StunMessage> response = std::nullopt;

            // STUN 응답 수신 또는 타이머 만료 중 하나를 기다림
            co_await (([&]() -> asio::awaitable<void> {
                          try {
                              std::size_t bytes = co_await udp_socket_.async_receive_from(asio::buffer(buf), sender,
                                                                                          asio::use_awaitable);
                              std::vector<uint8_t> received_data(buf.begin(), buf.begin() + bytes);
                              StunMessage resp = StunMessage::parse(received_data);
                              if (resp.get_transaction_id() == txn_id) {
                                  switch (resp.get_type()) {
                                      case StunMessageType::BINDING_RESPONSE_SUCCESS:
                                      case StunMessageType::BINDING_RESPONSE_ERROR:
                                      case StunMessageType::ALLOCATE_RESPONSE_SUCCESS:
                                      case StunMessageType::ALLOCATE_RESPONSE_ERROR: {
                                          // 메시지 무결성 및 핑거프린트 검증
                                          bool integrity_ok = true;
                                          bool fingerprint_ok = true;
                                          if (!remote_pwd.empty()) {
                                              integrity_ok = resp.verify_message_integrity(remote_pwd);
                                              fingerprint_ok = resp.verify_fingerprint();
                                          }
                                          if (integrity_ok && fingerprint_ok) {
                                              response = resp;
                                          }
                                          break;
                                      }
                                      default:
                                          break;
                                  }
                              }
                          } catch (...) {
                              // 오류 발생 시 무시
                          }
                      }()) ||
                      ([&]() -> asio::awaitable<void> {
                          try {
                              co_await timer.async_wait(asio::use_awaitable);
                          } catch (...) {
                              // 타이머 취소 시 무시
                          }
                      }()));

            if (response.has_value()) {
                log(LogLevel::Debug, "Received valid STUN response from " + sender.address().to_string() + ":" +
                                         std::to_string(sender.port()));
                co_return response;
            }

            // 지수 백오프
            timeout = std::min(timeout * 2, std::chrono::milliseconds(1600));
            log(LogLevel::Debug, "STUN retransmit attempt " + std::to_string(attempt + 1) +
                                     " failed. Retrying with timeout " + std::to_string(timeout.count()) + "ms.");
        }

        log(LogLevel::Warning, "STUN request to " + dest.address().to_string() + ":" + std::to_string(dest.port()) +
                                   " failed after " + std::to_string(max_tries) + " attempts.");
        co_return std::nullopt;
    }

    // Nominate a candidate pair
    asio::awaitable<bool> nominate_pair(CheckListEntry &entry) {
        asio::ip::udp::endpoint target = entry.pair.remote_candidate.endpoint;

        if (local_ice_attributes_.role == IceRole::Controller) {
            // Create and send BINDING_INDICATION with USE-CANDIDATE attribute
            StunMessage ind(StunMessageType::BINDING_REQUEST, StunMessage::generate_transaction_id());
            ind.add_attribute(StunAttributeType::USE_CANDIDATE, std::vector<uint8_t>{});
            ind.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
            ind.add_message_integrity(remote_ice_attributes_.pwd);
            ind.add_fingerprint();

            auto resp_opt = co_await send_stun_request(target, ind);
            if (!resp_opt.has_value())
                co_return false;

            auto resp = resp_opt.value();
            if (resp.get_type() != StunMessageType::BINDING_RESPONSE_SUCCESS)
                co_return false;
        }

        entry.is_nominated = true;
        nominated_pair_ = entry.pair;  // Set the nominated pair

        if (nominate_callback_) {
            nominate_callback_(entry.pair);
        }
        co_return true;
    }

    // Consent Freshness
    asio::awaitable<void> perform_consent_freshness() {
        while (current_state_ == IceConnectionState::Connected || current_state_ == IceConnectionState::Completed) {
            asio::steady_timer t(strand_);
            t.expires_after(std::chrono::seconds(15));
            co_await t.async_wait(asio::use_awaitable);
            if (!co_await send_consent_binding_request()) {
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::Error, "Consent freshness failed.");
                co_return;
            }
        }
    }

    asio::awaitable<bool> send_consent_binding_request() {
        const auto &pair = nominated_pair_.value();
        asio::ip::udp::endpoint target = pair.remote_candidate.endpoint;
        // If relay is allocated and the nominated pair uses relay, use relay endpoint
        if (pair.remote_candidate.type == CandidateType::Relay && !relay_endpoint_.address().is_unspecified()) {
            target = relay_endpoint_;
        }

        if (target.address().is_unspecified()) {
            co_return false;
        }
        // BINDING_REQUEST
        StunMessage req(StunMessageType::BINDING_REQUEST, StunMessage::generate_transaction_id());
        req.add_attribute(StunAttributeType::USERNAME, local_ice_attributes_.ufrag);  // Use local ufrag only
        if (local_ice_attributes_.role == IceRole::Controller) {
            req.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
        } else {
            req.add_attribute(StunAttributeType::ICE_CONTROLLED, serialize_uint64(local_ice_attributes_.tie_breaker));
        }
        req.add_message_integrity(local_ice_attributes_.pwd);  // Use local pwd
        req.add_fingerprint();

        bool ok = false;
        try {
            std::optional<StunMessage> resp_opt =
                co_await send_stun_request(target, req, remote_ice_attributes_.pwd, std::chrono::milliseconds(500), 5);
            ok = resp_opt.has_value();
            if (ok) {
                log(LogLevel::Debug, "Consent binding request succeeded.");
            } else {
                log(LogLevel::Warning, "Consent binding request timed out.");
            }
        } catch (const std::exception &ex) {
            log(LogLevel::Error, std::string("Consent binding request exception: ") + ex.what());
        }
        co_return ok;
    }

    // TURN refresh
    asio::awaitable<void> perform_turn_refresh() {
        while (current_state_ == IceConnectionState::Connected && !relay_endpoint_.address().is_unspecified()) {
            asio::steady_timer timer(strand_);
            timer.expires_after(std::chrono::seconds(300));  // Refresh every 5 minutes
            co_await timer.async_wait(asio::use_awaitable);
            try {
                // Create TURN Refresh request (similar to Allocate but with REFRESH attribute)
                StunMessage refresh_req(StunMessageType::ALLOCATE, StunMessage::generate_transaction_id());
                // Add necessary attributes
                refresh_req.add_attribute(StunAttributeType::USERNAME, turn_username_);
                refresh_req.add_attribute(StunAttributeType::REALM, turn_realm_);  // Replace with actual realm
                refresh_req.add_attribute(StunAttributeType::NONCE, turn_nonce_);  // Replace with actual nonce
                refresh_req.add_attribute(StunAttributeType::REFRESH);             // Indicate it's a refresh
                refresh_req.add_message_integrity(turn_password_);
                refresh_req.add_fingerprint();

                // Send Refresh request and await response TODO: 여러개이의 턴서버 지원.
                auto resp_opt = co_await send_stun_request(turn_endpoints_[0], refresh_req, turn_password_,
                                                           std::chrono::milliseconds(1000), 5);
                if (resp_opt.has_value()) {
                    StunMessage resp = resp_opt.value();
                    // Validate response if necessary
                    log(LogLevel::Debug, "TURN allocation refreshed.");
                } else {
                    throw std::runtime_error("TURN allocation refresh timed out.");
                }
            } catch (const std::exception &ex) {
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::Error, std::string("TURN refresh failed: ") + ex.what());
            }
        }
    }

    // 데이터 수신 시작 및 사용자 데이터 처리
    asio::awaitable<void> start_data_receive() {
        while (current_state_ == IceConnectionState::Connected || current_state_ == IceConnectionState::Completed) {
            std::vector<uint8_t> buf(2048);  // 수신 데이터 버퍼
            asio::ip::udp::endpoint sender;  // 송신자 엔드포인트
            size_t bytes = 0;

            try {
                // 비동기적으로 데이터 수신
                bytes = co_await udp_socket_.async_receive_from(asio::buffer(buf), sender, asio::use_awaitable);
            } catch (const std::exception &ex) {
                // 예외 발생 시 Failed 상태로 전환 및 로그 기록
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::Error, std::string("Data receive failed: ") + ex.what());
                break;
            }

            if (bytes > 0) {
                buf.resize(bytes);  // 실제 데이터 크기에 맞게 버퍼 크기 조정

                try {
                    // 수신된 데이터를 STUN 메시지로 파싱 시도
                    StunMessage sm = StunMessage::parse(buf);

                    // STUN 메시지로 처리
                    co_await handle_inbound_stun(sm, sender);
                } catch (const std::exception &ex) {
                    // STUN 메시지 파싱 실패 시, 응용 프로그램 데이터로 처리
                    // 추가: 로그에 예외 정보 포함
                    log(LogLevel::Debug, std::string("Failed to parse STUN message: ") + ex.what());

                    // 노미네이트된 원격 후보자로부터 온 데이터인지 확인
                    if (nominated_pair_.has_value() && sender == nominated_pair_.value().remote_candidate.endpoint) {
                        // 응용 프로그램 콜백을 통해 데이터 전달
                        if (data_callback_) {
                            data_callback_(buf, sender);
                            log(LogLevel::Debug,
                                "Received application data from nominated endpoint: " + sender.address().to_string() +
                                    ":" + std::to_string(sender.port()));
                        }
                    } else {
                        // 비노미네이트된 엔드포인트로부터 온 데이터 무시 및 경고 로그
                        log(LogLevel::Warning, "Received application data from unknown endpoint: " +
                                                   sender.address().to_string() + ":" + std::to_string(sender.port()));
                    }
                }
            }
        }
    }

    // Handle inbound STUN messages
    asio::awaitable<void> handle_inbound_stun(const StunMessage &sm, const asio::ip::udp::endpoint &sender) {
        switch (sm.get_type()) {
            case StunMessageType::BINDING_REQUEST:
                co_await handle_binding_request(sm, sender);
                break;
            case StunMessageType::BINDING_INDICATION:
                co_await handle_binding_indication(sm, sender);
                break;
            default:
                break;
        }
    }

    // Handle inbound STUN Binding Request (Triggered Checks and PRFLX Discovery)
    asio::awaitable<void> handle_binding_request(const StunMessage &req, const asio::ip::udp::endpoint &sender) {
        StunMessage resp(StunMessageType::BINDING_RESPONSE_SUCCESS, req.get_transaction_id());

        if (req.has_attribute(StunAttributeType::USE_CANDIDATE)) {
            co_await handle_use_candidate(req, sender);
        }

        auto uname_opt = req.get_attribute_as_string(StunAttributeType::USERNAME);
        if (uname_opt.has_value()) {
            std::string uname = uname_opt.value();
            size_t delim = uname.find(':');
            if (delim == std::string::npos) {
                log(LogLevel::Warning, "Invalid USERNAME format in binding request.");
            }

            std::string rcv_ufrag = uname.substr(0, delim);
            std::string snd_ufrag = uname.substr(delim + 1);

            // Verify that the receiver ufrag matches this agent's ufrag
            if (rcv_ufrag != local_ice_attributes_.ufrag) {
                log(LogLevel::Warning, "Received binding request with incorrect ufrag.");
            }
        }

        if (!req.verify_message_integrity(local_ice_attributes_.pwd)) {
            log(LogLevel::Warning, "Invalid MESSAGE-INTEGRITY in inbound binding request.");
        }

        if (!req.verify_fingerprint()) {
            log(LogLevel::Warning, "Invalid FINGERPRINT in inbound binding request.");
        }

        auto ice_controlling_opt = req.get_attribute_as_uint64(StunAttributeType::ICE_CONTROLLING);
        auto ice_controlled_opt = req.get_attribute_as_uint64(StunAttributeType::ICE_CONTROLLED);
        if (ice_controlling_opt.has_value() || ice_controlled_opt.has_value()) {
            uint64_t remote_tie_breaker =
                ice_controlling_opt.has_value() ? ice_controlling_opt.value() : ice_controlled_opt.value();
            negotiate_role(remote_tie_breaker);
        }

        auto mapped_opt = req.get_mapped_address();
        auto xor_mapped_opt = req.get_xor_mapped_address();
        if (mapped_opt.has_value() || xor_mapped_opt.has_value()) {
            asio::ip::udp::endpoint mapped;
            if (mapped_opt.has_value()) {
                mapped = mapped_opt.value();
                resp.add_attribute(StunAttributeType::MAPPED_ADDRESS, mapped);
            }

            if (xor_mapped_opt.has_value()) {
                mapped = xor_mapped_opt.value();
                resp.add_attribute(StunAttributeType::XOR_MAPPED_ADDRESS, mapped);
            }

            if (!mapped.address().is_unspecified()) {
                Candidate c = {mapped, CandidateType::PeerReflexive};
                auto priority_opt = req.get_attribute_as_uint32(StunAttributeType::PRIORITY);
                if (priority_opt.has_value()) {
                    c.priority = priority_opt.value();
                }

                // 연걸성을 테스트 하다가 새로운 candidate가 발견 되었을 경우.
                add_remote_candidate(c);

                // signaling으로 키를 주고 받았을 경우.
                resp.add_message_integrity(local_ice_attributes_.pwd);  // Use local p
            }
        }

        resp.add_fingerprint();

        co_await send_stun_request(sender, resp);
        log(LogLevel::Debug,
            "Sent BINDING_RESPONSE_SUCCESS to " + sender.address().to_string() + ":" + std::to_string(sender.port()));
    }

    // Helper Function to Handle USE-CANDIDATE Attribute
    asio::awaitable<void> handle_use_candidate(const StunMessage &req, const asio::ip::udp::endpoint &sender) {
        for (auto &e : check_list_) {
            if (e.pair.remote_candidate.endpoint == sender && e.state == CandidatePairState::Succeeded &&
                !e.is_nominated) {
                // Nominate the candidate pair
                co_await nominate_pair(e);
                transition_to_state(IceConnectionState::Completed);
                break;  // Exit after nominating the pair
            }
        }
    }

    asio::awaitable<void> handle_binding_indication(const StunMessage &ind, const asio::ip::udp::endpoint &sender) {}

    // Handle inbound signaling messages (e.g., SDP)
    asio::awaitable<void> handle_incoming_signaling_messages() {
        while (signaling_server_connected_ && current_state_ != IceConnectionState::Failed &&
               current_state_ != IceConnectionState::Completed) {
            try {
                // 비동기적으로 시그널링 메시지 수신
                std::size_t bytes =
                    co_await asio::async_read_until(tcp_socket_, signaling_buffer_, "\n", asio::use_awaitable);
                std::istream is(&signaling_buffer_);
                std::string sdp;
                std::getline(is, sdp);
                if (sdp.empty())
                    continue;

                auto [rattr, rcands] = parse_sdp(sdp);
                remote_ice_attributes_ = rattr;
                negotiate_role(rattr.tie_breaker);

                // Validate roles to prevent both being Controllers
                if (rattr.role == IceRole::Controller && local_ice_attributes_.role == IceRole::Controller) {
                    log(LogLevel::Error, "Both sides are Controller => fail");
                    transition_to_state(IceConnectionState::Failed);
                    co_return;
                }

                // Add remote candidates
                for (const auto &cand : rcands) add_remote_candidate(cand);
            } catch (const std::exception &ex) {
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::Error, "handle_incoming_signaling_messages exception: {}", ex.what());
            }
        }
    }

    // TODO: 동일 candidate가 추가되지 않게 옵션으로 변수추가.
    void add_remote_candidate(const Candidate &cand) {
        bool known = std::any_of(remote_candidates_.begin(), remote_candidates_.end(),
                                 [&](const auto &rc) { return cand == rc; });

        if (!known && !cand.endpoint.address().is_unspecified()) {
            remote_candidates_.emplace_back(cand);
            if (candidate_callback_) {
                candidate_callback_(cand);
            }
            log(LogLevel::Debug, "new candidate: {}", cand);

            // If trickle ICE is enabled or Full Ice, handle additional candidates as they arrive
            if (mode_ == IceMode::Full || local_ice_attributes_.has_option(IceOption::Trickle)) {
                if (connectivity_check_in_progress_) {
                } else {
                    asio::co_spawn(strand_, perform_connectivity_checks(), asio::detached);
                }
            }
        }
    }

    // 고유 식별자 기반 역할 결정 (IP 주소와 포트 합산)
    void negotiate_role(uint64_t remote_tie_breaker) {
        if (local_ice_attributes_.tie_breaker > remote_tie_breaker) {
            local_ice_attributes_.role = IceRole::Controller;
        } else if (local_ice_attributes_.tie_breaker < remote_tie_breaker) {
            local_ice_attributes_.role = IceRole::Controlled;
        } else {
            // Tie-breaker가 동일할 경우, IP 주소와 포트의 합으로 결정
            uint64_t local_id = 0;
            for (auto byte : udp_socket_.local_endpoint().address().to_v4().to_bytes()) {
                local_id = (local_id << 8) | byte;
            }
            local_id += udp_socket_.local_endpoint().port();

            uint64_t remote_id = 0;
            for (auto byte : udp_socket_.remote_endpoint().address().to_v4().to_bytes()) {
                remote_id = (remote_id << 8) | byte;
            }
            remote_id += udp_socket_.remote_endpoint().port();

            if (local_id > remote_id) {
                local_ice_attributes_.role = IceRole::Controller;
            } else {
                local_ice_attributes_.role = IceRole::Controlled;
            }
        }
        log(LogLevel::Info, "Negotiated role => " + ice_role_to_string(local_ice_attributes_.role));
    }

    // Convert IceRole to string for logging
    std::string ice_role_to_string(IceRole role) const {
        switch (role) {
            case IceRole::Controller:
                return "Controller";
            case IceRole::Controlled:
                return "Controlled";
            default:
                return "Unknown";
        }
    }

    // RFC 8445 Section 5.7.2에 따른 쌍 우선순위 계산
    uint64_t calculate_priority_pair(const Candidate &l, const Candidate &r) const {
        return ((std::min(l.priority, r.priority)) << 32) |
               ((static_cast<uint64_t>(std::max(l.priority, r.priority)) * 2)) | ((l.priority > r.priority) ? 1 : 0);
    }

    // Sort candidate pairs based on priority
    void sort_candidate_pairs() {
        std::sort(check_list_.begin(), check_list_.end(),
                  [&](auto &a, auto &b) { return a.pair.priority > b.pair.priority; });
    }

    // Logging function
    void log(LogLevel lvl, const std::string &msg_template, auto &&...args) {
        if (static_cast<int>(lvl) < static_cast<int>(log_level_))
            return;

        std::string formatted_msg = std::format(msg_template, std::forward<decltype(args)>(args)...);
        std::cout << "[IceAgent][" << log_level_to_string(lvl) << "] " << formatted_msg << std::endl;
    }

    // Convert LogLevel to string
    std::string log_level_to_string(LogLevel lvl) const {
        switch (lvl) {
            case LogLevel::Debug:
                return "DEBUG";
            case LogLevel::Info:
                return "INFO";
            case LogLevel::Warning:
                return "WARNING";
            case LogLevel::Error:
                return "ERROR";
            default:
                return "UNKNOWN";
        }
    }

    // Generate random string for ufrag and pwd
    static std::string generate_random_string(size_t len) {
        static const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> dist(0, 61);
        std::string s;
        s.reserve(len);
        for (size_t i = 0; i < len; ++i) {
            s.push_back(chars[dist(gen)]);
        }
        return s;
    }

    // Generate random uint64 for tie-breaker
    static uint64_t generate_random_uint64() {
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist;
        return dist(gen);
    }

    // Serialize uint32 to byte vector
    std::vector<uint8_t> serialize_uint32(uint32_t val) {
        std::vector<uint8_t> out(4);
        for (int i = 0; i < 4; ++i) {
            out[3 - i] = (val & 0xFF);
            val >>= 8;
        }
        return out;
    }

    // Serialize uint64 to byte vector
    std::vector<uint8_t> serialize_uint64(uint64_t val) {
        std::vector<uint8_t> out(8);
        for (int i = 0; i < 8; ++i) {
            out[7 - i] = (val & 0xFF);
            val >>= 8;
        }
        return out;
    }

    // ---------- TURN Operations Integrated ----------

    // TURN 릴레이 할당 (RFC 5766)
    asio::awaitable<void> allocate_turn_relay() {
        if (turn_endpoints_.empty()) {
            log(LogLevel::Warning, "No TURN servers available for allocation.");
            co_return;
        }

        for (const auto &turn_ep : turn_endpoints_) {
            uint32_t retry{0};

            do {
                try {
                    // STUN Allocate 요청 생성
                    StunMessage alloc_req(StunMessageType::ALLOCATE, StunMessage::generate_transaction_id());
                    alloc_req.add_attribute(StunAttributeType::REQUESTED_TRANSPORT, serialize_uint32(17));  // UDP
                    if (!turn_realm_.empty() && !turn_nonce_.empty()) {
                        std::string username = turn_username_ + ":" + turn_realm_;
                        alloc_req.add_attribute(StunAttributeType::REALM, turn_realm_);
                        alloc_req.add_attribute(StunAttributeType::NONCE, turn_nonce_);
                        alloc_req.add_attribute(StunAttributeType::USERNAME, username);
                        alloc_req.add_message_integrity(turn_password_);
                        alloc_req.add_fingerprint();
                    }

                    // Allocate 요청 전송
                    auto resp_opt = co_await send_stun_request(turn_ep, alloc_req, turn_password_,
                                                               std::chrono::milliseconds(1000), 3);

                    if (resp_opt.has_value()) {
                        StunMessage resp = resp_opt.value();
                        switch (resp.get_type()) {
                            case StunMessageType::ALLOCATE_RESPONSE_SUCCESS: {
                                auto relay_opt = resp.get_relayed_address();
                                if (relay_opt.has_value()) {
                                    relay_endpoint_ = relay_opt.value();
                                    log(LogLevel::Debug,
                                        "Allocated TURN relay: " + relay_endpoint_.address().to_string() + ":" +
                                            std::to_string(relay_endpoint_.port()));

                                    // 릴레이 후보자 생성
                                    Candidate c(relay_opt.value(), CandidateType::Relay);
                                    local_candidates_.push_back(c);
                                    if (candidate_callback_) {
                                        candidate_callback_(c);
                                    }
                                    log(LogLevel::Debug, "Gathered Relay candidate: " + c.to_sdp());

                                    // 주기적인 TURN 갱신 시작 (TODO: 나중에 정리)
                                    // asio::co_spawn(strand_, perform_turn_refresh(), asio::detached);
                                    co_return;  // 할당 성공
                                }
                                break;
                            }
                            case StunMessageType::ALLOCATE_RESPONSE_ERROR: {
                                // 인증 필요: REALM과 NONCE 추출
                                auto realm_opt = resp.get_attribute_as_string(StunAttributeType::REALM);
                                auto nonce_opt = resp.get_attribute_as_string(StunAttributeType::NONCE);
                                if (realm_opt.has_value() && nonce_opt.has_value()) {
                                    turn_realm_ = realm_opt.value();
                                    turn_nonce_ = nonce_opt.value();
                                } else {
                                    log(LogLevel::Warning, "TURN Allocate response missing REALM or NONCE.");
                                }
                                break;
                            }
                            default:
                                log(LogLevel::Warning, "Unexpected STUN message type.");
                                break;
                        }
                    }
                } catch (const std::exception &ex) {
                    log(LogLevel::Warning, "Failed to allocate TURN relay from " + turn_ep.address().to_string() + ":" +
                                               std::to_string(turn_ep.port()) + " | " + ex.what());
                    break;  // 현재 TURN 서버 시도 중단, 다음 서버로 이동
                }
            } while (retry++ > 1);
        }

        log(LogLevel::Warning, "Failed to allocate TURN relay from all TURN servers.");
    }

    // ---------- END TURN Operations Integrated ----------

    // ---------- Signaling Client Integrated ----------

    // 시작 시그널링 통신 로직
    asio::awaitable<void> start_signaling_communication() {
        signaling_server_connected_ = true;
        // 이후에 ICE 시작 로직을 호출하거나 필요한 초기화 수행
    }

    // 시그널링 서버에 SDP 전송
    asio::awaitable<void> send_sdp(const std::string &sdp) {
        std::string message = sdp + "\n";  // 메시지 구분자를 줄바꿈으로 가정
        co_await asio::async_write(tcp_socket_, asio::buffer(message), asio::use_awaitable);
        log(LogLevel::Debug, "Sent SDP to signaling server.");
    }

    // SDP 메시지를 생성 (예: Offer 또는 Answer)
    std::string create_sdp() const {
        std::ostringstream oss;
        return oss.str();
    }

    // SDP 파싱 (간단한 예제)
    std::pair<IceAttributes, std::vector<Candidate>> parse_sdp(const std::string &sdp) {
        IceAttributes attrs;
        std::vector<Candidate> candidates;
        return {attrs, candidates};
    }

    // ---------- END Signaling Client Integrated ----------
};
