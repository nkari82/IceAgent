#pragma once

#include <algorithm>
#include <asio.hpp>
#include <asio/experimental/parallel_group.hpp>
#include <atomic>
#include <bitset>
#include <chrono>
#include <format>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "stun_message.hpp"

// -------------------- ENUMS / STRUCTS --------------------
enum class IceMode { Full, Lite };

enum class IceRole { Controller, Controlled };

enum class IceOption { None = 1 << 0, IceLite = 1 << 1, Ice2 = 1 << 2, Trickle = 1 << 3 };

enum class IceConnectionState {
    New,           // 어떤 액션이 취해지기 전의 초기 상태
    Gathering,     // 로컬 후보자를 수집 중
    Checking,      // 로컬 후보와 원격 후보 간의 연결성 검사 수행
    Connected,     // 하나 이상의 후보 쌍이 성공했지만 검사가 아직 진행 중일 수 있음
    Completed,     // 모든 후보 쌍이 확인되었으며 하나 이상의 쌍이 성공
    Failed,        // 유효한 후보 쌍을 설정할 수 없었음
    Disconnected,  // 이전에 연결되었던 경로가 끊어짐
    Closed         // ICE 프로세스가 완전히 종료된 상태
};

enum class LogLevel { Debug = 0, Info, Warning, Error };

enum class CandidateType { Host = 126, PeerReflexive = 110, ServerReflexive = 100, Relay = 0 };

enum class Transport { Unknown, UDP, TCP, TLS };

// Candidate Structure
struct Candidate {
    asio::ip::udp::endpoint endpoint;
    CandidateType type;
    uint32_t priority;
    uint32_t component_id;
    Transport transport;
    std::string foundation;

    Candidate(const asio::ip::udp::endpoint &ep, CandidateType t, uint32_t comp_id = 1, Transport tp = Transport::UDP,
              const std::string &fnd = "")
        : endpoint(ep), type(t), component_id(comp_id), transport(tp) {
        // RFC 8445 Section 5.7.1에 따른 후보자 우선순위 계산
        uint32_t type_pref = static_cast<uint32_t>(t);
        switch (type) {
            case CandidateType::Host:
                foundation = fnd.empty() ? "host" : fnd;
                break;
            case CandidateType::PeerReflexive:
                foundation = fnd.empty() ? "prflx" : fnd;
                break;
            case CandidateType::ServerReflexive:
                foundation = fnd.empty() ? "srflx" : fnd;
                break;
            case CandidateType::Relay:
                foundation = fnd.empty() ? "relay" : fnd;
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
            return std::nullopt;
        }

        std::string typ;
        iss >> typ;  // "typ"
        if (typ != "typ")
            return std::nullopt;
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
                return std::nullopt;
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

    static std::string type_to_string(CandidateType t) {
        switch (t) {
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

    CandidatePair(const Candidate &l, const Candidate &r)
        : local_candidate(l),
          remote_candidate(r),
          // RFC 8445 Section 5.7.2에 따른 쌍 우선순위 계산
          priority(((std::min(l.priority, r.priority)) << 32) |
                   (static_cast<uint64_t>(std::max(l.priority, r.priority)) * 2) |
                   ((l.priority > r.priority) ? 1 : 0)) {}
};

enum class CandidatePairState { New, Frozen, InProgress, Failed, Succeeded, Nominated };

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
    std::string ufrag;
    std::string pwd;
    IceRole role;
    uint32_t options;
    uint64_t tie_breaker;

    void add_option(IceOption option) { options |= static_cast<uint32_t>(option); }

    bool has_option(IceOption option) const { return (options & static_cast<uint32_t>(option)) != 0; }
};

// -------------------- ICE AGENT --------------------
class IceAgent : public std::enable_shared_from_this<IceAgent> {
   public:
    IceAgent(asio::io_context &io_context, IceRole role, IceMode mode, const std::vector<std::string> &stun_servers,
             const std::vector<std::string> &turn_servers, const std::string &turn_username = "",
             const std::string &turn_password = "", const std::string &signaling_server = "",
             unsigned short signaling_port = 0)
        : io_context_(io_context),
          strand_(io_context.get_executor()),
          udp_socket_(io_context),
          tcp_socket_(strand_),
          mode_(mode),
          stun_servers_(stun_servers),
          turn_servers_(turn_servers),
          turn_username_(turn_username),
          turn_password_(turn_password),
          signaling_server_address_(signaling_server),
          signaling_server_port_(signaling_port),
          current_state_(IceConnectionState::New),
          log_level_(LogLevel::Info) {
        local_ice_attributes_ = generate_ice_attributes();
        local_ice_attributes_.role = role;

        // STUN 서버 비동기 resolve
        asio::ip::udp::resolver udp_resolver(io_context_);
        resolve(stun_endpoints_, udp_resolver, stun_servers_);

        // TURN 서버 비동기 resolve
        resolve(turn_endpoints_, udp_resolver, turn_servers_);

        // TURN relay endpoint (초기화)
        relay_endpoint_ = asio::ip::udp::endpoint();

        std::error_code ec;
        if (!(ec = udp_socket_.open(asio::ip::udp::v6(), ec))) {
            asio::ip::v6_only option(false);
            udp_socket_.set_option(option);

            asio::ip::udp::endpoint endpoint(asio::ip::udp::v6(), 0);
            udp_socket_.bind(endpoint, ec);
        }

        if (!ec) {
            log(LogLevel::Info, "UDP socket bound to: {}:{}", udp_socket_.local_endpoint().address().to_string(),
                std::to_string(udp_socket_.local_endpoint().port()));
        } else {
            log(LogLevel::Error, "Failed to bind UDP socket: {}", ec.message());
            transition_to_state(IceConnectionState::Failed);
        }

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
                                asio::co_spawn(strand_, start_signaling_communication(), asio::detached);
                            } else {
                                log(LogLevel::Error, "Failed to connect to signaling server: {}", ec.message());
                                transition_to_state(IceConnectionState::Failed);
                            }
                        }));
            } catch (const std::exception &ex) {
                log(LogLevel::Error, "Exception resolving signaling server: {}", std::string(ex.what()));
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
                    nominated_pair_ = std::nullopt;
                    check_list_.clear();
                    remote_candidates_.clear();
                    local_candidates_.clear();
                    relay_endpoint_ = asio::ip::udp::endpoint();

                    asio::co_spawn(strand_, start_data_receive(), asio::detached);

                    // 후보 수집
                    co_await gather_candidates();

                    // Full ICE 모드라면 체크 리스트 생성 후 연결성 검사
                    if (mode_ == IceMode::Full) {
                        co_await perform_connectivity_checks();
                    } else {
                        // Lite 모드
                        log(LogLevel::Info,
                            "ICE Lite mode => skipping local checks, waiting for remote side to check.");
                        transition_to_state(IceConnectionState::Connected);
                    }
                } catch (const std::exception &ex) {
                    log(LogLevel::Error, "start() exception: {}", ex.what());
                    transition_to_state(IceConnectionState::Failed);
                }
                co_return;
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

        if (pair.remote_candidate.type == CandidateType::Relay && !relay_endpoint_.address().is_unspecified()) {
            target = relay_endpoint_;
        }

        udp_socket_.async_send_to(asio::buffer(data), target, [this](std::error_code ec, std::size_t) {
            if (ec) {
                log(LogLevel::Error, "send_data failed: {}", ec.message());
            }
        });
    }

   private:
    struct ResponseData {
        ResponseData(asio::io_context &io_context) : timer(io_context) {}
        asio::steady_timer timer;
        std::optional<StunMessage> data;
    };

    using ResponseMap = std::unordered_map<StunMessage::Key, ResponseData, StunMessage::Key::Hasher>;

    asio::io_context &io_context_;
    asio::strand<asio::io_context::executor_type> strand_;
    asio::ip::udp::socket udp_socket_;
    asio::ip::tcp::socket tcp_socket_;
    IceMode mode_;
    std::vector<std::string> stun_servers_;
    std::vector<asio::ip::udp::endpoint> stun_endpoints_;
    std::vector<std::string> turn_servers_;
    std::string turn_username_;
    std::string turn_password_;
    std::vector<asio::ip::udp::endpoint> turn_endpoints_;
    std::atomic<IceConnectionState> current_state_;
    LogLevel log_level_;

    // TURN서버 AUTH
    std::string turn_realm_;
    std::string turn_nonce_;

    std::vector<Candidate> local_candidates_;
    std::vector<Candidate> remote_candidates_;
    std::vector<CheckListEntry> check_list_;
    bool connectivity_check_in_progress_{false};

    asio::ip::udp::endpoint relay_endpoint_;

    // 시그널링
    std::string signaling_server_address_;
    unsigned short signaling_server_port_;
    bool signaling_server_connected_ = false;
    asio::streambuf signaling_buffer_;

    StateCallback state_callback_;
    CandidateCallback candidate_callback_;
    DataCallback data_callback_;
    NominateCallback nominate_callback_;

    std::optional<CandidatePair> nominated_pair_;
    IceAttributes local_ice_attributes_;
    IceAttributes remote_ice_attributes_;

    ResponseMap pending_responses_;
    std::mutex response_mutex_;

    // ------------------------------------------------------

    bool transition_to_state(IceConnectionState new_state) {
        if (current_state_ == new_state)
            return false;
        current_state_ = new_state;
        if (state_callback_) {
            state_callback_(new_state);
        }
        log(LogLevel::Info, "ICE State => {}", ice_state_to_string(new_state));
        return true;
    }

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
            case IceConnectionState::Disconnected:
                return "Disconnected";
            case IceConnectionState::Closed:
                return "Closed";
            default:
                return "Unknown";
        }
    }

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

    asio::awaitable<void> gather_candidates() {
        if (!transition_to_state(IceConnectionState::Gathering))
            co_return;

        co_await gather_local_candidates();
        co_await gather_srflx_candidates();
        co_await gather_relay_candidates();

        co_return;
    }

    // RFC 8445 5.1.1.1 - 호스트 후보 수집
    asio::awaitable<void> gather_local_candidates() {
        asio::ip::udp::resolver resolver(strand_);
        auto results = co_await resolver.async_resolve(asio::ip::host_name(), "", asio::use_awaitable);
        for (auto &r : results) {
            auto address = r.endpoint().address();
            if (address.is_loopback()) {
                continue;
            }
            if (address.is_v6()) {
                auto v6 = address.to_v6();
                if (v6.is_link_local() || v6.is_site_local() || v6.is_v4_mapped()) {
                    continue;
                }
            }
            const auto &c = local_candidates_.emplace_back(Candidate{r.endpoint(), CandidateType::Host});
            if (candidate_callback_) {
                candidate_callback_(c);
            }
            log(LogLevel::Debug, "Gathered local candidate: {}", c.to_sdp());
        }
        co_return;
    }

    // RFC 8445 5.1.1.2 - 서버 반사형 후보 수집(STUN)
    asio::awaitable<void> gather_srflx_candidates() {
        for (const auto &stun_ep : stun_endpoints_) {
            try {
                StunMessage req(StunMessageType::BINDING_REQUEST, StunMessage::Key::generate());

                auto resp_opt = co_await send_stun_request(stun_ep, req);
                if (resp_opt.has_value()) {
                    StunMessage resp = resp_opt.value();
                    auto mapped_opt = resp.get_xor_mapped_address();
                    if (mapped_opt.has_value()) {
                        const auto &c = local_candidates_.emplace_back(
                            Candidate{convert_to_mapped_v6(mapped_opt.value()), CandidateType::ServerReflexive});
                        if (candidate_callback_) {
                            candidate_callback_(c);
                        }
                        log(LogLevel::Debug, "Gathered SRFLX candidate: {}", c.to_sdp());
                    }
                }
            } catch (const std::exception &ex) {
                log(LogLevel::Warning, "Failed to gather SRFLX from {}:{} | {}", stun_ep.address().to_string(),
                    std::to_string(stun_ep.port()), ex.what());
            }
        }
        co_return;
    }

    // RFC 8445 5.1.1.2 - 릴레이 후보 수집(TURN, RFC 5766 활용)
    asio::awaitable<void> gather_relay_candidates() {
        if (!turn_endpoints_.empty()) {
            co_await allocate_turn_relay();
        }
        co_return;
    }

    asio::awaitable<void> perform_connectivity_checks() {
        if (std::exchange(connectivity_check_in_progress_, true)) {
            co_return;
        }
        transition_to_state(IceConnectionState::Checking);

        try {
            check_list_.clear();
            for (auto &rc : remote_candidates_) {
                for (auto &lc : local_candidates_) {
                    if (lc.component_id == rc.component_id) {
                        CandidatePair cp(lc, rc);
                        check_list_.emplace_back(cp);
                    }
                }
            }
            sort_candidate_pairs();

            const size_t max_concurrency = 5;
            size_t next_pair = 0;
            std::vector<asio::awaitable<bool>> tasks;
            while (next_pair < check_list_.size()) {
                while (tasks.size() < max_concurrency && next_pair < check_list_.size()) {
                    CheckListEntry &entry = check_list_[next_pair++];
                    // #FIXME 새로 추가된 Candidate는 Frozen 상태 이므로 perform_single_connectivity_check에서 단순
                    // return한다.
                    if (entry.state == CandidatePairState::New || entry.state == CandidatePairState::Failed) {
                        entry.state = CandidatePairState::InProgress;

                        tasks.push_back(
                            asio::co_spawn(io_context_, perform_single_connectivity_check(entry), asio::use_awaitable));
                    }
                }

                for (auto &task : tasks) {
                    bool succeeded = co_await std::move(task);
                    if (succeeded) {
                        transition_to_state(IceConnectionState::Connected);
                    }
                }
                tasks.clear();

                co_await asio::post(strand_, asio::use_awaitable);
            }

            co_await evaluate_connectivity_results();
        } catch (...) {
            transition_to_state(IceConnectionState::Failed);
        }
        std::exchange(connectivity_check_in_progress_, false);
        co_return;
    }

    asio::awaitable<void> evaluate_connectivity_results() {
        bool any_success = std::any_of(check_list_.begin(), check_list_.end(), [](const CheckListEntry &e) {
            return e.state == CandidatePairState::Succeeded;
        });

        if (any_success) {
            transition_to_state(IceConnectionState::Completed);

            for (auto &entry : check_list_) {
                if (entry.state == CandidatePairState::New || entry.state == CandidatePairState::Failed) {
                    entry.state = CandidatePairState::Frozen;
                }
            }

            if (mode_ == IceMode::Full) {
                asio::co_spawn(strand_, perform_consent_freshness(), asio::detached);
            }
            if (!relay_endpoint_.address().is_unspecified()) {
                asio::co_spawn(strand_, perform_turn_refresh(), asio::detached);
            }
        } else {
            transition_to_state(IceConnectionState::Failed);
        }
        co_return;
    }

    asio::awaitable<bool> perform_single_connectivity_check(CheckListEntry &entry) {
        if (entry.state == CandidatePairState::Frozen) {
            co_return false;
        }
        const auto &pair = entry.pair;
        bool is_relay = (pair.remote_candidate.type == CandidateType::Relay);

        StunMessage req(StunMessageType::BINDING_REQUEST, StunMessage::Key::generate());
        req.add_attribute(StunAttributeType::PRIORITY, serialize_uint32(pair.local_candidate.priority));

        std::string uname = local_ice_attributes_.ufrag;
        req.add_attribute(StunAttributeType::USERNAME, uname);

        if (local_ice_attributes_.role == IceRole::Controller) {
            req.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
        } else {
            req.add_attribute(StunAttributeType::ICE_CONTROLLED, serialize_uint64(local_ice_attributes_.tie_breaker));
        }
        req.add_message_integrity(local_ice_attributes_.pwd);
        req.add_fingerprint();

        asio::ip::udp::endpoint dest = pair.remote_candidate.endpoint;
        if (is_relay && !relay_endpoint_.address().is_unspecified()) {
            dest = relay_endpoint_;
        }

        std::optional<StunMessage> resp_opt;
        try {
            resp_opt = co_await send_stun_request(dest, req, remote_ice_attributes_.pwd);

            if (resp_opt.has_value()) {
                entry.state = CandidatePairState::Succeeded;
                StunMessage resp = resp_opt.value();
                auto mapped_opt = resp.get_mapped_address();
                if (mapped_opt.has_value()) {
                    add_remote_candidate({mapped_opt.value(), CandidateType::PeerReflexive});
                }
            } else {
                entry.state = CandidatePairState::Failed;
            }
        } catch (const std::exception &ex) {
            entry.state = CandidatePairState::Failed;
            log(LogLevel::Warning, "Connectivity check exception for pair: {} <-> {} | {}",
                pair.local_candidate.to_sdp(), pair.remote_candidate.to_sdp(), ex.what());
        }
        co_return (entry.state == CandidatePairState::Succeeded);
    }

    // STUN 요청/응답 (#FIXME request와 allocate만 처리)
    asio::awaitable<std::optional<StunMessage>> send_stun_request(
        const asio::ip::udp::endpoint &dest, const StunMessage &request, const std::string &remote_pwd = "",
        std::chrono::milliseconds initial_timeout = std::chrono::milliseconds(500), int max_tries = 7) {
        asio::error_code ec;
        bool expect_response =
            (request.get_type() == StunMessageType::BINDING_REQUEST || request.get_type() == StunMessageType::ALLOCATE);

        auto data = request.serialize();

        if (!expect_response) {
            udp_socket_.async_send_to(asio::buffer(data), dest, [](std::error_code, size_t) {});
            log(LogLevel::Debug, "Sent STUN message to {}:{} | Not expecting response", dest.address().to_string(),
                std::to_string(dest.port()));
            co_return std::nullopt;
        }

        auto txn_id = request.get_transaction_id();
        ResponseData *response{nullptr};
        {
            std::lock_guard<std::mutex> lock(response_mutex_);
            auto [it, _] = pending_responses_.try_emplace(txn_id, io_context_);
            response = &it->second;
        }

        std::optional<StunMessage> message;
        std::chrono::milliseconds timeout = initial_timeout;

        for (int attempt = 0; attempt < max_tries; ++attempt) {
            udp_socket_.async_send_to(asio::buffer(data), dest, [](std::error_code, size_t) {});

            log(LogLevel::Debug, "Sent STUN request to {}:{} | Attempt: {}", dest.address().to_string(),
                std::to_string(dest.port()), std::to_string(attempt + 1));

            response->timer.expires_after(timeout);
            co_await response->timer.async_wait(asio::redirect_error(asio::use_awaitable, ec));

            message = std::move(response->data);
            if (!message) {
                timeout = std::min(timeout * 2, std::chrono::milliseconds(1600));
                log(LogLevel::Debug, "STUN retransmit attempt {} failed. Retrying with timeout {}ms",
                    std::to_string(attempt + 1), std::to_string(timeout.count()));
                continue;
            }

            const auto &value = message.value();
            if (value.get_transaction_id() == txn_id) {
                switch (value.get_type()) {
                    case StunMessageType::BINDING_RESPONSE_SUCCESS:
                    case StunMessageType::BINDING_RESPONSE_ERROR:
                    case StunMessageType::ALLOCATE_RESPONSE_SUCCESS:
                    case StunMessageType::ALLOCATE_RESPONSE_ERROR: {
                        bool integrity_ok = true;
                        bool fingerprint_ok = true;
                        if (!remote_pwd.empty()) {
                            integrity_ok = value.verify_message_integrity(remote_pwd);
                            fingerprint_ok = value.verify_fingerprint();
                        }
                        if (!integrity_ok || !fingerprint_ok) {
                            message = std::nullopt;
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
            break;
        }

        {
            std::lock_guard<std::mutex> lock(response_mutex_);
            pending_responses_.erase(txn_id);
        }
        co_return message;
    }

    // STUN Error Response
    void send_error_response(const asio::ip::udp::endpoint &sender, const StunMessage &req, StunErrorCode code,
                             const std::string &reason_template, auto &&...args) {
        try {
            StunMessage resp(StunMessageType::BINDING_RESPONSE_ERROR, req.get_transaction_id());
            std::string reason =
                std::vformat(reason_template, std::make_format_args(std::forward<decltype(args)>(args)...));
            resp.add_error_code(code, reason);
            resp.add_fingerprint();

            auto data = resp.serialize();
            udp_socket_.async_send_to(asio::buffer(data), sender, [](std::error_code, size_t) {});

            log(LogLevel::Warning, "Sent error response: {} ({}) to {}", get_error_reason(code), reason,
                sender.address().to_string());
        } catch (const std::exception &ex) {
            log(LogLevel::Error, "Failed to send error response to {}: {}", sender.address().to_string(), ex.what());
        }
    }

    // Candidate Pair Nomination
    asio::awaitable<bool> nominate_pair(CheckListEntry &entry) {
        asio::ip::udp::endpoint target = entry.pair.remote_candidate.endpoint;

        if (local_ice_attributes_.role == IceRole::Controller) {
            StunMessage ind(StunMessageType::BINDING_REQUEST, StunMessage::Key::generate());
            ind.add_attribute(StunAttributeType::USE_CANDIDATE, std::vector<uint8_t>{});
            ind.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
            ind.add_message_integrity(remote_ice_attributes_.pwd);
            ind.add_fingerprint();

            auto resp_opt = co_await send_stun_request(target, ind);
            if (!resp_opt.has_value()) {
                co_return false;
            }
            auto resp = resp_opt.value();
            if (resp.get_type() != StunMessageType::BINDING_RESPONSE_SUCCESS) {
                co_return false;
            }
        }

        entry.is_nominated = true;
        nominated_pair_ = entry.pair;
        if (nominate_callback_) {
            nominate_callback_(entry.pair);
        }
        co_return true;
    }

    // RFC 8445 Consent Freshness
    asio::awaitable<void> perform_consent_freshness() {
        while (current_state_ == IceConnectionState::Connected || current_state_ == IceConnectionState::Completed) {
            asio::steady_timer t(strand_);
            t.expires_after(std::chrono::seconds(15));
            co_await t.async_wait(asio::use_awaitable);

            bool ok = co_await send_consent_binding_request();
            if (!ok) {
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::Error, "Consent freshness failed.");
                co_return;
            }
        }
        co_return;
    }

    asio::awaitable<bool> send_consent_binding_request() {
        const auto &pair = nominated_pair_.value();
        asio::ip::udp::endpoint target = pair.remote_candidate.endpoint;

        if (pair.remote_candidate.type == CandidateType::Relay && !relay_endpoint_.address().is_unspecified()) {
            target = relay_endpoint_;
        }
        if (target.address().is_unspecified()) {
            co_return false;
        }

        StunMessage req(StunMessageType::BINDING_REQUEST, StunMessage::Key::generate());
        req.add_attribute(StunAttributeType::USERNAME, local_ice_attributes_.ufrag);
        if (local_ice_attributes_.role == IceRole::Controller) {
            req.add_attribute(StunAttributeType::ICE_CONTROLLING, serialize_uint64(local_ice_attributes_.tie_breaker));
        } else {
            req.add_attribute(StunAttributeType::ICE_CONTROLLED, serialize_uint64(local_ice_attributes_.tie_breaker));
        }
        req.add_message_integrity(local_ice_attributes_.pwd);
        req.add_fingerprint();

        bool ok = false;
        try {
            std::optional<StunMessage> resp_opt =
                co_await send_stun_request(target, req, remote_ice_attributes_.pwd, std::chrono::milliseconds(500), 5);
            ok = resp_opt.has_value();
        } catch (const std::exception &ex) {
            log(LogLevel::Error, "Consent binding request exception: {}", ex.what());
        }
        co_return ok;
    }

    // TURN refresh
    asio::awaitable<void> perform_turn_refresh() {
        while (current_state_ == IceConnectionState::Connected && !relay_endpoint_.address().is_unspecified()) {
            asio::steady_timer timer(strand_);
            timer.expires_after(std::chrono::seconds(300));
            co_await timer.async_wait(asio::use_awaitable);
            try {
                StunMessage refresh_req(StunMessageType::ALLOCATE, StunMessage::Key::generate());
                refresh_req.add_attribute(StunAttributeType::USERNAME, turn_username_);
                refresh_req.add_attribute(StunAttributeType::REALM, turn_realm_);
                refresh_req.add_attribute(StunAttributeType::NONCE, turn_nonce_);
                refresh_req.add_attribute(StunAttributeType::REFRESH);
                refresh_req.add_message_integrity(turn_password_);
                refresh_req.add_fingerprint();

                auto resp_opt = co_await send_stun_request(turn_endpoints_[0], refresh_req, turn_password_,
                                                           std::chrono::milliseconds(1000), 5);
                if (!resp_opt.has_value()) {
                    throw std::runtime_error("TURN allocation refresh timed out.");
                }
                log(LogLevel::Debug, "TURN allocation refreshed.");
            } catch (const std::exception &ex) {
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::Error, "TURN refresh failed: {}", ex.what());
            }
        }
        co_return;
    }

    asio::awaitable<void> start_data_receive() {
        while (current_state_ != IceConnectionState::Closed) {
            std::vector<uint8_t> buf(2048);
            asio::ip::udp::endpoint sender;
            size_t bytes = 0;

            try {
                bytes = co_await udp_socket_.async_receive_from(asio::buffer(buf), sender, asio::use_awaitable);
            } catch (const std::exception &ex) {
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::Error, "Data receive failed: {}", ex.what());
                break;
            }

            if (bytes > 0) {
                buf.resize(bytes);

                try {
                    if (IsStunMessage(buf)) {
                        StunMessage sm = StunMessage::parse(buf);

                        {
                            std::lock_guard<std::mutex> lock(response_mutex_);
                            auto it = pending_responses_.find(sm.get_transaction_id());
                            if (it != pending_responses_.end()) {
                                auto &response = it->second;
                                response.data = sm;
                                response.timer.cancel();
                                continue;
                            }
                        }
                        co_await handle_inbound_stun(sm, sender);
                    } else {
                        if (nominated_pair_.has_value() &&
                            sender == nominated_pair_.value().remote_candidate.endpoint) {
                            if (data_callback_) {
                                data_callback_(buf, sender);
                                log(LogLevel::Debug, "Received application data from nominated endpoint: {}:{}",
                                    sender.address().to_string(), std::to_string(sender.port()));
                            }
                        } else {
                            log(LogLevel::Warning, "Received application data from unknown endpoint: {}:{}",
                                sender.address().to_string(), std::to_string(sender.port()));
                        }
                    }
                } catch (const std::exception &ex) {
                    log(LogLevel::Debug, "Failed to parse STUN message: {}", ex.what());
                }
            }
        }
        co_return;
    }

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
        co_return;
    }

    asio::awaitable<void> handle_binding_request(const StunMessage &req, const asio::ip::udp::endpoint &sender) {
        try {
            // 1. USERNAME Attribute Validation
            auto uname_opt = req.get_attribute_as_string(StunAttributeType::USERNAME);
            if (!uname_opt.has_value()) {
                send_error_response(sender, req, StunErrorCode::BAD_REQUEST, "Missing USERNAME from {}",
                                    sender.address().to_string());
                co_return;
            }

            const std::string &uname = uname_opt.value();
            std::size_t delim_pos = uname.find(':');
            if (delim_pos == std::string::npos) {
                send_error_response(sender, req, StunErrorCode::BAD_REQUEST, "Invalid USERNAME format from {}",
                                    sender.address().to_string());
                co_return;
            }

            // USERNAME format: local_ufrag:remote_ufrag
            std::string rcv_ufrag = uname.substr(0, delim_pos);
            std::string snd_ufrag = uname.substr(delim_pos + 1);

            // Validate receiver ufrag
            if (rcv_ufrag != local_ice_attributes_.ufrag) {
                send_error_response(sender, req, StunErrorCode::UNAUTHORIZED, "Incorrect receiver ufrag from {}",
                                    sender.address().to_string());
                co_return;
            }

            // Optional: Validate sender ufrag if expected ufrags are maintained
            // This can prevent spoofing by ensuring snd_ufrag matches a known remote ufrag
            // For simplicity, assume any snd_ufrag is acceptable here

            // 2. MESSAGE-INTEGRITY Attribute Validation
            if (req.has_attribute(StunAttributeType::MESSAGE_INTEGRITY)) {
                if (!req.verify_message_integrity(local_ice_attributes_.pwd)) {
                    send_error_response(sender, req, StunErrorCode::UNAUTHORIZED, "Invalid MESSAGE-INTEGRITY from {}",
                                        sender.address().to_string());
                    co_return;
                }
            } else {
                // MESSAGE-INTEGRITY is mandatory if PRIORITY or ICE attributes are present
                // Depending on implementation specifics, you might enforce its presence
                // Here, we allow it to be optional
            }

            // 3. FINGERPRINT Attribute Validation
            if (req.has_attribute(StunAttributeType::FINGERPRINT)) {
                if (!req.verify_fingerprint()) {
                    send_error_response(sender, req, StunErrorCode::BAD_REQUEST, "Invalid FINGERPRINT from {}",
                                        sender.address().to_string());
                    co_return;
                }
            }

            // 4. ICE-CONTROLLING and ICE-CONTROLLED Attributes Handling
            auto ice_controlling_opt = req.get_attribute_as_uint64(StunAttributeType::ICE_CONTROLLING);
            auto ice_controlled_opt = req.get_attribute_as_uint64(StunAttributeType::ICE_CONTROLLED);

            if (ice_controlling_opt.has_value() || ice_controlled_opt.has_value()) {
                uint64_t remote_tie_breaker =
                    ice_controlling_opt.has_value() ? ice_controlling_opt.value() : ice_controlled_opt.value();

                negotiate_role(remote_tie_breaker);
            }

            // 5. Binding Response Creation
            StunMessage resp(StunMessageType::BINDING_RESPONSE_SUCCESS, req.get_transaction_id());

            // Determine whether to include XOR-MAPPED-ADDRESS or MAPPED-ADDRESS
            // RFC8445 prefers XOR-MAPPED-ADDRESS
            if (req.has_attribute(StunAttributeType::XOR_MAPPED_ADDRESS)) {
                resp.add_attribute(StunAttributeType::XOR_MAPPED_ADDRESS, sender);
            } else if (req.has_attribute(StunAttributeType::MAPPED_ADDRESS)) {
                resp.add_attribute(StunAttributeType::MAPPED_ADDRESS, sender);
            } else {
                // If neither attribute is present in the request, per RFC 5389,
                // XOR-MAPPED-ADDRESS should be included
                resp.add_attribute(StunAttributeType::XOR_MAPPED_ADDRESS, sender);
            }

            // 6. PRIORITY Attribute Handling
            auto priority_opt = req.get_attribute_as_uint32(StunAttributeType::PRIORITY);
            if (priority_opt.has_value()) {
                // Calculate Peer-Reflexive priority if necessary
                // Here, we use the provided priority directly
                Candidate prflx_candidate(sender, CandidateType::PeerReflexive);
                prflx_candidate.priority = priority_opt.value();
                add_remote_candidate(prflx_candidate);
            }

            // 7. USE-CANDIDATE Attribute Handling
            if (req.has_attribute(StunAttributeType::USE_CANDIDATE)) {
                for (auto &entry : check_list_) {
                    if (entry.pair.remote_candidate.endpoint == sender &&
                        entry.state == CandidatePairState::Succeeded && !entry.is_nominated) {
                        co_await nominate_pair(entry);
                        transition_to_state(IceConnectionState::Completed);
                        break;
                    }
                }
            }

            // 8. Add MESSAGE-INTEGRITY and FINGERPRINT to Response
            resp.add_message_integrity(local_ice_attributes_.pwd);
            resp.add_fingerprint();

            // 9. Send the Binding Response
            co_await send_stun_message(sender, resp);
        } catch (const std::exception &ex) {
            // Handle unexpected exceptions gracefully
            // Log the error and send a generic error response
            // Assuming a logging mechanism is in place
            // log_error("Exception in handle_binding_request: {}", ex.what());
            send_error_response(sender, req, StunErrorCode::SERVER_ERROR, "Internal Server Error from {}",
                                sender.address().to_string());
        }

        co_return;
    }

    // #FIXME 이게 필요가 있나??
    asio::awaitable<void> handle_binding_indication(const StunMessage &ind, const asio::ip::udp::endpoint &sender) {
        co_return;
    }

    asio::awaitable<void> handle_incoming_signaling_messages() {
        while (signaling_server_connected_ && current_state_ != IceConnectionState::Failed &&
               current_state_ != IceConnectionState::Completed) {
            try {
                std::size_t bytes =
                    co_await asio::async_read_until(tcp_socket_, signaling_buffer_, "\n", asio::use_awaitable);
                std::istream is(&signaling_buffer_);
                std::string sdp;
                std::getline(is, sdp);
                if (sdp.empty()) {
                    continue;
                }
                auto [rattr, rcands] = parse_sdp(sdp);
                remote_ice_attributes_ = rattr;
                negotiate_role(rattr.tie_breaker);

                if (rattr.role == IceRole::Controller && local_ice_attributes_.role == IceRole::Controller) {
                    log(LogLevel::Error, "Both sides are Controller => fail");
                    transition_to_state(IceConnectionState::Failed);
                    co_return;
                }
                for (const auto &cand : rcands) {
                    add_remote_candidate(cand);
                }
            } catch (const std::exception &ex) {
                transition_to_state(IceConnectionState::Failed);
                log(LogLevel::Error, "handle_incoming_signaling_messages exception: {}", ex.what());
            }
        }
        co_return;
    }

    asio::awaitable<void> add_remote_candidate(const Candidate &cand) {
        co_await asio::dispatch(bind_executor(strand_, asio::use_awaitable));
        bool known = std::any_of(remote_candidates_.begin(), remote_candidates_.end(),
                                 [&](const auto &rc) { return cand == rc; });
        if (!known && !cand.endpoint.address().is_unspecified()) {
            remote_candidates_.emplace_back(cand);
            if (candidate_callback_) {
                candidate_callback_(cand);
            }
            log(LogLevel::Debug, "new candidate: {}", cand.to_sdp());

            if (mode_ == IceMode::Full || local_ice_attributes_.has_option(IceOption::Trickle)) {
                if (connectivity_check_in_progress_) {
                    CandidatePair new_pair(local_candidates_.front(), cand);
                    CheckListEntry entry(new_pair);
                    entry.state = CandidatePairState::Frozen;
                    check_list_.push_back(entry);
                    sort_candidate_pairs();
                } else {
                    asio::co_spawn(strand_, perform_connectivity_checks(), asio::detached);
                }
            }
        }
        co_return;
    }

    void negotiate_role(uint64_t remote_tie_breaker) {
        if (local_ice_attributes_.tie_breaker > remote_tie_breaker) {
            local_ice_attributes_.role = IceRole::Controller;
        } else if (local_ice_attributes_.tie_breaker < remote_tie_breaker) {
            local_ice_attributes_.role = IceRole::Controlled;
        } else {
            uint64_t local_id = 0;
            auto local_ep = udp_socket_.local_endpoint();
            auto remote_ep = udp_socket_.remote_endpoint();
            if (local_ep.address().is_v4()) {
                for (auto byte : local_ep.address().to_v4().to_bytes()) {
                    local_id = (local_id << 8) | byte;
                }
                local_id += local_ep.port();
            }

            uint64_t remote_id = 0;
            if (!remote_ep.address().is_unspecified() && remote_ep.address().is_v4()) {
                for (auto byte : remote_ep.address().to_v4().to_bytes()) {
                    remote_id = (remote_id << 8) | byte;
                }
                remote_id += remote_ep.port();
            }

            if (local_id > remote_id) {
                local_ice_attributes_.role = IceRole::Controller;
            } else {
                local_ice_attributes_.role = IceRole::Controlled;
            }
        }
        log(LogLevel::Info, "Negotiated role => {}", ice_role_to_string(local_ice_attributes_.role));
    }

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

    void sort_candidate_pairs() {
        std::sort(check_list_.begin(), check_list_.end(),
                  [&](auto &a, auto &b) { return a.pair.priority > b.pair.priority; });
    }

    void log(LogLevel lvl, const std::string &msg_template, auto &&...args) {
        if (static_cast<int>(lvl) < static_cast<int>(log_level_)) {
            return;
        }
        std::string formatted_msg =
            std::vformat(msg_template, std::make_format_args(std::forward<decltype(args)>(args)...));
        std::cout << "[IceAgent][" << log_level_to_string(lvl) << "] " << formatted_msg << std::endl;
    }

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

    static uint64_t generate_random_uint64() {
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist;
        return dist(gen);
    }

    std::vector<uint8_t> serialize_uint32(uint32_t val) {
        std::vector<uint8_t> out(4);
        for (int i = 0; i < 4; ++i) {
            out[3 - i] = static_cast<uint8_t>(val & 0xFF);
            val >>= 8;
        }
        return out;
    }

    std::vector<uint8_t> serialize_uint64(uint64_t val) {
        std::vector<uint8_t> out(8);
        for (int i = 0; i < 8; ++i) {
            out[7 - i] = static_cast<uint8_t>(val & 0xFF);
            val >>= 8;
        }
        return out;
    }

    asio::awaitable<void> allocate_turn_relay() {
        if (turn_endpoints_.empty()) {
            log(LogLevel::Warning, "No TURN servers available for allocation.");
            co_return;
        }
        for (const auto &turn_ep : turn_endpoints_) {
            uint32_t retry{0};
            do {
                try {
                    StunMessage alloc_req(StunMessageType::ALLOCATE, StunMessage::Key::generate());
                    alloc_req.add_attribute(StunAttributeType::REQUESTED_TRANSPORT,
                                            serialize_uint32(17));  // UDP

                    if (!turn_realm_.empty() && !turn_nonce_.empty()) {
                        std::string username = turn_username_ + ":" + turn_realm_;
                        alloc_req.add_attribute(StunAttributeType::REALM, turn_realm_);
                        alloc_req.add_attribute(StunAttributeType::NONCE, turn_nonce_);
                        alloc_req.add_attribute(StunAttributeType::USERNAME, username);
                        alloc_req.add_message_integrity(turn_password_);
                        alloc_req.add_fingerprint();
                    }

                    auto resp_opt = co_await send_stun_message(turn_ep, alloc_req, turn_password_,
                                                               std::chrono::milliseconds(1000), 3);
                    if (resp_opt.has_value()) {
                        StunMessage resp = resp_opt.value();
                        switch (resp.get_type()) {
                            case StunMessageType::ALLOCATE_RESPONSE_SUCCESS: {
                                auto relay_opt = resp.get_relayed_address();
                                if (relay_opt.has_value()) {
                                    relay_endpoint_ = relay_opt.value();
                                    log(LogLevel::Debug, "Allocated TURN relay: {}:{}",
                                        relay_endpoint_.address().to_string(), std::to_string(relay_endpoint_.port()));

                                    Candidate c(relay_endpoint_, CandidateType::Relay);
                                    local_candidates_.push_back(c);
                                    if (candidate_callback_) {
                                        candidate_callback_(c);
                                    }
                                    co_return;
                                }
                                break;
                            }
                            case StunMessageType::ALLOCATE_RESPONSE_ERROR: {
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
                    log(LogLevel::Warning, "Failed to allocate TURN relay from {}:{} | {}",
                        turn_ep.address().to_string(), std::to_string(turn_ep.port()), ex.what());
                    break;
                }
            } while (retry++ > 1);
        }

        log(LogLevel::Warning, "Failed to allocate TURN relay from all TURN servers.");
        co_return;
    }

    asio::awaitable<void> start_signaling_communication() {
        signaling_server_connected_ = true;
        co_return;
    }

    asio::awaitable<void> send_sdp(const std::string &sdp) {
        std::string message = sdp + "\n";
        co_await asio::async_write(tcp_socket_, asio::buffer(message), asio::use_awaitable);
        log(LogLevel::Debug, "Sent SDP to signaling server.");
        co_return;
    }

    std::string create_sdp() const {
        std::ostringstream oss;
        return oss.str();
    }

    std::pair<IceAttributes, std::vector<Candidate>> parse_sdp(const std::string &sdp) {
        IceAttributes attrs;
        std::vector<Candidate> candidates;
        return {attrs, candidates};
    }

    template <typename ENDPOINT>
    ENDPOINT convert_to_mapped_v6(const ENDPOINT &ep) {
        if (ep.address().is_v6()) {
            return ep;
        }
        std::array<uint8_t, 16> bytes = {0};
        bytes[10] = 0xff;
        bytes[11] = 0xff;
        auto ipv4_bytes = ep.address().to_v4().to_bytes();
        std::copy(ipv4_bytes.begin(), ipv4_bytes.end(), bytes.begin() + 12);
        return ENDPOINT(asio::ip::address_v6(bytes), ep.port());
    }

    template <typename ENDPOINT, typename RESOLVER>
    void resolve(std::vector<ENDPOINT> &endpoints, RESOLVER &resolver, const std::vector<std::string> &servers) {
        for (const auto &s : servers) {
            size_t pos = s.find(':');
            if (pos != std::string::npos) {
                std::string host = s.substr(0, pos);
                std::string port_str = s.substr(pos + 1);
                try {
                    auto results = resolver.resolve(host, port_str, RESOLVER::flags::address_configured);
                    for (const auto &r : results) {
                        endpoints.push_back(convert_to_mapped_v6(r.endpoint()));
                        log(LogLevel::Debug, "Resolved server: {}:{}", r.endpoint().address().to_string(),
                            std::to_string(r.endpoint().port()));
                    }
                } catch (const std::exception &ex) {
                    log(LogLevel::Warning, "Failed to resolve server '{}:{}' | {}", host, port_str, ex.what());
                }
            }
        }
    }
};
