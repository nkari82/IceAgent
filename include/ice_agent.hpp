// include/ice_agent.hpp

#ifndef ICE_AGENT_HPP
#define ICE_AGENT_HPP

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <algorithm>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <sstream>
#include "stun_client.hpp"
#include "turn_client.hpp"
#include "signaling_client.hpp"
#include "stun_message.hpp"

// ICE 모드 정의
enum class IceMode {
    Full,
    Lite
};

// ICE 역할 정의
enum class IceRole {
    Controller,
    Controlled
};

// ICE 연결 상태 정의
enum class IceConnectionState {
    New,
    Gathering,
    Checking,
    Connected,
    Completed,
    Failed
};

// 로그 레벨 정의
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

// Candidate 구조체
struct Candidate {
    asio::ip::udp::endpoint endpoint;
    CandidateType type;
    uint32_t priority;
    int component_id;
    std::string foundation;
    std::string transport; // Typically "UDP"

    // Convert Candidate to SDP format
    std::string to_sdp() const {
        std::ostringstream oss;
        oss << "a=candidate:" << foundation << " " << component_id << " "
            << transport << " " << priority << " "
            << endpoint.address().to_string() << " " << endpoint.port()
            << " typ ";

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

    // Parse Candidate from SDP format
    static Candidate from_sdp(const std::string& sdp_line) {
        Candidate cand;
        std::istringstream iss(sdp_line);
        std::string prefix;
        iss >> prefix; // "a=candidate:<foundation>"

        // Extract foundation
        size_t colon_pos = prefix.find(':');
        if (colon_pos != std::string::npos) {
            cand.foundation = prefix.substr(colon_pos + 1);
        }

        iss >> cand.component_id;
        std::string transport;
        iss >> transport;
        cand.transport = transport;
        iss >> cand.priority;
        std::string ip;
        uint16_t port;
        iss >> ip >> port;

        asio::ip::address address = asio::ip::make_address(ip);
        cand.endpoint = asio::ip::udp::endpoint(address, port);

        std::string typ;
        iss >> typ; // "typ"
        std::string type_str;
        iss >> type_str;
        if (type_str == "host") cand.type = CandidateType::Host;
        else if (type_str == "prflx") cand.type = CandidateType::PeerReflexive;
        else if (type_str == "srflx") cand.type = CandidateType::ServerReflexive;
        else if (type_str == "relay") cand.type = CandidateType::Relay;
        else throw std::runtime_error("Unknown candidate type in SDP");

        return cand;
    }
};

// Candidate Pair 상태 정의
enum class CandidatePairState {
    New,
    InProgress,
    Failed,
    Succeeded,
    Nominated
};

// Candidate Pair 구조체
struct CandidatePair {
    Candidate local_candidate;
    Candidate remote_candidate;
    uint64_t priority;

    // 생성자
    CandidatePair() = default;
    CandidatePair(const Candidate& local, const Candidate& remote)
        : local_candidate(local), remote_candidate(remote), priority(0) {}
};

// Check List Entry 구조체
struct CheckListEntry {
    CandidatePair pair;
    CandidatePairState state;
    bool is_nominated;
	uint32_t retry_count;

    CheckListEntry(const CandidatePair& cp)
        : pair(cp), state(CandidatePairState::New), is_nominated(false), retry_count(0) {}
};

// 콜백 typedefs
using StateCallback = std::function<void(IceConnectionState)>;
using CandidateCallback = std::function<void(const Candidate&)>;
using DataCallback = std::function<void(const std::vector<uint8_t>&, const asio::ip::udp::endpoint&)>;
using NominateCallback = std::function<void(const CandidatePair&)>;

// ICE-specific STUN Attributes
struct IceAttributes {
    std::string ufrag;
    std::string pwd;
    uint64_t tie_breaker;
    IceRole role;
};

// IceAgent 클래스 선언
class IceAgent : public std::enable_shared_from_this<IceAgent> {
public:
    IceAgent(asio::io_context& io_context, IceRole role, IceMode mode,
             const std::vector<std::string>& stun_servers, 
             const std::string& turn_server = "",
             const std::string& turn_username = "", 
             const std::string& turn_password = "",
             std::chrono::seconds connectivity_check_timeout = std::chrono::seconds(3),
             size_t connectivity_check_retries = 1);
    ~IceAgent();
    
    // 콜백 설정
    void set_on_state_change_callback(StateCallback callback);
    void set_candidate_callback(CandidateCallback callback);
    void set_data_callback(DataCallback callback);
    void set_nominate_callback(NominateCallback cb); // 추가됨
    void set_signaling_client(std::shared_ptr<SignalingClient> signaling_client);

    // 로그 레벨 설정
    void set_log_level(LogLevel level);

    // ICE 프로세스 시작
    void start();

    // 연결된 소켓을 통해 데이터 전송
    void send_data(const std::vector<uint8_t>& data);

private:
    // Member Variables
	asio::strand<asio::io_context::executor_type> strand_;
    asio::ip::udp::socket socket_;
    IceMode mode_;
    std::vector<std::string> stun_servers_;
    std::string turn_server_;
    std::string turn_username_;
    std::string turn_password_;
    std::atomic<IceConnectionState> current_state_;
    asio::steady_timer keep_alive_timer_;
    LogLevel log_level_;

    // 후보 리스트
    std::vector<Candidate> local_candidates_;
    std::vector<Candidate> remote_candidates_;

    // Check List
    std::vector<CheckListEntry> check_list_;

    // STUN 및 TURN 클라이언트
    std::vector<std::shared_ptr<StunClient>> stun_clients_;
    std::shared_ptr<TurnClient> turn_client_;

    // 신호 클라이언트
    std::shared_ptr<SignalingClient> signaling_client_;

    // 콜백들
    StateCallback state_callback_;
    CandidateCallback candidate_callback_;
    DataCallback data_callback_;
    NominateCallback nominate_callback_;

    // Candidate Pair 관리
    CandidatePair nominated_pair_;

    // ICE-specific attributes
    IceAttributes ice_attributes_;
	IceAttributes remote_ice_attributes_;

    // 타임아웃 및 재시도 설정 변수
    std::chrono::seconds connectivity_check_timeout_;
    size_t connectivity_check_retries_;

    // Private Methods
    bool transition_to_state(IceConnectionState new_state);
    asio::awaitable<void> gather_candidates(uint32_t attempts = 0);
    asio::awaitable<void> gather_local_candidates();
    asio::awaitable<void> gather_srflx_candidates();
    asio::awaitable<void> gather_relay_candidates();
    asio::awaitable<void> perform_connectivity_checks(uint32_t attempts = 0);
    asio::awaitable<void> perform_single_connectivity_check(CheckListEntry& entry);
    asio::awaitable<void> evaluate_connectivity_results();
    asio::awaitable<void> perform_keep_alive();
    asio::awaitable<void> perform_turn_refresh();
    asio::awaitable<void> start_data_receive();
    uint32_t calculate_priority(const Candidate& local) const;
    uint64_t calculate_priority_pair(const Candidate& local, const Candidate& remote) const;
    void sort_candidate_pairs();
    void log(LogLevel level, const std::string& message);
    void negotiate_role(uint64_t remote_tie_breaker);
    asio::awaitable<void> send_nominate(const CandidatePair& pair);
    asio::awaitable<void> add_remote_candidate(const std::vector<Candidate>& candidates); // 신호를 통해 수신된 원격 후보 추가
    asio::awaitable<void> handle_incoming_signaling_messages();
	asio::awaitable<void> handle_incoming_stun_messages();
	asio::awaitable<void> nominate_pair(CheckListEntry& entry);
	asio::awaitable<void> listen_for_binding_indications();
	asio::awaitable<void> handle_binding_indication(const StunMessage& msg, const asio::ip::udp::endpoint& sender);
};

#endif // ICE_AGENT_HPP
