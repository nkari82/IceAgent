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

// NAT 타입 정의
enum class NatType {
    Unknown,
    OpenInternet,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric
};

// 로그 레벨 정의
enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

// Candidate 구조체
struct Candidate {
    asio::ip::udp::endpoint endpoint;
    uint32_t priority;
    std::string type; // "host", "srflx", "relay"
    std::string foundation;
    int component_id;
    std::string transport;

    std::string to_sdp() const {
        // SDP 표현 구현
        // 예시: "a=candidate:1 1 UDP 2130706431 192.168.1.2 54400 typ host"
        std::ostringstream oss;
        oss << "candidate:" << foundation << " " << component_id << " " << transport << " " << priority << " "
            << endpoint.address().to_string() << " " << endpoint.port() << " typ " << type;
        return oss.str();
    }

    static Candidate from_sdp(const std::string& sdp) {
        // SDP 문자열로부터 파싱 구현
        // 예시 SDP 라인: "a=candidate:1 1 UDP 2130706431 192.168.1.2 54400 typ host"
        Candidate cand;
        std::istringstream iss(sdp);
        std::string prefix;
        iss >> prefix; // "candidate:1"
        size_t colon_pos = prefix.find(':');
        if (colon_pos != std::string::npos) {
            cand.foundation = prefix.substr(colon_pos + 1);
        }
        iss >> cand.component_id;
        iss >> cand.transport;
        iss >> cand.priority;
        std::string ip;
        uint16_t port;
        iss >> ip;
        iss >> port;
        asio::ip::address address = asio::ip::make_address(ip);
        cand.endpoint = asio::ip::udp::endpoint(address, port);
        std::string typ;
        iss >> typ; // "typ"
        iss >> cand.type;
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
    uint32_t priority;
    CandidatePairState state;
    bool is_nominated;

    // 생성자
    CandidatePair() = default;
    CandidatePair(const Candidate& local, const Candidate& remote)
        : local_candidate(local), remote_candidate(remote), priority(0), state(CandidatePairState::New), is_nominated(false) {}
};

// Check List Entry 구조체
struct CheckListEntry {
    CandidatePair pair;
    CandidatePairState state;
    bool is_nominated;
    bool in_progress; // 추가됨

    CheckListEntry(const CandidatePair& cp)
        : pair(cp), state(CandidatePairState::New), is_nominated(false), in_progress(false) {}
};

// 콜백 typedefs
using StateCallback = std::function<void(IceConnectionState)>;
using CandidateCallback = std::function<void(const Candidate&)>;
using DataCallback = std::function<void(const std::vector<uint8_t>&, const asio::ip::udp::endpoint&)>;
using NatTypeCallback = std::function<void(NatType)>;
using NominateCallback = std::function<void(const CandidatePair&)>;

// ICE-specific STUN Attributes (예시)
struct IceAttributes {
    std::string username_fragment;
    std::string password;
    // 추가적인 ICE-specific attributes
};

// IceAgent 클래스 선언
class IceAgent : public std::enable_shared_from_this<IceAgent> {
public:
    IceAgent(asio::io_context& io_context, IceRole role, IceMode mode,
             const std::vector<std::string>& stun_servers, 
             const std::string& turn_server = "",
             const std::string& turn_username = "", 
             const std::string& turn_password = "",
             std::chrono::seconds candidate_gather_timeout = std::chrono::seconds(5),
             size_t candidate_gather_retries = 1,
             std::chrono::seconds connectivity_check_timeout = std::chrono::seconds(3),
             size_t connectivity_check_retries = 1);
    ~IceAgent();
    
    // 콜백 설정
    void set_on_state_change_callback(StateCallback callback);
    void set_candidate_callback(CandidateCallback callback);
    void set_data_callback(DataCallback callback);
    void set_nat_type_callback(NatTypeCallback cb);
    void set_nominate_callback(NominateCallback cb); // 추가됨
    void set_signaling_client(std::shared_ptr<SignalingClient> signaling_client);

    // 로그 레벨 설정
    void set_log_level(LogLevel level);

    // ICE 프로세스 시작
    asio::awaitable<void> start();

    // ICE 프로세스 재시작
    asio::awaitable<void> restart_ice();

    // 연결된 소켓을 통해 데이터 전송
    void send_data(const std::vector<uint8_t>& data);

    // 신호를 통해 수신된 원격 후보 추가
    void add_remote_candidate(const Candidate& candidate);

private:
    // Member Variables
    asio::io_context& io_context_;
    asio::ip::udp::socket socket_;
    IceRole role_;
    IceMode mode_;
    std::vector<std::string> stun_servers_;
    std::string turn_server_;
    std::string turn_username_;
    std::string turn_password_;
    IceConnectionState current_state_;
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
    NatTypeCallback on_nat_type_detected_;
    NominateCallback nominate_callback_; // 추가됨

    // Candidate Pair 관리
    CandidatePair nominated_pair_;
    bool connectivity_checks_running_;

    // ICE-specific attributes
    IceAttributes ice_attributes_;

    // 역할 협상
    IceRole remote_role_;

    // 타임아웃 및 재시도 설정 변수
    std::chrono::seconds candidate_gather_timeout_;
    size_t candidate_gather_retries_;
    std::chrono::seconds connectivity_check_timeout_;
    size_t connectivity_check_retries_;

    // Thread pool 관리
    std::vector<std::thread> thread_pool_;
    void initialize_thread_pool(size_t num_threads = std::thread::hardware_concurrency());

    // Private Methods
    bool transition_to_state(IceConnectionState new_state);
    asio::awaitable<NatType> detect_nat_type();
    asio::awaitable<void> gather_candidates(uint32_t attempts = 0);
    asio::awaitable<void> gather_local_candidates();
    asio::awaitable<void> gather_srflx_candidates();
    asio::awaitable<void> gather_relay_candidates();
    asio::awaitable<void> perform_connectivity_checks(uint32_t attempts = 0);
    asio::awaitable<void> perform_single_connectivity_check(CheckListEntry& entry);
    void evaluate_connectivity_results();
    asio::awaitable<void> perform_keep_alive();
    asio::awaitable<void> perform_turn_refresh();
    asio::awaitable<void> start_data_receive();
    NatType infer_nat_type(const std::vector<asio::ip::udp::endpoint>& mapped_endpoints);
    uint32_t calculate_priority(const Candidate& local, const Candidate& remote) const;
    void sort_candidate_pairs();
    void log(LogLevel level, const std::string& message);
    std::string nat_type_to_string(NatType nat_type) const;
    void negotiate_role(IceRole remote_role);
    asio::awaitable<void> send_nominate(const CandidatePair& pair);
    asio::awaitable<void> handle_incoming_signaling_messages();
    std::vector<uint8_t> generate_transaction_id();
	void nominate_pair(CheckListEntry& entry);
	asio::awaitable<void> IceAgent::handle_binding_indication(const StunMessage& msg, const asio::ip::udp::endpoint& sender);
};

#endif // ICE_AGENT_HPP
