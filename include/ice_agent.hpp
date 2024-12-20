// include/ice_agent.hpp

#ifndef ICE_AGENT_HPP
#define ICE_AGENT_HPP

#include <asio.hpp>
#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <unordered_set>
#include "stun_client.hpp" // StunClient 포함
#include "message.hpp"     // Message 클래스 포함

// JSON 라이브러리 사용
using json = nlohmann::json;
typedef websocketpp::client<websocketpp::config::asio_client> WebSocketClient;

// 로그 레벨 정의
enum class LogLevel {
    INFO,
    WARNING,
    ERROR
};

// ICE 상태 정의
enum class IceConnectionState {
    New,
    Gathering,
    Checking,
    Connected,
    Disconnected,
    Failed,
    Reconnecting
};

// ICE 역할 정의
enum class IceRole {
    Controller,
    Controlled
};

enum class IceMode {
    Full,    // 기존 ICE
    Lite     // ICE Lite
};

// NAT 유형 정의
enum class NatType {
    Unknown,
    OpenInternet,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric
};

// Candidate 구조체 정의
struct Candidate {
    asio::ip::udp::endpoint endpoint;
    uint64_t priority;
    std::string type;
    std::string foundation;
    int component_id;
    std::string transport;
	double rtt = 0.0;
    int packet_loss = 0;
    double bandwidth = 0.0;
};

// Candidate Pair 상태 정의
enum class CandidatePairState {
    Waiting,
    InProgress,
    Succeeded,
    Failed
};

// CandidatePair 구조체 정의
struct CandidatePair {
    Candidate local_candidate;
    Candidate remote_candidate;
    uint64_t priority;
    CandidatePairState state = CandidatePairState::Waiting;
    bool is_nominated = false;
    int retry_count = 0; // 재시도 횟수
	double rtt; // RTT 측정 값
    int packet_loss; // 패킷 손실률
    double bandwidth; // 대역폭
    asio::steady_timer timeout_timer; // 타임아웃 타이머

    CandidatePair(asio::io_context& io_context)
        : timeout_timer(io_context) {}
};

// Forward 선언
class SignalingClient;

// IceAgent 클래스 정의
class IceAgent : public std::enable_shared_from_this<IceAgent> {
public:
    using StateCallback = std::function<void(IceConnectionState)>;
    using CandidateCallback = std::function<void(const Candidate&)>;
    using DataCallback = std::function<void(const std::vector<uint8_t>&, const asio::ip::udp::endpoint&)>;

	IceAgent(asio::io_context& io_context, IceRole role, IceMode mode,
             const std::string& stun_server1, const std::string& stun_server2, const std::string& turn_server);

    void set_on_state_change_callback(StateCallback callback);
    void set_candidate_callback(CandidateCallback callback);
    void set_data_callback(DataCallback callback);
    void set_log_level(LogLevel level);
    void set_signaling_client(std::shared_ptr<SignalingClient> signaling_client);

    void log(LogLevel level, const std::string& message);

    awaitable<void> start();
    void send_data(const std::vector<uint8_t>& data);
    void add_remote_candidate(const Candidate& candidate);
	
    // ICE Restart 관련
    void send_restart_signal();
    void on_receive_restart_signal();

private:
    asio::io_context& io_context_;
    asio::ip::udp::socket socket_;
    IceRole role_;
	IceMode mode_;
    std::string stun_server1_, stun_server2_, turn_server_;
    IceConnectionState current_state_;
    asio::steady_timer keep_alive_timer_;
    std::vector<Candidate> local_candidates_;
    std::vector<Candidate> remote_candidates_;
    std::vector<CandidatePair> candidate_pairs_;
    CandidatePair selected_pair_;
    StateCallback state_callback_;
    CandidateCallback candidate_callback_;
    DataCallback data_callback_;
    LogLevel log_level_;
    std::shared_ptr<SignalingClient> signaling_client_;
    std::shared_ptr<StunClient> stun_client_;
	
    // 재시도 및 타임아웃 설정
    int max_retries_ = 3;           // 최대 재시도 횟수
    int pair_timeout_seconds_ = 5;  // Candidate Pair 검증 타임아웃

    // 실패한 Pair 관리
    std::unordered_set<std::string> failed_pairs_;

    // 로그 레벨 문자열 변환
    std::string nat_type_to_string(NatType nat_type) const;

    // 우선순위 계산
    uint64_t calculate_priority(const Candidate& local, const Candidate& remote) const;

    // Candidate Pair 정렬
    void sort_candidate_pairs();

    // ICE 상태 전환
    bool transition_to_state(IceConnectionState new_state);

    // Candidate 수집
    awaitable<void> gather_candidates();

    // Local Candidate 수집
    awaitable<void> gather_local_candidates();

    // TURN Candidate 수집
    awaitable<void> gather_turn_candidates();

    // STUN Candidate 수집
    awaitable<void> gather_host_candidates();
	
    // TURN Allocate Request 생성
    std::vector<uint8_t> create_turn_allocate_request() const;

    // TURN Allocate Response 파싱
    Candidate parse_turn_allocate_response(const std::vector<uint8_t>& response, size_t length) const;

    // STUN Binding Request 생성
    std::vector<uint8_t> create_stun_binding_request(const CandidatePair& pair) const;

    // STUN Binding Response 파싱
    asio::ip::udp::endpoint parse_stun_binding_response(const std::vector<uint8_t>& response, size_t length) const;

    // NAT 유형 탐지
    NatType detect_nat_type();

    // NAT 우회 전략 적용
    awaitable<void> apply_nat_traversal_strategy(NatType nat_type);

    // Methods
    awaitable<void> gather_candidates();
    awaitable<void> connectivity_check();

    awaitable<void> keep_alive();
    awaitable<void> start_data_receive();

    // ICE Restart
    awaitable<void> restart_ice();

    // 시그널링 서버를 통해 Hole Punching 동기화 신호 전송
    void signal_ready_to_punch(const CandidatePair& pair);

    // 검증 및 전략 통합 함수
    awaitable<void> validate_pair_with_strategy(CandidatePair& pair, std::function<std::vector<uint8_t>(const CandidatePair&)> create_request);

    // NAT Traversal 전략 함수
    awaitable<void> udp_hole_punching();
    awaitable<void> direct_p2p_connection();
    awaitable<void> turn_relay_connection();
	
	// RTT 측정 관련
    awaitable<void> measure_rtt(CandidatePair& pair);
	
	// QoS 기반 우선순위 재조정
    void adjust_priority_based_on_qos();
};

#endif // ICE_AGENT_HPP
