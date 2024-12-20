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
    Symmetric,
    SymmetricUDPFirewall,
    SymmetricTCPFirewall,
    Unknown
};

// Candidate 구조체 정의
struct Candidate {
    asio::ip::udp::endpoint endpoint;
    uint64_t priority;
    std::string type;
    std::string foundation;
    int component_id;
    std::string transport;
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
	using NatTypeCallback = std::function<void(NatType)>;

	IceAgent(asio::io_context& io_context, 
			IceRole role, 
			IceMode mode,
            const std::vector<std::string>& stun_servers, 
			const std::string& turn_server, 
			const std::string& turn_username, 
			const std::string& turn_password);

    void set_on_state_change_callback(StateCallback callback);
    void set_candidate_callback(CandidateCallback callback);
    void set_data_callback(DataCallback callback);
    void set_log_level(LogLevel level);
	void set_nat_type_callback(NatTypeCallback cb);
    void set_signaling_client(std::shared_ptr<SignalingClient> signaling_client);

    void log(LogLevel level, const std::string& message);

    // NAT Type Detection
    awaitable<NatType> detect_nat_type();
	
    awaitable<void> start();
	
    void send_data(const std::vector<uint8_t>& data);
    void add_remote_candidate(const Candidate& candidate);
	
private:
    asio::io_context& io_context_;
    asio::ip::udp::socket socket_;
    IceRole role_;
	IceMode mode_;
	std::vector<std::string> stun_servers_;
    std::string turn_server_;
    IceConnectionState current_state_;
    asio::steady_timer keep_alive_timer_;
    std::vector<Candidate> local_candidates_;
    std::vector<Candidate> remote_candidates_;
    std::vector<CandidatePair> candidate_pairs_;
    CandidatePair selected_pair_;
    StateCallback state_callback_;
    CandidateCallback candidate_callback_;
    DataCallback data_callback_;
	NatTypeCallback on_nat_type_detected_;
    LogLevel log_level_;
    std::shared_ptr<SignalingClient> signaling_client_;
	std::vector<std::shared_ptr<StunClient>> stun_clients_;

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

	// TURN related
    awaitable<void> gather_relay_candidates(); // turn과 relay는 같은 것?
	
    // STUN Candidate 수집
    awaitable<void> gather_host_candidates();
	
	awaitable<void> gather_srflx_candidates();
	
    // Methods
    awaitable<void> gather_candidates();
	awaitable<void> perform_turn_refresh()
    awaitable<void> perform_connectivity_checks();
    awaitable<void> perform_keep_alive();
    awaitable<void> start_data_receive();

    // ICE Restart
    awaitable<void> restart_ice();

    // 시그널링 서버를 통해 Hole Punching 동기화 신호 전송
    void signal_ready_to_punch(const CandidatePair& pair);

	// NAT Type Detection Helpers
    NatType infer_nat_type(const std::vector<asio::ip::udp::endpoint>& mapped_endpoints);
};

#endif // ICE_AGENT_HPP
