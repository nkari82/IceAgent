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
#include "stun_client.hpp"
#include "turn_client.hpp"
#include "signaling_client.hpp"

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
    Failed,
    Frozen,    // 추가됨
    Paused     // 추가됨
};

enum class NatType {
    Unknown,
    OpenInternet,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric
};

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

// Candidate structure
struct Candidate {
    asio::ip::udp::endpoint endpoint;
    std::string type; // "host", "srflx", "relay"
    uint32_t priority;
    std::string foundation;
    int component_id;
    std::string transport;
};

// Enumerations for Candidate Pair State
enum class CandidatePairState {
    New,
    InProgress,
    Failed,
    Succeeded,
    Nominated
};

// Candidate Pair structure
struct CandidatePair {
    Candidate local_candidate;
    Candidate remote_candidate;
    uint32_t priority;
    CandidatePairState state;
    bool is_nominated;
    
    // Constructor
    CandidatePair() = default;
    CandidatePair(const Candidate& local, const Candidate& remote)
        : local_candidate(local), remote_candidate(remote), priority(0), state(CandidatePairState::New), is_nominated(false) {}
};

// Check List Entry 구조체
struct CheckListEntry {
    CandidatePair pair;
    CandidatePairState state;
    bool nominated;
    
    CheckListEntry(const CandidatePair& cp)
        : pair(cp), state(CandidatePairState::New), nominated(false) {}
};

// Callback typedefs
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

// Maximum concurrent connectivity checks
constexpr size_t MAX_CONCURRENT_CHECKS = 5;

// Number of ICE components (예: RTP, RTCP)
constexpr int NUM_COMPONENTS = 2;

// IceAgent 클래스 정의
class IceAgent : public std::enable_shared_from_this<IceAgent> {
public:
    IceAgent(asio::io_context& io_context, IceRole role, IceMode mode,
             const std::vector<std::string>& stun_servers, 
             const std::string& turn_server = "",
             const std::string& turn_username = "", 
             const std::string& turn_password = "");

    // Setters for callbacks
    void set_on_state_change_callback(StateCallback callback);
    void set_candidate_callback(CandidateCallback callback);
    void set_data_callback(DataCallback callback);
    void set_nat_type_callback(NatTypeCallback cb);
    void set_nominate_callback(NominateCallback cb); // 추가됨
    void set_signaling_client(std::shared_ptr<SignalingClient> signaling_client);

    // Set log level
    void set_log_level(LogLevel level);

    // Start ICE process
    asio::awaitable<void> start();

    // Restart ICE process
    asio::awaitable<void> restart_ice();

    // Send data over established connection
    void send_data(const std::vector<uint8_t>& data);

    // Add remote candidate received via signaling
    void add_remote_candidate(const Candidate& candidate);

private:
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

    // Candidates
    std::vector<Candidate> local_candidates_;
    std::vector<Candidate> remote_candidates_;
    std::vector<CandidatePair> candidate_pairs_;

    // Check List
    std::vector<CheckListEntry> check_list_;
    std::mutex check_list_mutex_;

    // STUN and TURN clients
    std::vector<std::shared_ptr<StunClient>> stun_clients_;
    std::shared_ptr<TurnClient> turn_client_;

    // Signaling client
    std::shared_ptr<SignalingClient> signaling_client_;

    // Callbacks
    StateCallback state_callback_;
    CandidateCallback candidate_callback_;
    DataCallback data_callback_;
    NatTypeCallback on_nat_type_detected_;
    NominateCallback nominate_callback_; // 추가됨

    // Candidate Pair Management
    CandidatePair nominated_pair_;
    bool connectivity_checks_running_;

    // ICE-specific attributes
    IceAttributes ice_attributes_;

    // Private Methods
    bool transition_to_state(IceConnectionState new_state);
    asio::awaitable<NatType> detect_nat_type();
    asio::awaitable<void> gather_candidates();
    asio::awaitable<void> gather_local_candidates();
    asio::awaitable<void> gather_host_candidates();
    asio::awaitable<void> gather_srflx_candidates();
    asio::awaitable<void> gather_relay_candidates();
    asio::awaitable<void> perform_connectivity_checks();
    asio::awaitable<void> perform_single_connectivity_check(CheckListEntry& entry);
    void evaluate_connectivity_results();
    asio::awaitable<void> perform_keep_alive();
    asio::awaitable<void> perform_turn_refresh();
    asio::awaitable<void> start_data_receive();
    NatType infer_nat_type(const std::vector<asio::ip::udp::endpoint>& mapped_endpoints);
    uint64_t calculate_priority(const Candidate& local, const Candidate& remote) const;
    void sort_candidate_pairs();
    void log(LogLevel level, const std::string& message);
    std::string nat_type_to_string(NatType nat_type) const;

    // Nomination methods
    void nominate_pair(CheckListEntry& entry);
    asio::awaitable<void> send_nominate(const CandidatePair& pair);

    // ICE Restart methods
    void initiate_ice_restart();
    asio::awaitable<void> handle_incoming_signaling_messages();
    std::vector<Candidate> parse_candidates_from_message(const std::string& message);
};

#endif // ICE_AGENT_HPP
