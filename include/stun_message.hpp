// include/stun_message.hpp

#ifndef STUN_MESSAGE_HPP
#define STUN_MESSAGE_HPP

#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <stdexcept>
#include <random>
#include <algorithm>
#include "hmac_sha1.hpp" // HMAC-SHA1 구현체
#include "crc32.hpp"      // CRC32 구현체

enum StunMessageType {
    STUN_BINDING_REQUEST = 0x0001,
    STUN_BINDING_RESPONSE_SUCCESS = 0x0101,
    STUN_BINDING_RESPONSE_ERROR = 0x0111,
    STUN_BINDING_INDICATION = 0x0011
    // 추가적인 STUN 메시지 타입 정의
	// 0x003  :  Allocate          (only request/response semantics defined)
    // 0x004  :  Refresh           (only request/response semantics defined)
    // 0x006  :  Send              (only indication semantics defined)
    // 0x007  :  Data              (only indication semantics defined)
    // 0x008  :  CreatePermission  (only request/response semantics defined
    // 0x009  :  ChannelBind       (only request/response semantics defined)
};

기본 STUN 속성 (RFC 5389)
MAPPED-ADDRESS	0x0001	클라이언트의 공인 IP 주소와 포트
USERNAME	0x0006	인증에 사용되는 사용자 이름
MESSAGE-INTEGRITY	0x0008	HMAC-SHA1을 사용한 메시지 무결성 확인
ERROR-CODE	0x0009	오류 코드와 오류 메시지
UNKNOWN-ATTRIBUTES	0x000A	알 수 없는 속성의 목록
REALM	0x0014	인증 영역 (Realm) 정보
NONCE	0x0015	인증을 위한 난수
XOR-MAPPED-ADDRESS	0x0020	XOR 암호화된 공인 IP 주소와 포트
SOFTWARE	0x8022	클라이언트/서버 소프트웨어 정보
ALTERNATE-SERVER	0x8023	대체 서버의 주소 정보
FINGERPRINT	0x8028	메시지의 무결성 검사를 위한 CRC32 값

TURN 확장 속성 (RFC 5766)
CHANNEL-NUMBER	0x000C	TURN 데이터 채널 번호
LIFETIME	0x000D	TURN 릴레이 주소의 유효 시간 (초 단위)
XOR-PEER-ADDRESS	0x0012	XOR 암호화된 피어 주소
DATA	0x0013	TURN 송신 또는 수신 데이터
REQUESTED-ADDRESS-FAMILY	0x0017	요청된 주소 패밀리 (IPv4 또는 IPv6)
EVEN-PORT	0x0018	짝수 포트 요청
REQUESTED-TRANSPORT	0x0019	TURN에서 사용할 전송 프로토콜 (UDP, TCP 등)
DONT-FRAGMENT	0x001A	패킷 분할 방지
RESERVATION-TOKEN	0x0022	TURN 포트 예약 토큰
XOR-RELAYED-ADDRESS	0x0016	XOR 암호화된 TURN 릴레이 주소

ICE (Interactive Connectivity Establishment) 관련 속성
PRIORITY	0x0024	ICE 연결 우선 순위 정보
USE-CANDIDATE	0x0025	특정 후보(candidate)를 사용하겠다는 신호
ICE-CONTROLLED	0x8029	제어 상태가 "제어됨"임을 나타냄
ICE-CONTROLLING	0x802A	제어 상태가 "제어 중"임을 나타냄

// Attribute Types
enum StunAttributeType {
	STUN_ATTR_USERNAME = 0x0006;
	STUN_ATTR_PASSWORD = 0x0007;
	STUN_ATTR_MESSAGE_INTEGRITY = 0x0008;
	STUN_ATTR_FINGERPRINT = 0x8028;
	STUN_ATTR_USE_CANDIDATE = 0x000C; // 0x0011
	STUN_ATTR_PRIORITY = 0x0024;
	STUN_ATTR_ICE_CONTROLLING = 0x802A; // 0x8029
	STUN_ATTR_ICE_CONTROLLED = 0x802B;
	STUN_ATTR_MAPPED_ADDRESS = 0x0001;
	 // 0x000C: CHANNEL-NUMBER
     // 0x000D: LIFETIME
     // 0x0010: Reserved (was BANDWIDTH)
     // 0x0012: XOR-PEER-ADDRESS
     // 0x0013: DATA
     // 0x0016: XOR-RELAYED-ADDRESS
     // 0x0018: EVEN-PORT
     // 0x0019: REQUESTED-TRANSPORT
     // 0x001A: DONT-FRAGMENT
     // 0x0021: Reserved (was TIMER-VAL)
     // 0x0022: RESERVATION-TOKEN
}

struct StunAttribute {
    uint16_t type;
    std::vector<uint8_t> value;
};

class StunMessage {
public:
    StunMessage(StunMessageType type, const std::vector<uint8_t>& transaction_id);
    StunMessageType get_type() const;
    std::vector<uint8_t> get_transaction_id() const;
    
    void add_attribute(StunAttributeType attr, const std::string& value);
    void add_attribute(StunAttributeType attr, const std::vector<uint8_t>& value);
    void add_message_integrity(const std::string& key);
    void add_fingerprint();
    
    std::vector<uint8_t> serialize() const;
    std::vector<uint8_t> serialize_without_attributes(const std::vector<std::string>& exclude_attributes) const;
    
    static StunMessage parse(const std::vector<uint8_t>& data);
    
    bool verify_message_integrity(const std::string& key) const;
    bool verify_fingerprint() const;
    
    bool has_attribute(StunAttributeType attr) const;
    std::string get_attribute(StunAttributeType attr) const;
    
    static std::vector<uint8_t> generate_transaction_id();
    
private:
    StunMessageType type_;
    std::vector<uint8_t> transaction_id_;
    std::unordered_map<uint16_t, std::vector<uint8_t>> attributes_;
    
    // Helper methods for parsing and serialization
    void parse_attributes(const std::vector<uint8_t>& data);
    std::vector<uint8_t> calculate_fingerprint() const;
};

#endif // STUN_MESSAGE_HPP
