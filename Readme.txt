# ICE Agent Documentation

## Overview

The ICE Agent is responsible for establishing peer-to-peer connections between two clients across various network topologies. It implements the ICE protocol as defined in [RFC 8445](https://tools.ietf.org/html/rfc8445).

## Components

- **IceAgent**: Core class managing the ICE process.
- **StunClient**: Handles communication with STUN servers.
- **TurnClient**: Handles communication with TURN servers.
- **SignalingClient**: Manages SDP exchange with the remote peer.
- **StunMessage**: Represents and processes STUN messages.

## ICE Process Flow

1. **Candidate Gathering**: Collect local, server reflexive, and relay candidates.
2. **Exchange of ICE Parameters**: Use signaling to exchange SDP containing ICE credentials and candidates.
3. **Connectivity Checks**: Perform STUN binding requests to verify connectivity between candidate pairs.
4. **Pair Nomination**: Select the best candidate pair for the connection.
5. **Establishment of the Connection**: Once a pair is nominated, the connection is established.

## Roles

- **Controller**: Initiates connectivity checks and nominates candidate pairs.
- **Controlled**: Responds to connectivity checks and accepts nominations.

## Testing

Refer to the `tests/` directory for unit and integration tests. Use Google Test to run the test suite.

## Dependencies

- **Asio**: Asynchronous networking library.
- **OpenSSL**: Provides cryptographic functions for HMAC-SHA1.
- **Google Test**: Testing framework.


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