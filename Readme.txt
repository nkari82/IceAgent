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
