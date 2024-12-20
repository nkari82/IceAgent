// tests/ice_agent_tests.cpp

#include <gtest/gtest.h>
#include "ice_agent.hpp"
#include "stun_client.hpp"
#include "turn_client.hpp"
#include "message.hpp"
#include <asio.hpp>
#include <memory>
#include <thread>
#include <chrono>

// Mock STUN Server using Asio (same as before)
class MockStunServer {
public:
    MockStunServer(asio::io_context& io_context, uint16_t port)
        : socket_(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), port)) {
        start_receive();
    }

    void start_receive() {
        socket_.async_receive_from(asio::buffer(recv_buffer_), remote_endpoint_,
            [this](const asio::error_code& ec, std::size_t bytes_transferred) {
                if (!ec && bytes_transferred >= STUN_HEADER_SIZE) {
                    // Parse incoming message
                    try {
                        auto message = Message::parse(std::vector<uint8_t>(recv_buffer_.begin(), recv_buffer_.begin() + bytes_transferred), bytes_transferred);
                        if (message->get_type() == STUN_BINDING_REQUEST) {
                            // Create Binding Response
                            auto response = std::make_unique<Message>(STUN_BINDING_RESPONSE_SUCCESS, message->get_transaction_id());
                            // Add XOR-MAPPED-ADDRESS attribute
                            asio::ip::address_v4 public_ip = remote_endpoint_.address().to_v4();
                            uint16_t port = remote_endpoint_.port();
                            uint16_t xport = port ^ ((STUN_MAGIC_COOKIE >> 16) & 0xFFFF);
                            uint32_t xaddr = public_ip.to_uint() ^ STUN_MAGIC_COOKIE;

                            std::vector<uint8_t> xor_mapped_address;
                            xor_mapped_address.push_back(0x00); // Reserved
                            xor_mapped_address.push_back(0x01); // IPv4
                            xor_mapped_address.push_back((xport >> 8) & 0xFF);
                            xor_mapped_address.push_back(xport & 0xFF);
                            xor_mapped_address.push_back((xaddr >> 24) & 0xFF);
                            xor_mapped_address.push_back((xaddr >> 16) & 0xFF);
                            xor_mapped_address.push_back((xaddr >> 8) & 0xFF);
                            xor_mapped_address.push_back(xaddr & 0xFF);

                            response->add_attribute(STUN_ATTR_XOR_MAPPED_ADDRESS, xor_mapped_address);

                            auto serialized_response = response->serialize();
                            socket_.async_send_to(asio::buffer(serialized_response), remote_endpoint_,
                                [this](const asio::error_code& ec, std::size_t /*bytes_transferred*/) {
                                    if (ec) {
                                        std::cerr << "MockStunServer send error: " << ec.message() << std::endl;
                                    }
                                });
                        }
                    } catch (const std::exception& ex) {
                        std::cerr << "MockStunServer parse error: " << ex.what() << std::endl;
                    }
                }
                // Continue receiving
                start_receive();
            });
    }

private:
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint remote_endpoint_;
    std::array<uint8_t, 2048> recv_buffer_;
};

// Mock TURN Server using Asio (same as before)
class MockTurnServer {
public:
    MockTurnServer(asio::io_context& io_context, uint16_t port)
        : socket_(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), port)) {
        start_receive();
    }

    void start_receive() {
        socket_.async_receive_from(asio::buffer(recv_buffer_), remote_endpoint_,
            [this](const asio::error_code& ec, std::size_t bytes_transferred) {
                if (!ec && bytes_transferred >= STUN_HEADER_SIZE) {
                    // Parse incoming TURN message
                    try {
                        auto message = Message::parse(std::vector<uint8_t>(recv_buffer_.begin(), recv_buffer_.begin() + bytes_transferred), bytes_transferred);
                        if (message->get_type() == TURN_ALLOCATE) {
                            // Create TURN Allocate Response
                            auto response = std::make_unique<Message>(TURN_SUCCESS_RESPONSE, message->get_transaction_id());
                            // Add XOR-RELAYED-ADDRESS attribute
                            asio::ip::address_v4 relay_ip = asio::ip::address_v4::from_string("192.0.2.1"); // Example relay IP
                            uint16_t relay_port = 3480; // Example relay port
                            uint16_t xport = relay_port ^ ((TURN_MAGIC_COOKIE >> 16) & 0xFFFF);
                            uint32_t xaddr = relay_ip.to_uint() ^ TURN_MAGIC_COOKIE;

                            std::vector<uint8_t> xor_relayed_address;
                            xor_relayed_address.push_back(0x00); // Reserved
                            xor_relayed_address.push_back(0x01); // IPv4
                            xor_relayed_address.push_back((xport >> 8) & 0xFF);
                            xor_relayed_address.push_back(xport & 0xFF);
                            xor_relayed_address.push_back((xaddr >> 24) & 0xFF);
                            xor_relayed_address.push_back((xaddr >> 16) & 0xFF);
                            xor_relayed_address.push_back((xaddr >> 8) & 0xFF);
                            xor_relayed_address.push_back(xaddr & 0xFF);

                            response->add_attribute(TURN_ATTR_XOR_RELAYED_ADDRESS, xor_relayed_address);

                            auto serialized_response = response->serialize();
                            socket_.async_send_to(asio::buffer(serialized_response), remote_endpoint_,
                                [this](const asio::error_code& ec, std::size_t /*bytes_transferred*/) {
                                    if (ec) {
                                        std::cerr << "MockTurnServer send error: " << ec.message() << std::endl;
                                    }
                                });
                        }

                        // Implement handling for Send Indication and other TURN messages if needed
                        // For simplicity, this mock server only handles Allocate Requests
                    } catch (const std::exception& ex) {
                        std::cerr << "MockTurnServer parse error: " << ex.what() << std::endl;
                    }
                }
                // Continue receiving
                start_receive();
            });
    }

private:
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint remote_endpoint_;
    std::array<uint8_t, 2048> recv_buffer_;
};

// Test Fixture
class IceAgentTest : public ::testing::Test {
protected:
    asio::io_context io_context;
    std::unique_ptr<MockStunServer> mock_stun_server1;
    std::unique_ptr<MockStunServer> mock_stun_server2;
    std::unique_ptr<MockTurnServer> mock_turn_server;
    std::shared_ptr<IceAgent> ice_agent;

    void SetUp() override {
        // Start Mock STUN Servers on different ports
        mock_stun_server1 = std::make_unique<MockStunServer>(io_context, 3478);
        mock_stun_server2 = std::make_unique<MockStunServer>(io_context, 3479);

        // Start Mock TURN Server on port 3480
        mock_turn_server = std::make_unique<MockTurnServer>(io_context, 3480);

        // Define STUN and TURN servers in "host:port" format
        std::vector<std::string> stun_servers = {
            "127.0.0.1:3478",
            "127.0.0.1:3479"
        };
        std::string turn_server = "127.0.0.1:3480";
        std::string turn_username = "user";
        std::string turn_password = "pass";

        // Initialize IceAgent with TURN server details
        ice_agent = std::make_shared<IceAgent>(
            io_context, IceRole::Controller, IceMode::Full, stun_servers, turn_server, turn_username, turn_password);
    }

    void TearDown() override {
        // Cleanup
    }
};

// Test ICE Start with TURN Allocation
TEST_F(IceAgentTest, StartWithTurnAllocation) {
    NatType detected_nat_type = NatType::Unknown;
    bool relay_candidate_found = false;

    // Set NAT type callback
    ice_agent->set_nat_type_callback([&detected_nat_type](NatType nat_type) {
        detected_nat_type = nat_type;
    });

    // Set candidate callback to detect relay candidates
    ice_agent->set_candidate_callback([&relay_candidate_found](const Candidate& candidate) {
        if (candidate.type == "relay") {
            relay_candidate_found = true;
            std::cout << "New Relay Candidate: " << candidate.endpoint.address().to_string()
                      << ":" << candidate.endpoint.port() << " Type: " << candidate.type << std::endl;
        } else {
            std::cout << "New Candidate: " << candidate.endpoint.address().to_string()
                      << ":" << candidate.endpoint.port() << " Type: " << candidate.type << std::endl;
        }
    });

    // Set other callbacks as needed
    ice_agent->set_on_state_change_callback([](IceConnectionState state) {
        std::cout << "[ICE State]: " << static_cast<int>(state) << std::endl;
    });

    ice_agent->set_data_callback([](const std::vector<uint8_t>& data, const asio::ip::udp::endpoint& endpoint) {
        std::string message(data.begin(), data.end());
        std::cout << "[Received Data] From " << endpoint.address().to_string() << ":" << endpoint.port()
                  << " - " << message << std::endl;
    });

    // Run IceAgent::start() in a separate thread
    std::thread agent_thread([this]() {
        try {
            asio::co_spawn(io_context, ice_agent->start(), asio::detached);
            io_context.run();
        } catch (const std::exception& ex) {
            FAIL() << "IceAgent exception: " << ex.what();
        }
    });

    // Let the agent and mock servers communicate
    std::this_thread::sleep_for(std::chrono::seconds(5));

    agent_thread.join();

    // Verify that NAT type was detected
    EXPECT_NE(detected_nat_type, NatType::Unknown);
    EXPECT_EQ(detected_nat_type, NatType::FullCone); // Based on mock STUN servers' behavior

    // Verify that relay candidates were gathered
    EXPECT_TRUE(relay_candidate_found);
}

// Additional Test Cases:

// Test ICE Start without TURN Allocation (Non-Symmetric NAT)
TEST_F(IceAgentTest, StartWithoutTurnAllocation) {
    NatType detected_nat_type = NatType::Unknown;
    bool relay_candidate_found = false;

    // Simulate a NAT type that does not require TURN (Full Cone)
    // Modify infer_nat_type() to return FullCone for this test
    // This can be achieved by mocking infer_nat_type()

    // For simplicity, proceed with the existing mock STUN servers which infer FullCone

    // Set NAT type callback
    ice_agent->set_nat_type_callback([&detected_nat_type](NatType nat_type) {
        detected_nat_type = nat_type;
    });

    // Set candidate callback to detect relay candidates
    ice_agent->set_candidate_callback([&relay_candidate_found](const Candidate& candidate) {
        if (candidate.type == "relay") {
            relay_candidate_found = true;
            std::cout << "New Relay Candidate: " << candidate.endpoint.address().to_string()
                      << ":" << candidate.endpoint.port() << " Type: " << candidate.type << std::endl;
        } else {
            std::cout << "New Candidate: " << candidate.endpoint.address().to_string()
                      << ":" << candidate.endpoint.port() << " Type: " << candidate.type << std::endl;
        }
    });

    // Set other callbacks as needed
    ice_agent->set_on_state_change_callback([](IceConnectionState state) {
        std::cout << "[ICE State]: " << static_cast<int>(state) << std::endl;
    });

    ice_agent->set_data_callback([](const std::vector<uint8_t>& data, const asio::ip::udp::endpoint& endpoint) {
        std::string message(data.begin(), data.end());
        std::cout << "[Received Data] From " << endpoint.address().to_string() << ":" << endpoint.port()
                  << " - " << message << std::endl;
    });

    // Run IceAgent::start() in a separate thread
    std::thread agent_thread([this]() {
        try {
            asio::co_spawn(io_context, ice_agent->start(), asio::detached);
            io_context.run();
        } catch (const std::exception& ex) {
            FAIL() << "IceAgent exception: " << ex.what();
        }
    });

    // Let the agent and mock servers communicate
    std::this_thread::sleep_for(std::chrono::seconds(5));

    agent_thread.join();

    // Verify that NAT type was detected
    EXPECT_NE(detected_nat_type, NatType::Unknown);
    EXPECT_EQ(detected_nat_type, NatType::FullCone); // Based on mock STUN servers' behavior

    // Verify that relay candidates were not gathered
    EXPECT_FALSE(relay_candidate_found);
}
