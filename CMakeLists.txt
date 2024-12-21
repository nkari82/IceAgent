# CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(IceAgentProject)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Asio
find_package(Asio REQUIRED)

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/ice_agent.cpp
    src/stun_message.cpp
    src/stun_client.cpp
    src/turn_client.cpp
    src/signaling_client.cpp
    src/hmac_sha1.cpp
    src/crc32.cpp
)

# Library
add_library(ice_agent_lib ${SOURCES})

# Link Asio (Boost 없이 standalone Asio 사용 시)
target_include_directories(ice_agent_lib PRIVATE ${ASIO_INCLUDE_DIRS})
target_link_libraries(ice_agent_lib PRIVATE Asio::asio)

# Test executable
add_executable(test_ice_agent test/test_ice_agent.cpp)
target_link_libraries(test_ice_agent PRIVATE ice_agent_lib)

# Enable testing
enable_testing()

# Add test
add_test(NAME TestIceAgent COMMAND test_ice_agent)
