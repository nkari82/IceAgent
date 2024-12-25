# CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(IceAgentProject)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
#set(SOURCES src/hmac_sha1.cpp src/crc32.cpp)


# Link Asio (Boost 없이 standalone Asio 사용 시)
target_include_directories(ice_agent_lib PRIVATE "include" "external/asio/asio/include")# Test executable
add_executable(test_ice_agent tests/test_ice_agent.cpp)


# Enable testing
enable_testing()

# Add test
#add_test(NAME TestIceAgent COMMAND test_ice_agent)
