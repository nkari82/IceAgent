# CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(IceAgentProject)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)



# Link Asio (Boost 없이 standalone Asio 사용 시)
include_directories(test_ice_agent PRIVATE include external/asio/asio/include)# Test executable
add_executable(test_ice_agent tests/ice_agent_tests.cpp)


# Enable testing
#enable_testing()

# Add test
#add_test(NAME TestIceAgent COMMAND test_ice_agent)
