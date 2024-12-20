# CMakeLists.txt

cmake_minimum_required(VERSION 3.14)
project(IceAgentProject)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Asio
find_package(Asio REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(include)
include_directories(external/websocketpp)
include_directories(external/nlohmann)

# Google Test 다운로드 및 추가
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/release-1.12.1.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

# Add executable
add_executable(ice_agent
    src/ice_agent.cpp
    src/signaling_client.cpp
    src/stun_client.cpp
    src/message.cpp        # Add Message class source
    src/main.cpp
)

# Link Asio and OpenSSL
if(OPENSSL_FOUND)
    target_include_directories(ice_agent PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(ice_agent PRIVATE Asio::asio  OpenSSL::SSL OpenSSL::Crypto)
else
	target_link_libraries(ice_agent PRIVATE Asio::asio)
endif()

# Add nlohmann/json as a header-only library
target_include_directories(ice_agent PRIVATE external/nlohmann/include)

# Add WebSocket++ as a header-only library
target_include_directories(ice_agent PRIVATE external/websocketpp)

# Define ASIO_STANDALONE if using standalone Asio
target_compile_definitions(ice_agent PRIVATE ASIO_STANDALONE)

# Enable coroutine support and threading
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines -pthread")

# Add test executable
add_executable(stun_client_tests
    tests/stun_client_tests.cpp
    src/stun_client.cpp
    src/message.cpp
)

target_link_libraries(stun_client_tests
    gtest_main
    Asio::asio
    OpenSSL::SSL
    OpenSSL::Crypto
)

include(GoogleTest)
gtest_discover_tests(stun_client_tests)