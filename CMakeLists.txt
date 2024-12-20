# CMakeLists.txt

cmake_minimum_required(VERSION 3.14)
project(IceAgentProject)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Asio
find_package(Asio REQUIRED)

# Include directories
include_directories(include)
include_directories(external/websocketpp)
include_directories(external/nlohmann)

# Add executable
add_executable(ice_agent
    src/ice_agent.cpp
    src/signaling_client.cpp
    src/main.cpp
)

# Link Asio
target_link_libraries(ice_agent PRIVATE Asio::asio)

# Add nlohmann/json as a header-only library
target_include_directories(ice_agent PRIVATE external/nlohmann/include)

# Add WebSocket++ as a header-only library
target_include_directories(ice_agent PRIVATE external/websocketpp)

# Define ASIO_STANDALONE if using standalone Asio
target_compile_definitions(ice_agent PRIVATE ASIO_STANDALONE)

# Enable coroutine support
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines -pthread")
