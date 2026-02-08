cmake_minimum_required(VERSION 3.20)
project(splithello LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Fetch spdlog
include(FetchContent)
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.15.0
)
FetchContent_MakeAvailable(spdlog)

add_executable(splithello
    src/main.cpp
    src/SocksProxy.cpp
    src/WsClient.cpp
    src/Relay.cpp
    src/DirectRelay.cpp
    src/Config.cpp
    src/Setup.cpp
    src/SystemProxy.cpp
)

target_include_directories(splithello PRIVATE src)
target_link_libraries(splithello PRIVATE
    spdlog::spdlog
    ws2_32
    winhttp
    wininet
)
