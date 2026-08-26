cmake_minimum_required(VERSION 3.20)
project(splithello LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /utf-8)
endif()

# windows.h defines min/max macros that shadow std::min/std::max.
add_compile_definitions(NOMINMAX)

include(FetchContent)
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.15.0
)
FetchContent_MakeAvailable(spdlog)

# WinDivert ships signed WFP drivers and import libraries in its official
# binary archive. Pin both the version and archive hash so a build can never
# silently consume different driver bytes.
FetchContent_Declare(
    windivert
    URL      https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip
    URL_HASH SHA256=63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(windivert)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(WINDIVERT_ARCH_DIR x64)
    set(WINDIVERT_DRIVER WinDivert64.sys)
else()
    set(WINDIVERT_ARCH_DIR x86)
    set(WINDIVERT_DRIVER WinDivert32.sys)
endif()

add_library(windivert_import SHARED IMPORTED GLOBAL)
set_target_properties(windivert_import PROPERTIES
    IMPORTED_IMPLIB "${windivert_SOURCE_DIR}/${WINDIVERT_ARCH_DIR}/WinDivert.lib"
    IMPORTED_LOCATION "${windivert_SOURCE_DIR}/${WINDIVERT_ARCH_DIR}/WinDivert.dll"
    INTERFACE_INCLUDE_DIRECTORIES "${windivert_SOURCE_DIR}/include"
)

# ---- Worker source is embedded from worker/src/index.js at build time ----
# There is exactly one copy of the Worker in this repo. `wrangler deploy` and
# `splithello --setup` therefore always ship identical code.
set(WORKER_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/worker/src/index.js)
set(WORKER_HEADER ${CMAKE_CURRENT_BINARY_DIR}/generated/WorkerSource.g.hpp)

add_custom_command(
    OUTPUT ${WORKER_HEADER}
    COMMAND ${CMAKE_COMMAND}
            -DINPUT=${WORKER_SOURCE}
            -DOUTPUT=${WORKER_HEADER}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/EmbedWorker.cmake
    DEPENDS ${WORKER_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/EmbedWorker.cmake
    COMMENT "worker/src/index.js gomuluyor"
    VERBATIM
)

# ---- Core logic, shared by the executable and the tests ----
add_library(splithello_core STATIC
    src/Config.cpp
    src/Diagnosis.cpp
    src/Dns.cpp
    src/DnsMessage.cpp
    src/FileUtil.cpp
    src/Http.cpp
    src/NetworkIdentity.cpp
    src/PacketStrategy.cpp
    src/QuicStrategy.cpp
    src/RecoveryPolicy.cpp
    src/Secure.cpp
    src/Strategy.cpp
    src/SystemProxy.cpp
    src/TcpConnect.cpp
    src/TlsHello.cpp
    src/TransparentFlow.cpp
)

target_include_directories(splithello_core PUBLIC src)
target_link_libraries(splithello_core PUBLIC
    spdlog::spdlog
    ws2_32
    winhttp
    wininet
    crypt32
    bcrypt
    ole32
)

add_executable(splithello
    src/main.cpp
    src/DirectRelay.cpp
    src/Relay.cpp
    src/SocksProxy.cpp
    src/Setup.cpp
    src/TransparentDnsProxy.cpp
    src/TrayApp.cpp
    src/WinDivertInterceptor.cpp
    src/WsClient.cpp
    ${WORKER_HEADER}
)

target_include_directories(splithello PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(splithello PRIVATE splithello_core windivert_import shell32 advapi32)

add_custom_command(TARGET splithello POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${windivert_SOURCE_DIR}/${WINDIVERT_ARCH_DIR}/WinDivert.dll"
            "$<TARGET_FILE_DIR:splithello>/WinDivert.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${windivert_SOURCE_DIR}/${WINDIVERT_ARCH_DIR}/${WINDIVERT_DRIVER}"
            "$<TARGET_FILE_DIR:splithello>/${WINDIVERT_DRIVER}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${windivert_SOURCE_DIR}/LICENSE"
            "$<TARGET_FILE_DIR:splithello>/WinDivert-LICENSE.txt"
    COMMENT "WinDivert runtime ve imzali surucu kopyalaniyor"
)

enable_testing()
add_subdirectory(tests)
