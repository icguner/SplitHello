cmake_minimum_required(VERSION 3.20)
project(splithello_fuzz LANGUAGES CXX)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "SplitHello fuzz targets require Clang/libFuzzer")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(WIN32)
    # LLVM's Windows libFuzzer runtime does not support the dynamic MSVC CRT.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
    # The bundled libFuzzer runtime is built without MSVC STL container
    # annotations; keep the target ABI identical to avoid fail-if-mismatch.
    add_compile_definitions(_DISABLE_STRING_ANNOTATION _DISABLE_VECTOR_ANNOTATION)
endif()

add_library(splithello_fuzz_parsers STATIC
    ../src/DnsMessage.cpp
    ../src/TlsHello.cpp
)
target_include_directories(splithello_fuzz_parsers PUBLIC ../src)
if(WIN32)
    target_link_libraries(splithello_fuzz_parsers PUBLIC ws2_32)
endif()
target_compile_options(splithello_fuzz_parsers PRIVATE
    -O1
    -g
    -fno-omit-frame-pointer
    -fsanitize=address,fuzzer-no-link
    -Wall
    -Wextra
    -Wpedantic
)

function(add_splithello_fuzzer target source)
    add_executable(${target} ${source})
    target_include_directories(${target} PRIVATE ../src)
    target_link_libraries(${target} PRIVATE splithello_fuzz_parsers)
    target_compile_options(${target} PRIVATE
        -O1
        -g
        -fno-omit-frame-pointer
        -fsanitize=address,fuzzer
        -Wall
        -Wextra
        -Wpedantic
    )
    target_link_options(${target} PRIVATE -fsanitize=address,fuzzer)
endfunction()

add_splithello_fuzzer(fuzz_tls FuzzTls.cpp)
add_splithello_fuzzer(fuzz_dns FuzzDns.cpp)
add_splithello_fuzzer(fuzz_json FuzzJson.cpp)
