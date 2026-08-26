add_executable(splithello_tests
    TestMain.cpp
    TestDiagnosis.cpp
    TestDnsMessage.cpp
    TestJson.cpp
    TestNetworkIdentity.cpp
    TestPacketStrategy.cpp
    TestQuicStrategy.cpp
    TestRecoveryPolicy.cpp
    TestStrategy.cpp
    TestTlsHello.cpp
    TestTransparentFlow.cpp
)

target_link_libraries(splithello_tests PRIVATE splithello_core)
target_include_directories(splithello_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME splithello_tests COMMAND splithello_tests)
