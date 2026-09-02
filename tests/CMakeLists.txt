add_executable(splithello_tests
    TestMain.cpp
    TestDiagnosis.cpp
    TestDnsMessage.cpp
    TestJson.cpp
    TestLiveStats.cpp
    TestNetworkIdentity.cpp
    TestPacketStrategy.cpp
    TestProcessFilter.cpp
    TestQuicStrategy.cpp
    TestRecoveryPolicy.cpp
    TestSocksProxy.cpp
    TestStrategy.cpp
    TestTelemetry.cpp
    TestTlsHello.cpp
    TestTransparentFlow.cpp
    TestWrangler.cpp
)

target_link_libraries(splithello_tests PRIVATE splithello_core)
target_include_directories(splithello_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME splithello_tests COMMAND splithello_tests)
