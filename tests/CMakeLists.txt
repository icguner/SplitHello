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
    TestStrategy.cpp
    TestTelemetry.cpp
    TestTlsHello.cpp
    TestWrangler.cpp
    TestWfpPacketCore.cpp
    ../driver/shared/PacketCore.cpp
)

target_link_libraries(splithello_tests PRIVATE splithello_core)
target_include_directories(splithello_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(splithello_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../driver/shared)

add_test(NAME splithello_tests COMMAND splithello_tests)
