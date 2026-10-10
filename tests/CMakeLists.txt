add_executable(splithello_tests
    TestMain.cpp
    TestWsLifecycle.cpp
    TestCommandLine.cpp
    TestConfig.cpp
    TestWinDivertPacket.cpp
    TestWinDivertLifecycle.cpp
    TestDnsLifecycle.cpp
    ../src/TransparentDnsProxy.cpp
    TestDiagnosis.cpp
    TestDnsMessage.cpp
    TestDnsResolver.cpp
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

target_link_libraries(splithello_tests PRIVATE splithello_core splithello_packet shell32)
target_include_directories(splithello_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME splithello_tests COMMAND splithello_tests)

add_custom_command(TARGET splithello_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:windivert_import>" "$<TARGET_FILE_DIR:splithello_tests>"
)
set_tests_properties(splithello_tests PROPERTIES TIMEOUT 120)
