#include "Test.hpp"
#include "WsClient.hpp"
#include <condition_variable>
#include <mutex>
#include <thread>
#include <chrono>
#include <cstring>

namespace {
std::mutex mockMutex;
std::condition_variable mockReady;
bool receiving = false;
bool shutdownSent = false;
bool oversized = false;
unsigned closedHandles = 0;
unsigned gracefulCloses = 0;
template<class... A> HINTERNET mockOpen(A...) { return reinterpret_cast<HINTERNET>(1); }
template<class... A> HINTERNET mockConnect(A...) { return reinterpret_cast<HINTERNET>(2); }
template<class... A> HINTERNET mockRequest(A...) { return reinterpret_cast<HINTERNET>(3); }
template<class... A> HINTERNET mockUpgrade(A...) { return reinterpret_cast<HINTERNET>(4); }
template<class... A> BOOL mockOk(A...) { return TRUE; }
template<class... A> DWORD mockSend(A...) { return NO_ERROR; }
BOOL mockCloseHandle(HINTERNET) { ++closedHandles; return TRUE; }
BOOL mockHeaders(HINTERNET, DWORD, LPCWSTR, LPVOID buffer, LPDWORD, LPDWORD) {
    *static_cast<DWORD*>(buffer) = 101; return TRUE;
}
DWORD mockReceive(HINTERNET, PVOID buffer, DWORD length, DWORD* read,
                  WINHTTP_WEB_SOCKET_BUFFER_TYPE* type) {
    std::unique_lock lock(mockMutex);
    if (oversized) {
        std::memset(buffer, 0, length); *read = length;
        *type = WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE;
        return NO_ERROR;
    }
    receiving = true; mockReady.notify_all();
    if (!mockReady.wait_for(lock, std::chrono::seconds(2), [] { return shutdownSent; }))
        return ERROR_WINHTTP_TIMEOUT;
    *read = 0; *type = WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE;
    return NO_ERROR;
}
template<class... A> DWORD mockShutdown(A...) {
    std::lock_guard lock(mockMutex);
    shutdownSent = true; mockReady.notify_all(); return NO_ERROR;
}
template<class... A> DWORD mockGracefulClose(A...) { ++gracefulCloses; return NO_ERROR; }
void resetMock() {
    receiving = false; shutdownSent = false; oversized = false;
    closedHandles = 0; gracefulCloses = 0;
}
}
#define WinHttpOpen mockOpen
#define WinHttpConnect mockConnect
#define WinHttpOpenRequest mockRequest
#define WinHttpWebSocketCompleteUpgrade mockUpgrade
#define WinHttpCloseHandle mockCloseHandle
#define WinHttpSetTimeouts mockOk
#define WinHttpAddRequestHeaders mockOk
#define WinHttpSetOption mockOk
#define WinHttpSendRequest mockOk
#define WinHttpReceiveResponse mockOk
#define WinHttpQueryHeaders mockHeaders
#define WinHttpWebSocketSend mockSend
#define WinHttpWebSocketReceive mockReceive
#define WinHttpWebSocketShutdown mockShutdown
#define WinHttpWebSocketClose mockGracefulClose
#include "../src/WsClient.cpp"

TEST(websocket_shutdown_can_overlap_receive_without_closing_handle) {
    resetMock();
    bool entered = false;
    {
        WsClient client;
        CHECK(client.connect("ws://localhost/tunnel"));
        std::thread receiver([&]() { std::vector<uint8_t> bytes; bool text=false; client.receive(bytes, text); });
        {
            std::unique_lock lock(mockMutex);
            entered = mockReady.wait_for(lock, std::chrono::seconds(1), [] {return receiving;});
        }
        client.close();
        receiver.join();
        CHECK(entered);
        CHECK(shutdownSent);
        CHECK_EQ(gracefulCloses, 0U);
        CHECK_EQ(closedHandles, 1U); // only the completed HTTP upgrade request
        CHECK(!client.isConnected());
    }
    CHECK_EQ(closedHandles, 4U);
}

TEST(websocket_cancellation_before_connect_is_latched) {
    resetMock();
    WsClient client;
    client.close();
    CHECK(!client.connect("ws://localhost/tunnel"));
    CHECK_EQ(closedHandles, 0U);
}

TEST(websocket_fragment_stream_has_memory_limit) {
    resetMock(); oversized = true;
    WsClient client;
    CHECK(client.connect("ws://localhost/tunnel"));
    std::vector<uint8_t> bytes; bool text = false;
    CHECK_EQ(client.receive(bytes, text), -1);
    CHECK(bytes.size() <= 1024 * 1024);
}
