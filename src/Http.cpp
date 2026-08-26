#include "Http.hpp"

#include <spdlog/spdlog.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

namespace http {
namespace {

std::wstring toWide(const std::string& s) {
    if (s.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring wide((size_t)size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), wide.data(), size);
    return wide;
}

// RAII for the handle chain so every early return closes what it opened.
class Handle {
public:
    explicit Handle(HINTERNET handle = nullptr) : handle_(handle) {}
    ~Handle() { if (handle_) WinHttpCloseHandle(handle_); }

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    Handle& operator=(HINTERNET handle) {
        if (handle_) WinHttpCloseHandle(handle_);
        handle_ = handle;
        return *this;
    }

    operator HINTERNET() const { return handle_; }
    explicit operator bool() const { return handle_ != nullptr; }

private:
    HINTERNET handle_;
};

} // namespace

Response perform(const Request& request) {
    Response response;
    response.status = -1;

    if (request.host.empty()) return response;

    Handle session(WinHttpOpen(L"SplitHello/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) {
        spdlog::error("WinHttpOpen hatasi: {}", GetLastError());
        return response;
    }

    const DWORD timeout = request.timeoutMs;
    WinHttpSetTimeouts(session, (int)timeout, (int)timeout, (int)timeout, (int)timeout);

    const INTERNET_PORT connectPort = request.connectPort == 0
        ? INTERNET_DEFAULT_HTTPS_PORT : request.connectPort;
    Handle connection(WinHttpConnect(session, toWide(request.host).c_str(), connectPort, 0));
    if (!connection) {
        spdlog::error("WinHttpConnect hatasi ({}): {}", request.host, GetLastError());
        return response;
    }

    Handle handle(WinHttpOpenRequest(connection, toWide(request.method).c_str(),
                                     toWide(request.path).c_str(), nullptr,
                                     WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     WINHTTP_FLAG_SECURE));
    if (!handle) {
        spdlog::error("WinHttpOpenRequest hatasi: {}", GetLastError());
        return response;
    }

    if (request.connectPort != 0 && request.connectPort != INTERNET_DEFAULT_HTTPS_PORT) {
        const std::wstring hostHeader = toWide("Host: " + request.host);
        WinHttpAddRequestHeaders(handle, hostHeader.c_str(), (DWORD)-1,
                                 WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    for (const auto& [name, value] : request.headers) {
        const std::wstring line = toWide(name + ": " + value);
        WinHttpAddRequestHeaders(handle, line.c_str(), (DWORD)-1,
                                 WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    LPVOID bodyPtr = request.body.empty() ? WINHTTP_NO_REQUEST_DATA
                                          : (LPVOID)request.body.data();
    const DWORD bodyLength = (DWORD)request.body.size();

    if (!WinHttpSendRequest(handle, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            bodyPtr, bodyLength, bodyLength, 0)) {
        spdlog::error("WinHttpSendRequest hatasi: {}", GetLastError());
        return response;
    }

    if (!WinHttpReceiveResponse(handle, nullptr)) {
        spdlog::error("WinHttpReceiveResponse hatasi: {}", GetLastError());
        return response;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
                        WINHTTP_NO_HEADER_INDEX);
    response.status = (int)statusCode;

    // Cap the body: these endpoints return small JSON, anything larger is a
    // captive portal or an error page we have no use for.
    constexpr size_t kMaxBody = 256 * 1024;
    char buffer[8192];
    DWORD read = 0;
    while (WinHttpReadData(handle, buffer, sizeof(buffer), &read) && read > 0) {
        if (response.body.size() + read > kMaxBody) break;
        response.body.append(buffer, read);
    }

    return response;
}

std::string hostFromUrl(const std::string& url) {
    std::string rest = url;

    const size_t scheme = rest.find("://");
    if (scheme != std::string::npos) rest = rest.substr(scheme + 3);

    const size_t slash = rest.find('/');
    if (slash != std::string::npos) rest.resize(slash);

    const size_t colon = rest.find(':');
    if (colon != std::string::npos) rest.resize(colon);

    return rest;
}

} // namespace http
