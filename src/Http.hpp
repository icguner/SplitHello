#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// Thin WinHTTP wrapper for the few HTTPS calls we make (Cloudflare API,
// Worker DNS lookups, deployment health check).
//
// Every request is made with WINHTTP_ACCESS_TYPE_NO_PROXY on purpose: this
// process *is* the system proxy, so honouring the system proxy setting would
// make it call itself.
namespace http {

struct Response {
    int status = 0;
    std::string body;
    bool ok() const { return status >= 200 && status < 300; }
    bool transportFailed() const { return status < 0; }
};

struct Request {
    std::string method = "GET";
    std::string host;                                            // "api.cloudflare.com"
    std::string path = "/";                                      // "/client/v4/user"
    std::vector<std::pair<std::string, std::string>> headers;    // name -> value
    std::string body;
    unsigned timeoutMs = 8000;
    uint16_t connectPort = 0;   // transport-only override; TLS/Host still use `host`
};

Response perform(const Request& request);

// Split "wss://name.subdomain.workers.dev/x" into its host part.
// Accepts ws/wss/http/https and bare hosts. Empty on failure.
std::string hostFromUrl(const std::string& url);

} // namespace http
