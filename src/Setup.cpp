#include "Setup.hpp"
#include <spdlog/spdlog.h>

#include <iostream>
#include <string>
#include <vector>
#include <format>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <shellapi.h>

#pragma comment(lib, "winhttp.lib")

// ---------- Embedded worker code ----------

static const char* WORKER_JS = R"(
import { connect } from 'cloudflare:sockets';

const CF_IPV4 = [
  '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22',
  '141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20',
  '197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13',
  '104.24.0.0/14','172.64.0.0/13','131.0.72.0/22'
];

function ipToInt(ip) {
  return ip.split('.').reduce((a, o) => (a << 8) + parseInt(o), 0) >>> 0;
}

function inCIDR(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const mask = ~(2 ** (32 - parseInt(bits)) - 1) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(range) & mask);
}

function isCfIP(ip) {
  return CF_IPV4.some(c => inCIDR(ip, c));
}

async function resolveHost(hostname) {
  try {
    const r = await fetch(`https://1.1.1.1/dns-query?name=${hostname}&type=A`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    const d = await r.json();
    if (d.Answer) return d.Answer.filter(a => a.type === 1).map(a => a.data);
  } catch {}
  return [];
}

function isIP(s) { return /^\d+\.\d+\.\d+\.\d+$/.test(s); }

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/" || url.pathname === "/health") {
      return new Response("SplitHello Relay OK", { status: 200 });
    }

    if (url.pathname === "/resolve") {
      const host = url.searchParams.get("host");
      if (!host) return new Response(JSON.stringify({error:"missing host"}), {status:400, headers:{"Content-Type":"application/json"}});
      const ips = await resolveHost(host);
      if (ips.length > 0) return new Response(JSON.stringify({ip:ips[0]}), {headers:{"Content-Type":"application/json"}});
      return new Response(JSON.stringify({error:"no A records"}), {status:404, headers:{"Content-Type":"application/json"}});
    }

    if (url.pathname !== "/tunnel") {
      return new Response("Not Found", { status: 404 });
    }

    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected WebSocket", { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    let targetSocket = null;
    let targetWriter = null;

    server.addEventListener("message", async (event) => {
      try {
        if (!targetSocket) {
          const cmd = JSON.parse(event.data);

          if (cmd.cmd !== "connect" || !cmd.host || !cmd.port) {
            server.send(JSON.stringify({ status: "error", msg: "Invalid command" }));
            server.close(1008, "Invalid command");
            return;
          }

          let connectHost = cmd.host;
          let connectPort = cmd.port;
          let useRelay = false;

          // Check if target is on Cloudflare's network
          let ip = isIP(cmd.host) ? cmd.host : null;
          if (!ip) {
            const ips = await resolveHost(cmd.host);
            if (ips.length > 0) ip = ips[0];
          }

          if (ip && isCfIP(ip) && cmd.relay) {
            // Route through external relay
            const [rHost, rPort] = cmd.relay.split(':');
            connectHost = rHost;
            connectPort = parseInt(rPort) || 6666;
            useRelay = true;
          }

          targetSocket = connect({ hostname: connectHost, port: connectPort });
          targetWriter = targetSocket.writable.getWriter();

          // If using relay, send metadata header first
          if (useRelay) {
            const meta = `tcp@${cmd.host}$${cmd.port}\r\n`;
            await targetWriter.write(new TextEncoder().encode(meta));
          }

          // Pipe target -> client
          const reader = targetSocket.readable.getReader();
          (async () => {
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                if (server.readyState === 1) server.send(value);
                else break;
              }
            } catch (e) {
              try { server.send(JSON.stringify({ status: "error", msg: "target: " + e.message })); } catch {}
            } finally {
              try { server.close(1000, "Target closed"); } catch {}
            }
          })();

          server.send(JSON.stringify({
            status: "connected",
            relay: useRelay,
            resolvedIP: ip || "unresolved"
          }));
        } else {
          const data = typeof event.data === "string"
            ? new TextEncoder().encode(event.data)
            : event.data;
          await targetWriter.write(data);
        }
      } catch (e) {
        try {
          server.send(JSON.stringify({ status: "error", msg: e.message }));
          server.close(1011, "Internal error");
        } catch {}
      }
    });

    server.addEventListener("close", () => {
      if (targetWriter) try { targetWriter.close(); } catch {}
    });

    server.addEventListener("error", () => {
      if (targetWriter) try { targetWriter.close(); } catch {}
    });

    return new Response(null, { status: 101, webSocket: client });
  },
};
)";

// ---------- Minimal JSON helpers for API responses ----------

namespace json {
    static std::string getString(const std::string& data, const std::string& key) {
        std::string needle = "\"" + key + "\"";
        auto pos = data.find(needle);
        if (pos == std::string::npos) return {};

        pos += needle.size();
        while (pos < data.size() && (data[pos] == ' ' || data[pos] == ':' || data[pos] == '\t'))
            pos++;

        if (pos >= data.size() || data[pos] != '"') return {};
        pos++;

        std::string result;
        while (pos < data.size() && data[pos] != '"') {
            if (data[pos] == '\\' && pos + 1 < data.size()) pos++;
            result += data[pos++];
        }
        return result;
    }

    static bool getBool(const std::string& data, const std::string& key) {
        std::string needle = "\"" + key + "\"";
        auto pos = data.find(needle);
        if (pos == std::string::npos) return false;
        pos += needle.size();
        while (pos < data.size() && (data[pos] == ' ' || data[pos] == ':')) pos++;
        return (pos + 4 <= data.size() && data.substr(pos, 4) == "true");
    }

    // Get content starting after a key's colon (for nested extraction)
    static std::string getAfter(const std::string& data, const std::string& key) {
        std::string needle = "\"" + key + "\"";
        auto pos = data.find(needle);
        if (pos == std::string::npos) return {};
        pos += needle.size();
        while (pos < data.size() && (data[pos] == ' ' || data[pos] == ':')) pos++;
        return data.substr(pos);
    }
}

// ---------- WinHTTP-based Cloudflare API client ----------

struct ApiResponse {
    int status = 0;
    std::string body;
    bool ok() const { return status >= 200 && status < 300; }
};

class CloudflareApi {
public:
    explicit CloudflareApi(const std::string& token) {
        authHeader_ = L"Authorization: Bearer " + toWide(token);

        session_ = WinHttpOpen(L"SplitHello/1.0",
                               WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME,
                               WINHTTP_NO_PROXY_BYPASS, 0);
        if (session_) {
            connect_ = WinHttpConnect(session_, L"api.cloudflare.com",
                                      INTERNET_DEFAULT_HTTPS_PORT, 0);
        }
    }

    ~CloudflareApi() {
        if (connect_) WinHttpCloseHandle(connect_);
        if (session_) WinHttpCloseHandle(session_);
    }

    bool isReady() const { return session_ && connect_; }

    // GET /client/v4/user/tokens/verify
    bool verifyToken() {
        auto resp = request(L"GET", L"/client/v4/user/tokens/verify");
        if (!resp.ok()) {
            spdlog::error("Token verification failed (HTTP {})", resp.status);
            return false;
        }
        return json::getBool(resp.body, "success");
    }

    // GET /client/v4/accounts -> first account's ID
    std::string getAccountId() {
        auto resp = request(L"GET", L"/client/v4/accounts");
        if (!resp.ok()) {
            spdlog::error("Failed to fetch accounts (HTTP {})", resp.status);
            return {};
        }
        // result is an array, extract first element's "id"
        std::string afterResult = json::getAfter(resp.body, "result");
        return json::getString(afterResult, "id");
    }

    // GET /client/v4/accounts/{id}/workers/subdomain
    std::string getSubdomain(const std::string& accountId) {
        std::wstring path = L"/client/v4/accounts/" + toWide(accountId) + L"/workers/subdomain";
        auto resp = request(L"GET", path.c_str());
        if (!resp.ok()) {
            spdlog::error("Failed to fetch subdomain (HTTP {})", resp.status);
            return {};
        }
        std::string afterResult = json::getAfter(resp.body, "result");
        return json::getString(afterResult, "subdomain");
    }

    // PUT /client/v4/accounts/{id}/workers/scripts/{name} (multipart ES module upload)
    bool deployWorker(const std::string& accountId, const std::string& scriptName) {
        std::wstring path = L"/client/v4/accounts/" + toWide(accountId)
                          + L"/workers/scripts/" + toWide(scriptName);

        // Build multipart form body
        const std::string boundary = "----SplitHelloBoundary";
        std::string body;

        // Part 1: metadata
        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"metadata\"; filename=\"metadata.json\"\r\n";
        body += "Content-Type: application/json\r\n\r\n";
        body += R"({"main_module":"index.js","compatibility_date":"2024-09-23","compatibility_flags":["nodejs_compat"]})";
        body += "\r\n";

        // Part 2: worker script
        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"index.js\"; filename=\"index.js\"\r\n";
        body += "Content-Type: application/javascript+module\r\n\r\n";
        body += WORKER_JS;
        body += "\r\n";

        body += "--" + boundary + "--\r\n";

        std::string contentType = "multipart/form-data; boundary=" + boundary;

        auto resp = request(L"PUT", path.c_str(), body, toWide(contentType));
        if (!resp.ok()) {
            spdlog::error("Worker deployment failed (HTTP {}): {}", resp.status, resp.body);
            return false;
        }
        return json::getBool(resp.body, "success");
    }

    // Enable workers.dev subdomain route for the script
    bool enableWorkerRoute(const std::string& accountId, const std::string& scriptName) {
        std::wstring path = L"/client/v4/accounts/" + toWide(accountId)
                          + L"/workers/scripts/" + toWide(scriptName) + L"/subdomain";

        std::string body = R"({"enabled":true})";
        auto resp = request(L"POST", path.c_str(), body, L"application/json");

        // 200 = OK, 409 = already enabled — both are fine
        if (resp.status == 200 || resp.status == 409) return true;

        spdlog::warn("Enable subdomain route returned HTTP {} (may already be enabled)", resp.status);
        return true; // non-fatal
    }

private:
    HINTERNET session_ = nullptr;
    HINTERNET connect_ = nullptr;
    std::wstring authHeader_;

    static std::wstring toWide(const std::string& s) {
        if (s.empty()) return {};
        int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
        std::wstring w(sz, 0);
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), sz);
        return w;
    }

    ApiResponse request(const wchar_t* method, const wchar_t* path,
                        const std::string& body = {},
                        const std::wstring& contentType = {}) {
        ApiResponse result;

        if (!connect_) { result.status = -1; return result; }

        HINTERNET req = WinHttpOpenRequest(connect_, method, path,
                                           nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           WINHTTP_FLAG_SECURE);
        if (!req) { result.status = -1; return result; }

        // Add auth header
        WinHttpAddRequestHeaders(req, authHeader_.c_str(), (DWORD)-1,
                                 WINHTTP_ADDREQ_FLAG_ADD);

        // Add content-type if provided
        if (!contentType.empty()) {
            std::wstring ctHeader = L"Content-Type: " + contentType;
            WinHttpAddRequestHeaders(req, ctHeader.c_str(), (DWORD)-1,
                                     WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
        }

        // Send
        LPVOID bodyPtr = body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data();
        DWORD bodyLen = (DWORD)body.size();

        if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                bodyPtr, bodyLen, bodyLen, 0)) {
            spdlog::error("WinHttpSendRequest failed: {}", GetLastError());
            WinHttpCloseHandle(req);
            result.status = -1;
            return result;
        }

        if (!WinHttpReceiveResponse(req, nullptr)) {
            spdlog::error("WinHttpReceiveResponse failed: {}", GetLastError());
            WinHttpCloseHandle(req);
            result.status = -1;
            return result;
        }

        // Status code
        DWORD statusCode = 0;
        DWORD scSize = sizeof(statusCode);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &scSize,
                            WINHTTP_NO_HEADER_INDEX);
        result.status = (int)statusCode;

        // Read body
        DWORD available = 0;
        do {
            WinHttpQueryDataAvailable(req, &available);
            if (available == 0) break;
            std::vector<char> buf(available);
            DWORD bytesRead = 0;
            WinHttpReadData(req, buf.data(), available, &bytesRead);
            result.body.append(buf.data(), bytesRead);
        } while (available > 0);

        WinHttpCloseHandle(req);
        return result;
    }
};

// ---------- Interactive setup ----------

static std::string maskToken(const std::string& token) {
    if (token.size() <= 8) return "****";
    return token.substr(0, 4) + "..." + token.substr(token.size() - 4);
}

bool runSetup(Config& config) {
    std::cout << "\n"
              << "=== SplitHello Setup ===\n\n"
              << "Cloudflare API token gerekiyor.\n"
              << "Tarayici aciliyor...\n\n"
              << "  Adilar:\n"
              << "  1. 'Create Token' tikla\n"
              << "  2. 'Edit Cloudflare Workers' sablonu -> 'Use template'\n"
              << "  3. 'Continue to summary' -> 'Create Token'\n"
              << "  4. Token'i kopyala\n\n";

    // Open browser to Cloudflare API tokens page
    ShellExecuteA(nullptr, "open",
                  "https://dash.cloudflare.com/profile/api-tokens",
                  nullptr, nullptr, SW_SHOWNORMAL);

    // Read token from user
    std::cout << "API Token: ";
    std::string token;
    std::getline(std::cin, token);

    // Trim whitespace
    while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) token.erase(0, 1);
    while (!token.empty() && (token.back() == ' ' || token.back() == '\t' || token.back() == '\n' || token.back() == '\r')) token.pop_back();

    if (token.empty()) {
        std::cerr << "Token bos. Setup iptal edildi.\n";
        return false;
    }

    std::cout << "Token: " << maskToken(token) << "\n\n";

    CloudflareApi api(token);
    if (!api.isReady()) {
        std::cerr << "HTTP client baslatma hatasi.\n";
        return false;
    }

    // Step 1: Verify token
    std::cout << "[1/5] Token dogrulaniyor... ";
    if (!api.verifyToken()) {
        std::cout << "HATA\n";
        std::cerr << "Token gecersiz veya suresi dolmus.\n";
        return false;
    }
    std::cout << "OK\n";

    // Step 2: Get account ID
    std::cout << "[2/5] Hesap bilgileri aliniyor... ";
    std::string accountId = api.getAccountId();
    if (accountId.empty()) {
        std::cout << "HATA\n";
        std::cerr << "Hesap ID alinamadi. Token izinlerini kontrol edin.\n";
        return false;
    }
    std::cout << "OK (" << accountId.substr(0, 8) << "...)\n";

    // Step 3: Deploy worker
    std::string workerName = config.workerName.empty() ? "splithello-relay" : config.workerName;
    std::cout << "[3/5] Worker deploy ediliyor (" << workerName << ")... ";
    if (!api.deployWorker(accountId, workerName)) {
        std::cout << "HATA\n";
        std::cerr << "Worker deploy edilemedi.\n";
        return false;
    }
    std::cout << "OK\n";

    // Step 4: Enable workers.dev route
    std::cout << "[4/5] workers.dev route aktiflestiriliyor... ";
    api.enableWorkerRoute(accountId, workerName);
    std::cout << "OK\n";

    // Step 5: Get subdomain
    std::cout << "[5/5] Worker URL belirleniyor... ";
    std::string subdomain = api.getSubdomain(accountId);
    if (subdomain.empty()) {
        std::cout << "HATA\n";
        std::cerr << "\nworkers.dev subdomain bulunamadi.\n"
                  << "Cloudflare Dashboard > Workers & Pages > Overview'dan subdomain ayarlayin,\n"
                  << "sonra tekrar --setup calistirin.\n";
        return false;
    }

    std::string workerUrl = "wss://" + workerName + "." + subdomain + ".workers.dev";
    std::cout << "OK\n";

    // Save config
    config.apiToken   = token;
    config.accountId  = accountId;
    config.workerName = workerName;
    config.workerUrl  = workerUrl;

    if (!config.save()) {
        std::cerr << "Config kaydedilemedi (proxy yine de calisacak).\n";
    }

    std::cout << "\n"
              << "=== Setup Tamamlandi ===\n"
              << "Worker URL: " << workerUrl << "\n"
              << "Config: " << Config::configPath() << "\n\n";

    return true;
}

bool redeployWorker(Config& config) {
    if (!config.canDeploy()) {
        std::cerr << "Redeploy icin once --setup calistirin.\n";
        return false;
    }

    CloudflareApi api(config.apiToken);
    if (!api.isReady()) {
        std::cerr << "HTTP client baslatma hatasi.\n";
        return false;
    }

    std::cout << "Worker yeniden deploy ediliyor (" << config.workerName << ")... ";
    if (!api.deployWorker(config.accountId, config.workerName)) {
        std::cout << "HATA\n";
        return false;
    }
    std::cout << "OK\n";

    api.enableWorkerRoute(config.accountId, config.workerName);
    return true;
}
