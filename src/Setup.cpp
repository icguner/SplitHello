#include "Setup.hpp"

#include "Http.hpp"
#include "Json.hpp"
#include "Secure.hpp"
#include "WorkerSource.g.hpp"   // generated from worker/src/index.js

#include <spdlog/spdlog.h>

#include <iostream>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

namespace {

constexpr const char* kApiHost = "api.cloudflare.com";
constexpr const char* kTokenPage = "https://dash.cloudflare.com/profile/api-tokens";
constexpr size_t kSharedSecretBytes = 32;   // 256 bits, hex-encoded

std::string maskToken(const std::string& token) {
    if (token.size() <= 8) return "****";
    return token.substr(0, 4) + "..." + token.substr(token.size() - 4);
}

// Read a line without echoing it. An API token pasted into a terminal
// otherwise stays visible in the scrollback and in any screen recording.
std::string readSecretLine() {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD originalMode = 0;
    const bool isConsole = GetConsoleMode(input, &originalMode) != 0;

    if (isConsole) SetConsoleMode(input, originalMode & ~(DWORD)ENABLE_ECHO_INPUT);

    std::string line;
    std::getline(std::cin, line);

    if (isConsole) {
        SetConsoleMode(input, originalMode);
        std::cout << "\n";
    }

    while (!line.empty() && (line.back() == '\r' || line.back() == '\n' ||
                             line.back() == ' ' || line.back() == '\t')) {
        line.pop_back();
    }
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
        line.erase(0, 1);
    }
    return line;
}

bool askYesNo(const std::string& question, bool defaultYes) {
    std::cout << question << (defaultYes ? " [E/h]: " : " [e/H]: ");
    std::string answer;
    std::getline(std::cin, answer);
    if (answer.empty()) return defaultYes;
    const char first = (char)tolower((unsigned char)answer[0]);
    return first == 'e' || first == 'y';
}

class CloudflareApi {
public:
    explicit CloudflareApi(std::string token) : token_(std::move(token)) {}

    bool verifyToken() {
        const http::Response response = get("/client/v4/user/tokens/verify");
        if (!response.ok()) {
            spdlog::debug("Token dogrulama HTTP {}: {}", response.status, response.body);
            return false;
        }
        return json::getBool(response.body, "success");
    }

    std::string accountId() {
        const http::Response response = get("/client/v4/accounts");
        if (!response.ok()) {
            spdlog::debug("Hesap listesi HTTP {}", response.status);
            return {};
        }
        return json::getString(json::getRaw(response.body, "result"), "id");
    }

    std::string subdomain(const std::string& account) {
        const http::Response response =
            get("/client/v4/accounts/" + account + "/workers/subdomain");
        if (!response.ok()) {
            spdlog::debug("Subdomain sorgusu HTTP {}", response.status);
            return {};
        }
        return json::getString(json::getRaw(response.body, "result"), "subdomain");
    }

    // Uploads the embedded Worker with its SHARED_SECRET binding.
    // The rate-limit binding is not available on every account, so a rejection
    // is retried without it rather than failing the whole deployment.
    bool deployWorker(const std::string& account, const std::string& script,
                      const std::string& sharedSecret) {
        if (upload(account, script, sharedSecret, true)) return true;

        spdlog::warn("Rate limit binding'i kabul edilmedi, onsuz deneniyor "
                     "(worker kendi ic sayacini kullanacak)");
        return upload(account, script, sharedSecret, false);
    }

    bool enableWorkersDevRoute(const std::string& account, const std::string& script) {
        const http::Response response =
            request("POST", "/client/v4/accounts/" + account + "/workers/scripts/" +
                            script + "/subdomain",
                    R"({"enabled":true})", "application/json");

        // 409 means it is already enabled.
        if (response.ok() || response.status == 409) return true;

        spdlog::warn("workers.dev route HTTP {} (zaten aktif olabilir)", response.status);
        return true; // non-fatal
    }

private:
    std::string token_;

    http::Response get(const std::string& path) {
        return request("GET", path, {}, {});
    }

    http::Response request(const std::string& method, const std::string& path,
                           const std::string& body, const std::string& contentType) {
        http::Request req;
        req.method = method;
        req.host = kApiHost;
        req.path = path;
        req.body = body;
        req.timeoutMs = 30000;   // script uploads are not instant
        req.headers.push_back({"Authorization", "Bearer " + token_});
        if (!contentType.empty()) req.headers.push_back({"Content-Type", contentType});
        return http::perform(req);
    }

    bool upload(const std::string& account, const std::string& script,
                const std::string& sharedSecret, bool withRateLimiter) {
        std::string bindings =
            R"({"type":"secret_text","name":"SHARED_SECRET","text":")" +
            json::escape(sharedSecret) + R"("})";

        if (withRateLimiter) {
            bindings += R"(,{"type":"ratelimit","name":"RATE_LIMITER",)"
                        R"("namespace_id":"1001","simple":{"limit":600,"period":60}})";
        }

        const std::string metadata =
            R"({"main_module":"index.js","compatibility_date":"2024-09-23",)"
            R"("compatibility_flags":["nodejs_compat"],"bindings":[)" + bindings + "]}";

        // A random boundary can never collide with the payload.
        const std::string boundary = "----SplitHello" + secure::randomHex(16);

        std::string body;
        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"metadata\"; filename=\"metadata.json\"\r\n";
        body += "Content-Type: application/json\r\n\r\n";
        body += metadata;
        body += "\r\n";

        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"index.js\"; filename=\"index.js\"\r\n";
        body += "Content-Type: application/javascript+module\r\n\r\n";
        body += kWorkerSource;
        body += "\r\n";

        body += "--" + boundary + "--\r\n";

        const http::Response response =
            request("PUT", "/client/v4/accounts/" + account + "/workers/scripts/" + script,
                    body, "multipart/form-data; boundary=" + boundary);

        if (!response.ok()) {
            spdlog::debug("Worker yukleme HTTP {}: {}", response.status, response.body);
            return false;
        }
        return json::getBool(response.body, "success");
    }
};

// End-to-end check that the deployment works *and* that our secret matches.
bool verifyDeployment(const std::string& workerUrl, const std::string& sharedSecret) {
    const std::string host = http::hostFromUrl(workerUrl);
    if (host.empty()) return false;

    http::Request request;
    request.host = host;
    request.path = "/resolve?host=cloudflare.com";
    request.timeoutMs = 15000;
    request.headers.push_back({"Authorization", "Bearer " + sharedSecret});

    const http::Response response = http::perform(request);

    if (response.status == 401 || response.status == 403) {
        std::cerr << "\nWorker gizli anahtari kabul etmedi (HTTP " << response.status << ").\n";
        return false;
    }
    if (!response.ok()) {
        std::cerr << "\nWorker dogrulama basarisiz (HTTP " << response.status << ").\n";
        return false;
    }
    return !json::getStringArray(response.body, "a").empty();
}

// Deploys the embedded Worker and fills in workerUrl / sharedSecret.
bool deployAndVerify(Config& config, CloudflareApi& api, bool interactive) {
    if (config.sharedSecret.empty()) {
        config.sharedSecret = secure::randomHex(kSharedSecretBytes);
        if (config.sharedSecret.empty()) {
            std::cerr << "Rastgele anahtar uretilemedi.\n";
            return false;
        }
    }

    if (interactive) std::cout << "[3/6] Worker deploy ediliyor (" << config.workerName << ")... ";
    if (!api.deployWorker(config.accountId, config.workerName, config.sharedSecret)) {
        if (interactive) std::cout << "HATA\n";
        std::cerr << "Worker deploy edilemedi. --verbose ile ayrinti gorebilirsiniz.\n";
        return false;
    }
    if (interactive) std::cout << "OK\n";

    if (interactive) std::cout << "[4/6] workers.dev route aktiflestiriliyor... ";
    api.enableWorkersDevRoute(config.accountId, config.workerName);
    if (interactive) std::cout << "OK\n";

    if (interactive) std::cout << "[5/6] Worker URL belirleniyor... ";
    const std::string subdomain = api.subdomain(config.accountId);
    if (subdomain.empty()) {
        if (interactive) std::cout << "HATA\n";
        std::cerr << "\nworkers.dev subdomain bulunamadi.\n"
                  << "Cloudflare Dashboard > Workers & Pages > Overview'dan subdomain ayarlayin,\n"
                  << "sonra --setup komutunu tekrar calistirin.\n";
        return false;
    }
    config.workerUrl = "wss://" + config.workerName + "." + subdomain + ".workers.dev";
    if (interactive) std::cout << "OK\n";

    if (interactive) std::cout << "[6/6] Dogrulaniyor... ";
    // A fresh deployment takes a moment to become globally reachable.
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (verifyDeployment(config.workerUrl, config.sharedSecret)) {
            if (interactive) std::cout << "OK\n";
            return true;
        }
        Sleep(2000);
    }

    if (interactive) std::cout << "HATA\n";
    std::cerr << "Worker deploy edildi ama /resolve yanit vermedi.\n"
              << "Birkac dakika sonra 'splithello.exe --redeploy' deneyin.\n";
    return false;
}

} // namespace

bool runSetup(Config& config) {
    std::cout << "\n=== SplitHello Setup ===\n\n";

    std::string token = config.apiToken;

    if (!token.empty()) {
        std::cout << "Kayitli Cloudflare token bulundu: " << maskToken(token) << "\n";
        if (!askYesNo("Bu token kullanilsin mi?", true)) token.clear();
    }

    if (token.empty()) {
        std::cout << "Cloudflare API token gerekiyor. Tarayici aciliyor...\n\n"
                  << "  1. 'Create Token'\n"
                  << "  2. 'Edit Cloudflare Workers' sablonu -> 'Use template'\n"
                  << "  3. 'Continue to summary' -> 'Create Token'\n"
                  << "  4. Token'i kopyalayin\n\n";

        ShellExecuteA(nullptr, "open", kTokenPage, nullptr, nullptr, SW_SHOWNORMAL);

        std::cout << "API Token (girdi gizlidir): ";
        token = readSecretLine();

        if (token.empty()) {
            std::cerr << "Token bos. Setup iptal edildi.\n";
            return false;
        }
        std::cout << "Token: " << maskToken(token) << "\n\n";
    }

    CloudflareApi api(token);

    std::cout << "[1/6] Token dogrulaniyor... ";
    if (!api.verifyToken()) {
        std::cout << "HATA\n";
        std::cerr << "Token gecersiz veya suresi dolmus.\n";
        secure::wipe(token);
        return false;
    }
    std::cout << "OK\n";

    std::cout << "[2/6] Hesap bilgileri aliniyor... ";
    const std::string account = api.accountId();
    if (account.empty()) {
        std::cout << "HATA\n";
        std::cerr << "Hesap ID alinamadi. Token izinlerini kontrol edin.\n";
        secure::wipe(token);
        return false;
    }
    std::cout << "OK (" << account.substr(0, 8) << "...)\n";

    config.apiToken = token;
    config.accountId = account;
    if (config.workerName.empty()) config.workerName = "splithello-relay";

    if (!deployAndVerify(config, api, true)) return false;

    const bool keepToken =
        askYesNo("\nCloudflare token'i kaydedelim mi? (Hayir derseniz --redeploy icin "
                 "tekrar istenir)", true);
    if (!keepToken) secure::wipe(config.apiToken);

    if (!config.save()) {
        std::cerr << "Config kaydedilemedi (proxy yine de calisacak).\n";
    }

    std::cout << "\n=== Setup Tamamlandi ===\n"
              << "Worker URL : " << config.workerUrl << "\n"
              << "Config     : " << Config::configPath() << "\n"
              << "Sirlar     : Windows DPAPI ile sifreli (yalnizca bu Windows kullanicisi cozer)\n"
              << (keepToken ? "Token      : kaydedildi (silmek icin: --forget-token)\n"
                            : "Token      : kaydedilmedi\n")
              << "\n";

    return true;
}

bool redeployWorker(Config& config) {
    if (config.apiToken.empty()) {
        std::cout << "Kayitli token yok. Cloudflare API token (girdi gizlidir): ";
        config.apiToken = readSecretLine();
        if (config.apiToken.empty()) {
            std::cerr << "Token bos. Redeploy iptal edildi.\n";
            return false;
        }
    }

    CloudflareApi api(config.apiToken);

    if (config.accountId.empty()) {
        config.accountId = api.accountId();
        if (config.accountId.empty()) {
            std::cerr << "Hesap ID alinamadi.\n";
            return false;
        }
    }

    // Rotate the shared secret on every redeploy: the old one stops working the
    // moment the new script goes live, so a leaked URL+secret pair is short lived.
    config.sharedSecret = secure::randomHex(kSharedSecretBytes);

    std::cout << "Worker yeniden deploy ediliyor (" << config.workerName << ")...\n";
    if (!deployAndVerify(config, api, true)) return false;

    if (!config.save()) {
        std::cerr << "Config kaydedilemedi.\n";
        return false;
    }

    std::cout << "Redeploy tamamlandi. Yeni gizli anahtar kaydedildi.\n";
    return true;
}
