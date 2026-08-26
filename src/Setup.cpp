#include "Setup.hpp"

#include "Http.hpp"
#include "Json.hpp"
#include "Secure.hpp"
#include "WorkerSource.g.hpp"   // generated from worker/src/index.js
#include "Wrangler.hpp"

#include <algorithm>
#include <iostream>
#include <optional>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

constexpr size_t kSharedSecretBytes = 32;   // 256 bits, hex-encoded

std::optional<std::string> selectAccount(const wrangler::Identity& identity,
                                         const std::string& preferredId) {
    if (!preferredId.empty()) {
        const auto existing = std::ranges::find_if(
            identity.accounts,
            [&](const wrangler::Account& account) { return account.id == preferredId; });
        if (existing != identity.accounts.end()) return existing->id;
    }

    if (identity.accounts.size() == 1) return identity.accounts.front().id;
    if (identity.accounts.empty()) return std::nullopt;

    std::cout << "Birden fazla Cloudflare hesabi bulundu:\n";
    for (size_t i = 0; i < identity.accounts.size(); ++i) {
        const auto& account = identity.accounts[i];
        std::cout << "  " << (i + 1) << ". "
                  << (account.name.empty() ? account.id : account.name) << " ("
                  << account.id.substr(0, 8) << "...)\n";
    }
    std::cout << "Kullanilacak hesap [1-" << identity.accounts.size() << "]: ";

    std::string answer;
    std::getline(std::cin, answer);
    try {
        size_t consumed = 0;
        const unsigned long selected = std::stoul(answer, &consumed);
        if (consumed == answer.size() && selected >= 1 &&
            selected <= identity.accounts.size()) {
            return identity.accounts[selected - 1].id;
        }
    } catch (...) {
    }

    std::cerr << "Gecersiz hesap secimi.\n";
    return std::nullopt;
}

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

bool deployAndVerify(Config& config, const wrangler::Client& client) {
    if (config.sharedSecret.empty()) {
        config.sharedSecret = secure::randomHex(kSharedSecretBytes);
        if (config.sharedSecret.empty()) {
            std::cerr << "Rastgele anahtar uretilemedi.\n";
            return false;
        }
    }

    std::cout << "[4/6] Worker ve gizli anahtar deploy ediliyor (" << config.workerName
              << ")...\n";
    const wrangler::DeployResult deployment =
        client.deploy(config.accountId, config.workerName, kWorkerSource,
                      config.sharedSecret, config.workerUrl);
    if (!deployment.success) {
        std::cerr << "Worker deploy edilemedi. --verbose ile ayrinti gorebilirsiniz.\n";
        return false;
    }

    config.workerUrl = deployment.workerUrl;
    std::cout << "[5/6] Worker URL: " << config.workerUrl << "\n";

    // Persist the rotated secret before the network check. A transient outage
    // must not strand a successfully updated remote Worker with a lost secret.
    if (!config.save()) {
        std::cerr << "Worker deploy edildi ama yeni gizli anahtar config'e kaydedilemedi.\n"
                  << "Dosya izinlerini duzeltip --redeploy calistirin.\n";
        return false;
    }

    std::cout << "[6/6] Uctan uca dogrulaniyor... ";
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (verifyDeployment(config.workerUrl, config.sharedSecret)) {
            std::cout << "OK\n";
            return true;
        }
        Sleep(2000);
    }

    std::cout << "HATA\n";
    std::cerr << "Worker deploy edildi ama /resolve henuz yanit vermedi.\n"
              << "Yeni anahtar guvenle kaydedildi; biraz sonra tekrar deneyebilir veya "
                 "--redeploy calistirabilirsiniz.\n";
    return false;
}

bool prepareClient(wrangler::Client& client) {
    std::string error;
    std::cout << "[1/6] Wrangler 4 kontrol ediliyor... ";
    if (!client.available(error)) {
        std::cout << "HATA\n";
        std::cerr << error << "\n";
        return false;
    }
    std::cout << "OK\n";
    return true;
}

std::optional<wrangler::Identity> loginAndReadIdentity(const wrangler::Client& client,
                                                        bool alwaysLogin) {
    if (!alwaysLogin) {
        if (auto identity = client.whoami()) return identity;
    }

    std::cout << "[2/6] Cloudflare OAuth aciliyor; tarayicida izin verin.\n";
    if (!client.loginWithKeyring()) {
        std::cerr << "Cloudflare OAuth girisi tamamlanamadi.\n";
        return std::nullopt;
    }

    auto identity = client.whoami();
    if (!identity) {
        std::cerr << "OAuth tamamlandi ancak Wrangler hesap bilgisini okuyamadi.\n";
        return std::nullopt;
    }
    return identity;
}

} // namespace

bool runSetup(Config& config) {
    std::cout << "\n=== SplitHello Setup ===\n\n";

    wrangler::Client client;
    if (!prepareClient(client)) return false;

    const auto identity = loginAndReadIdentity(client, true);
    if (!identity) return false;

    std::cout << "[3/6] Cloudflare hesabi seciliyor... ";
    const auto accountId = selectAccount(*identity, config.accountId);
    if (!accountId) return false;
    config.accountId = *accountId;
    std::cout << "OK (" << config.accountId.substr(0, 8) << "...)\n";

    if (config.workerName.empty()) config.workerName = "splithello-relay";
    if (!wrangler::isValidWorkerName(config.workerName)) {
        std::cerr << "Gecersiz Worker adi: " << config.workerName << "\n";
        return false;
    }

    // API tokens from pre-OAuth versions are migration-only and are never
    // passed to Wrangler or written back to config.
    secure::wipe(config.apiToken);
    config.sharedSecret = secure::randomHex(kSharedSecretBytes);
    if (!deployAndVerify(config, client)) return false;

    std::cout << "\n=== Setup Tamamlandi ===\n"
              << "Worker URL : " << config.workerUrl << "\n"
              << "Config     : " << Config::configPath() << "\n"
              << "OAuth      : Wrangler + Windows Credential Manager\n"
              << "Worker sirri: Windows DPAPI ile sifreli\n\n";
    return true;
}

bool redeployWorker(Config& config) {
    wrangler::Client client;
    if (!prepareClient(client)) return false;

    const auto identity = loginAndReadIdentity(client, false);
    if (!identity) return false;

    const auto accountId = selectAccount(*identity, config.accountId);
    if (!accountId) return false;
    config.accountId = *accountId;

    if (!wrangler::isValidWorkerName(config.workerName)) {
        std::cerr << "Gecersiz Worker adi: " << config.workerName << "\n";
        return false;
    }

    secure::wipe(config.apiToken);
    config.sharedSecret = secure::randomHex(kSharedSecretBytes);
    if (config.sharedSecret.empty()) {
        std::cerr << "Rastgele anahtar uretilemedi.\n";
        return false;
    }

    std::cout << "Worker yeniden deploy ediliyor (" << config.workerName << ")...\n";
    if (!deployAndVerify(config, client)) return false;

    std::cout << "Redeploy tamamlandi. Yeni gizli anahtar kaydedildi.\n";
    return true;
}
