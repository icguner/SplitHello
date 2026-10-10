#include "Setup.hpp"

#include "Console.hpp"
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

void step(int number, const std::string& text) {
    std::cout << console::dim("[" + std::to_string(number) + "/6] ") << text << std::flush;
}

void stepOk(const std::string& detail = {}) {
    std::cout << " " << console::green("OK")
              << (detail.empty() ? std::string{} : " " + console::dim(detail)) << "\n";
}

void stepFailed() { std::cout << " " << console::red("HATA") << "\n"; }

// Default answer is yes; end of input (no console) counts as no.
bool askRetry(const std::string& question) {
    std::cout << "\n" << console::yellow(question) << " [E/h] " << std::flush;
    std::string answer;
    if (!std::getline(std::cin, answer)) return false;
    return answer.empty() || answer[0] == 'e' || answer[0] == 'E' || answer[0] == 'y' ||
           answer[0] == 'Y';
}

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

    std::cout << "\nBirden fazla Cloudflare hesabi var:\n";
    for (size_t i = 0; i < identity.accounts.size(); ++i) {
        const auto& account = identity.accounts[i];
        std::cout << "  " << console::cyan(std::to_string(i + 1)) << "  "
                  << (account.name.empty() ? account.id : account.name) << " "
                  << console::dim("(" + account.id.substr(0, 8) + "...)") << "\n";
    }
    std::cout << "Kullanilacak hesap [1-" << identity.accounts.size() << "]: " << std::flush;

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

    std::cerr << console::red("Gecersiz hesap secimi.") << "\n";
    return std::nullopt;
}

// End-to-end check that the deployment works *and* that our secret matches.
// A freshly written secret takes a few seconds to reach every edge, so a 401 is
// expected at first; the caller decides when it has become a real failure.
bool verifyDeployment(const std::string& workerUrl, const std::string& sharedSecret,
                      int& status) {
    const std::string host = http::hostFromUrl(workerUrl);
    if (host.empty()) return false;

    http::Request request;
    request.host = host;
    request.path = "/resolve?host=cloudflare.com";
    request.timeoutMs = 15000;
    request.headers.push_back({"Authorization", "Bearer " + sharedSecret});

    const http::Response response = http::perform(request);
    secure::wipe(request.headers.back().second);   // the "Bearer <secret>" copy
    status = response.status;
    if (!response.ok()) return false;
    return !json::getStringArray(response.body, "a").empty();
}

bool deployAndVerify(Config& config, const wrangler::Client& client) {
    if (config.sharedSecret.empty()) {
        config.sharedSecret = secure::randomHex(kSharedSecretBytes);
        if (config.sharedSecret.empty()) {
            std::cerr << console::red("Rastgele anahtar uretilemedi.") << "\n";
            return false;
        }
    }

    step(4, "Worker yukleniyor (" + config.workerName + ")...");
    const wrangler::DeployResult deployment =
        client.deploy(config.accountId, config.workerName, kWorkerSource,
                      config.sharedSecret, config.workerUrl);
    if (!deployment.success) {
        stepFailed();
        std::cerr << console::dim("Ayrinti icin --verbose ile calistirin.") << "\n";
        return false;
    }
    stepOk();

    config.workerUrl = deployment.workerUrl;
    step(5, "Adres kaydediliyor...");
    stepOk(config.workerUrl);

    // Persist the rotated secret before the network check. A transient outage
    // must not strand a successfully updated remote Worker with a lost secret.
    if (!config.save()) {
        std::cerr << console::red("Worker yuklendi ama yeni gizli anahtar config'e kaydedilemedi.")
                  << "\n" << "Dosya izinlerini duzeltip --redeploy calistirin.\n";
        return false;
    }

    step(6, "Uctan uca dogrulaniyor...");
    int status = 0;
    for (int attempt = 0; attempt < 10; ++attempt) {
        if (verifyDeployment(config.workerUrl, config.sharedSecret, status)) {
            stepOk();
            return true;
        }
        Sleep(2000);
    }

    stepFailed();
    if (status == 401 || status == 403) {
        std::cerr << console::red("Worker gizli anahtari kabul etmedi (HTTP " +
                                  std::to_string(status) + ").") << "\n";
    }
    std::cerr << console::yellow("Worker yuklendi ama henuz yanit vermiyor.") << "\n"
              << console::dim("Yeni anahtar kaydedildi; biraz sonra tekrar deneyin veya --redeploy "
                              "calistirin.") << "\n";
    return false;
}

bool prepareClient(wrangler::Client& client) {
    std::string error;
    step(1, "Wrangler kontrol ediliyor...");
    if (!client.available(error)) {
        stepFailed();
        std::cerr << console::red(error) << "\n";
        return false;
    }
    stepOk();
    return true;
}

std::optional<wrangler::Identity> loginAndReadIdentity(const wrangler::Client& client,
                                                        bool alwaysLogin) {
    if (!alwaysLogin) {
        if (auto identity = client.whoami()) return identity;
    }

    // A closed tab or a denied consent is common; offer another go instead of
    // making the user restart the whole setup.
    for (;;) {
        step(2, "Cloudflare girisi: tarayicida acilan sayfada izin verin.\n");
        if (client.loginWithKeyring()) break;
        if (!askRetry("Tekrar denensin mi?")) return std::nullopt;
    }

    auto identity = client.whoami();
    if (!identity) {
        std::cerr << console::red("Giris tamamlandi ama hesap bilgisi okunamadi.") << "\n";
        return std::nullopt;
    }
    return identity;
}

} // namespace

bool runSetup(Config& config) {
    std::cout << "\n" << console::cyan("SplitHello kurulumu") << "\n\n";

    wrangler::Client client;
    if (!prepareClient(client)) return false;

    const auto identity = loginAndReadIdentity(client, true);
    if (!identity) return false;

    step(3, "Cloudflare hesabi seciliyor...");
    const auto accountId = selectAccount(*identity, config.accountId);
    if (!accountId) {
        stepFailed();
        return false;
    }
    config.accountId = *accountId;
    stepOk(config.accountId.substr(0, 8) + "...");

    if (config.workerName.empty()) config.workerName = "splithello-relay";
    if (!wrangler::isValidWorkerName(config.workerName)) {
        std::cerr << console::red("Gecersiz Worker adi: " + config.workerName) << "\n";
        return false;
    }

    // API tokens from pre-OAuth versions are migration-only and are never
    // passed to Wrangler or written back to config.
    secure::wipe(config.apiToken);
    config.sharedSecret = secure::randomHex(kSharedSecretBytes);
    if (!deployAndVerify(config, client)) return false;

    std::cout << "\n" << console::green("Kurulum tamamlandi.") << "\n"
              << console::dim("  Worker  ") << config.workerUrl << "\n"
              << console::dim("  Ayarlar ") << Config::configPath() << "\n\n";
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
        std::cerr << console::red("Gecersiz Worker adi: " + config.workerName) << "\n";
        return false;
    }

    secure::wipe(config.apiToken);
    config.sharedSecret = secure::randomHex(kSharedSecretBytes);
    if (config.sharedSecret.empty()) {
        std::cerr << console::red("Rastgele anahtar uretilemedi.") << "\n";
        return false;
    }

    if (!deployAndVerify(config, client)) return false;

    std::cout << "\n" << console::green("Yeniden yukleme tamamlandi.")
              << " Yeni gizli anahtar kaydedildi.\n";
    return true;
}
