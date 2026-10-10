#pragma once

#include <optional>
#include <string>
#include <vector>

namespace wrangler {

struct Account {
    std::string id;
    std::string name;
};

struct Identity {
    std::string email;
    std::vector<Account> accounts;
};

struct DeployResult {
    bool success = false;
    std::string workerUrl;
};

// Pure helpers are public so authentication/deployment output can be covered
// without touching a real Cloudflare account in the unit tests.
std::optional<Identity> parseIdentity(const std::string& output);
// With a non-empty `workerName` only "<workerName>.<subdomain>.workers.dev" is
// accepted, not any workers.dev link that happens to be in the output.
std::string parseWorkersDevUrl(const std::string& output, const std::string& workerName = {});
bool isValidWorkerName(const std::string& name);

class Client {
public:
    Client();

    bool available(std::string& error) const;
    bool loginWithKeyring() const;
    std::optional<Identity> whoami() const;

    DeployResult deploy(const std::string& accountId,
                        const std::string& workerName,
                        const std::string& workerSource,
                        const std::string& sharedSecret,
                        const std::string& previousWorkerUrl = {}) const;

private:
    std::wstring nodePath_;
    std::wstring npxCliPath_;
};

} // namespace wrangler
