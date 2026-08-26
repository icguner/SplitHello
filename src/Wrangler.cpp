#include "Wrangler.hpp"

#include "FileUtil.hpp"
#include "Json.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <iostream>
#include <string_view>
#include <utility>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace wrangler {
namespace {

namespace fs = std::filesystem;

constexpr std::wstring_view kWranglerPackage = L"wrangler@4";
constexpr DWORD kProbeTimeoutMs = 120000;
constexpr DWORD kLoginTimeoutMs = 10 * 60 * 1000;
constexpr DWORD kDeployTimeoutMs = 5 * 60 * 1000;
constexpr size_t kMaxCapturedOutput = 2 * 1024 * 1024;

struct Handle {
    HANDLE value = nullptr;

    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    ~Handle() {
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
    }

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    Handle(Handle&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this == &other) return *this;
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
        value = std::exchange(other.value, nullptr);
        return *this;
    }

    HANDLE release() { return std::exchange(value, nullptr); }
};

struct ProcessResult {
    bool launched = false;
    bool timedOut = false;
    DWORD exitCode = ERROR_GEN_FAILURE;
    std::string output;

    bool ok() const { return launched && !timedOut && exitCode == 0; }
};

std::wstring searchPath(const wchar_t* fileName) {
    const DWORD required = SearchPathW(nullptr, fileName, nullptr, 0, nullptr, nullptr);
    if (required == 0) return {};

    std::wstring result(required, L'\0');
    const DWORD length =
        SearchPathW(nullptr, fileName, nullptr, required, result.data(), nullptr);
    if (length == 0 || length >= required) return {};
    result.resize(length);
    return result;
}

std::wstring quoteArgument(std::wstring_view value) {
    if (!value.empty() && value.find_first_of(L" \t\n\v\"") == std::wstring_view::npos) {
        return std::wstring(value);
    }

    std::wstring quoted = L"\"";
    size_t backslashes = 0;
    for (const wchar_t ch : value) {
        if (ch == L'\\') {
            ++backslashes;
            continue;
        }
        if (ch == L'\"') {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted.push_back(ch);
            backslashes = 0;
            continue;
        }
        quoted.append(backslashes, L'\\');
        backslashes = 0;
        quoted.push_back(ch);
    }
    quoted.append(backslashes * 2, L'\\');
    quoted.push_back(L'\"');
    return quoted;
}

std::vector<wchar_t> sanitizedEnvironment() {
    std::vector<std::wstring> entries;
    LPWCH block = GetEnvironmentStringsW();
    if (block) {
        for (const wchar_t* item = block; *item; item += wcslen(item) + 1) {
            std::wstring entry(item);
            const size_t equals = entry.find(L'=', entry.starts_with(L'=') ? 1 : 0);
            std::wstring key = entry.substr(0, equals);
            std::transform(key.begin(), key.end(), key.begin(), [](const wchar_t ch) {
                return static_cast<wchar_t>(std::towupper(ch));
            });

            // Wrangler gives these variables precedence over OAuth. Strip both
            // current and legacy spellings so this process can only use the
            // OS-keyring-backed OAuth session.
            if (key == L"CLOUDFLARE_API_TOKEN" || key == L"CLOUDFLARE_API_KEY" ||
                key == L"CLOUDFLARE_EMAIL" || key == L"CF_API_TOKEN" ||
                key == L"CF_API_KEY" || key == L"CF_EMAIL" ||
                key == L"CLOUDFLARE_AUTH_USE_KEYRING" || key == L"NO_COLOR" ||
                key == L"WRANGLER_SEND_METRICS") {
                continue;
            }
            entries.push_back(std::move(entry));
        }
        FreeEnvironmentStringsW(block);
    }

    entries.emplace_back(L"CLOUDFLARE_AUTH_USE_KEYRING=true");
    entries.emplace_back(L"NO_COLOR=1");
    entries.emplace_back(L"WRANGLER_SEND_METRICS=false");
    std::sort(entries.begin(), entries.end(), [](const std::wstring& left,
                                                  const std::wstring& right) {
        return _wcsicmp(left.c_str(), right.c_str()) < 0;
    });

    size_t size = 1;
    for (const auto& entry : entries) size += entry.size() + 1;
    std::vector<wchar_t> result;
    result.reserve(size);
    for (const auto& entry : entries) {
        result.insert(result.end(), entry.begin(), entry.end());
        result.push_back(L'\0');
    }
    result.push_back(L'\0');
    return result;
}

void appendCaptured(std::string& destination, const char* data, size_t size) {
    if (destination.size() >= kMaxCapturedOutput) return;
    const size_t available = kMaxCapturedOutput - destination.size();
    destination.append(data, std::min(size, available));
}

ProcessResult runProcess(const std::wstring& application,
                         const std::vector<std::wstring>& arguments,
                         const std::wstring& workingDirectory,
                         std::string_view input,
                         bool echoOutput,
                         DWORD timeoutMs) {
    ProcessResult result;

    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE rawOutputRead = nullptr;
    HANDLE rawOutputWrite = nullptr;
    HANDLE rawInputRead = nullptr;
    HANDLE rawInputWrite = nullptr;
    if (!CreatePipe(&rawOutputRead, &rawOutputWrite, &security, 0) ||
        !CreatePipe(&rawInputRead, &rawInputWrite, &security, 0)) {
        if (rawOutputRead) CloseHandle(rawOutputRead);
        if (rawOutputWrite) CloseHandle(rawOutputWrite);
        if (rawInputRead) CloseHandle(rawInputRead);
        if (rawInputWrite) CloseHandle(rawInputWrite);
        return result;
    }

    Handle outputRead(rawOutputRead);
    Handle outputWrite(rawOutputWrite);
    Handle inputRead(rawInputRead);
    Handle inputWrite(rawInputWrite);
    SetHandleInformation(outputRead.value, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(inputWrite.value, HANDLE_FLAG_INHERIT, 0);

    std::wstring commandLine = quoteArgument(application);
    for (const auto& argument : arguments) {
        commandLine.push_back(L' ');
        commandLine += quoteArgument(argument);
    }
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');
    std::vector<wchar_t> environment = sanitizedEnvironment();

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = inputRead.value;
    startup.hStdOutput = outputWrite.value;
    startup.hStdError = outputWrite.value;

    PROCESS_INFORMATION process{};
    if (!CreateProcessW(application.c_str(), mutableCommand.data(), nullptr, nullptr, TRUE,
                        CREATE_UNICODE_ENVIRONMENT, environment.data(),
                        workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
                        &startup, &process)) {
        return result;
    }

    result.launched = true;
    Handle processHandle(process.hProcess);
    Handle threadHandle(process.hThread);
    inputRead = {};
    outputWrite = {};

    if (!input.empty()) {
        size_t offset = 0;
        while (offset < input.size()) {
            DWORD written = 0;
            const DWORD chunk = static_cast<DWORD>(
                std::min<size_t>(input.size() - offset, MAXDWORD));
            if (!WriteFile(inputWrite.value, input.data() + offset, chunk, &written, nullptr) ||
                written == 0) {
                break;
            }
            offset += written;
        }
    }
    inputWrite = {};

    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    bool processEnded = false;
    for (;;) {
        DWORD available = 0;
        while (PeekNamedPipe(outputRead.value, nullptr, 0, nullptr, &available, nullptr) &&
               available > 0) {
            char buffer[4096];
            DWORD read = 0;
            const DWORD requested = std::min<DWORD>(available, sizeof(buffer));
            if (!ReadFile(outputRead.value, buffer, requested, &read, nullptr) || read == 0) break;
            appendCaptured(result.output, buffer, read);
            if (echoOutput) {
                std::cout.write(buffer, read);
                std::cout.flush();
            }
            available -= std::min(available, read);
        }

        if (processEnded) break;
        if (WaitForSingleObject(processHandle.value, 50) == WAIT_OBJECT_0) {
            processEnded = true;
            continue;
        }
        if (GetTickCount64() >= deadline) {
            result.timedOut = true;
            TerminateProcess(processHandle.value, ERROR_TIMEOUT);
            WaitForSingleObject(processHandle.value, 5000);
            processEnded = true;
        }
    }

    GetExitCodeProcess(processHandle.value, &result.exitCode);
    return result;
}

std::string makeWranglerConfig(const std::string& accountId,
                               const std::string& workerName,
                               bool withRateLimiter) {
    std::string config;
    config += "name = \"" + workerName + "\"\n";
    config += "main = \"index.js\"\n";
    config += "account_id = \"" + accountId + "\"\n";
    config += "compatibility_date = \"2024-09-23\"\n";
    config += "compatibility_flags = [\"nodejs_compat\"]\n";
    config += "workers_dev = true\n";
    config += "preview_urls = false\n";
    config += "send_metrics = false\n";
    if (withRateLimiter) {
        config += "\n[[unsafe.bindings]]\n";
        config += "name = \"RATE_LIMITER\"\n";
        config += "type = \"ratelimit\"\n";
        config += "namespace_id = \"1001\"\n";
        config += "simple = { limit = 600, period = 60 }\n";
    }
    return config;
}

bool isHexAccountId(const std::string& accountId) {
    return accountId.size() == 32 &&
           std::ranges::all_of(accountId, [](const unsigned char ch) {
               return std::isxdigit(ch) != 0;
           });
}

class TemporaryWorkerDirectory {
public:
    TemporaryWorkerDirectory() {
        wchar_t tempPath[MAX_PATH + 1]{};
        if (GetTempPathW(MAX_PATH, tempPath) == 0) return;

        wchar_t candidate[MAX_PATH + 1]{};
        if (GetTempFileNameW(tempPath, L"shw", 0, candidate) == 0) return;
        DeleteFileW(candidate);
        if (!CreateDirectoryW(candidate, nullptr)) return;
        path_ = candidate;
    }

    ~TemporaryWorkerDirectory() {
        if (path_.empty()) return;
        DeleteFileW((path_ / L"index.js").c_str());
        DeleteFileW((path_ / L"wrangler.toml").c_str());
        RemoveDirectoryW(path_.c_str());
    }

    bool valid() const { return !path_.empty(); }
    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

std::pair<std::wstring, std::wstring> findNpxRuntime() {
    const std::wstring node = searchPath(L"node.exe");
    if (node.empty()) return {};

    std::vector<fs::path> roots;
    roots.push_back(fs::path(node).parent_path());
    const std::wstring npx = searchPath(L"npx.cmd");
    if (!npx.empty()) {
        fs::path npxDir = fs::path(npx).parent_path();
        roots.push_back(npxDir);
        if (npxDir.filename() == L"bin") {
            roots.push_back(npxDir.parent_path().parent_path().parent_path());
        }
    }

    for (const auto& root : roots) {
        const fs::path cli = root / L"node_modules" / L"npm" / L"bin" / L"npx-cli.js";
        std::error_code ec;
        if (fs::is_regular_file(cli, ec)) return {node, cli.wstring()};
    }
    return {};
}

std::vector<std::wstring> npxArguments(const std::wstring& npxCli,
                                       std::initializer_list<std::wstring> arguments) {
    std::vector<std::wstring> result{npxCli, L"--yes", std::wstring(kWranglerPackage)};
    result.insert(result.end(), arguments.begin(), arguments.end());
    return result;
}

std::vector<std::string> arrayObjects(const std::string& array) {
    std::vector<std::string> objects;
    size_t depth = 0;
    size_t objectStart = std::string::npos;
    bool inString = false;
    bool escaped = false;
    for (size_t i = 0; i < array.size(); ++i) {
        const char ch = array[i];
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                inString = false;
            }
            continue;
        }
        if (ch == '"') {
            inString = true;
        } else if (ch == '{') {
            if (depth++ == 0) objectStart = i;
        } else if (ch == '}' && depth > 0 && --depth == 0 && objectStart != std::string::npos) {
            objects.push_back(array.substr(objectStart, i - objectStart + 1));
            objectStart = std::string::npos;
        }
    }
    return objects;
}

} // namespace

std::optional<Identity> parseIdentity(const std::string& output) {
    const std::string accountsJson = json::getRaw(output, "accounts");
    if (accountsJson.empty()) return std::nullopt;

    Identity identity;
    identity.email = json::getString(output, "email");
    for (const std::string& object : arrayObjects(accountsJson)) {
        const std::string id = json::getString(object, "id");
        if (!isHexAccountId(id)) continue;
        identity.accounts.push_back({id, json::getString(object, "name")});
    }
    if (identity.accounts.empty()) return std::nullopt;
    return identity;
}

std::string parseWorkersDevUrl(const std::string& output) {
    constexpr std::string_view prefix = "https://";
    size_t cursor = 0;
    while ((cursor = output.find(prefix, cursor)) != std::string::npos) {
        const size_t hostStart = cursor + prefix.size();
        size_t hostEnd = hostStart;
        while (hostEnd < output.size()) {
            const unsigned char ch = static_cast<unsigned char>(output[hostEnd]);
            if (!(std::isalnum(ch) || ch == '.' || ch == '-')) break;
            ++hostEnd;
        }
        std::string host = output.substr(hostStart, hostEnd - hostStart);
        std::transform(host.begin(), host.end(), host.begin(), [](const unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        constexpr std::string_view suffix = ".workers.dev";
        if (host.size() > suffix.size() && host.ends_with(suffix)) {
            return "wss://" + host;
        }
        cursor = hostEnd;
    }
    return {};
}

bool isValidWorkerName(const std::string& name) {
    if (name.empty() || name.size() > 63 || name.front() == '-' || name.back() == '-') {
        return false;
    }
    return std::ranges::all_of(name, [](const unsigned char ch) {
        return std::islower(ch) || std::isdigit(ch) || ch == '-';
    });
}

Client::Client() {
    auto [node, npx] = findNpxRuntime();
    nodePath_ = std::move(node);
    npxCliPath_ = std::move(npx);
}

bool Client::available(std::string& error) const {
    if (nodePath_.empty() || npxCliPath_.empty()) {
        error = "Node.js/npm bulunamadi. Node.js 20+ LTS kurup tekrar deneyin.";
        return false;
    }
    const ProcessResult result = runProcess(
        nodePath_, npxArguments(npxCliPath_, {L"--version"}), {}, {}, false, kProbeTimeoutMs);
    if (!result.ok()) {
        error = result.timedOut ? "Wrangler surum kontrolu zaman asimina ugradi."
                                : "Wrangler calistirilamadi: " + result.output;
        return false;
    }
    return true;
}

bool Client::loginWithKeyring() const {
    const ProcessResult result = runProcess(
        nodePath_, npxArguments(npxCliPath_, {L"login", L"--use-keyring"}), {}, {}, true,
        kLoginTimeoutMs);
    if (result.timedOut) std::cerr << "Wrangler OAuth girisi zaman asimina ugradi.\n";
    return result.ok();
}

std::optional<Identity> Client::whoami() const {
    const ProcessResult result = runProcess(
        nodePath_, npxArguments(npxCliPath_, {L"whoami", L"--json"}), {}, {}, false,
        kProbeTimeoutMs);
    if (!result.ok()) {
        spdlog::debug("wrangler whoami basarisiz (exit={}): {}", result.exitCode,
                      result.output);
        return std::nullopt;
    }
    auto identity = parseIdentity(result.output);
    if (!identity) spdlog::debug("wrangler whoami JSON okunamadi: {}", result.output);
    return identity;
}

DeployResult Client::deploy(const std::string& accountId,
                            const std::string& workerName,
                            const std::string& workerSource,
                            const std::string& sharedSecret,
                            const std::string& previousWorkerUrl) const {
    DeployResult deployment;
    if (!isHexAccountId(accountId) || !isValidWorkerName(workerName) ||
        workerSource.empty() || sharedSecret.empty()) {
        std::cerr << "Wrangler deploy parametreleri gecersiz.\n";
        return deployment;
    }

    TemporaryWorkerDirectory directory;
    if (!directory.valid()) {
        std::cerr << "Gecici Wrangler klasoru olusturulamadi.\n";
        return deployment;
    }

    const fs::path scriptPath = directory.path() / L"index.js";
    const fs::path configPath = directory.path() / L"wrangler.toml";
    if (!fileutil::writeAtomic(scriptPath.string(), workerSource) ||
        !fileutil::writeAtomic(configPath.string(),
                               makeWranglerConfig(accountId, workerName, true))) {
        std::cerr << "Gecici Worker dosyalari yazilamadi.\n";
        return deployment;
    }

    auto deployCode = [&]() {
        return runProcess(nodePath_,
                          npxArguments(npxCliPath_,
                                       {L"deploy", L"--config", configPath.wstring(),
                                        L"--no-autoconfig"}),
                          directory.path().wstring(), {}, true, kDeployTimeoutMs);
    };

    ProcessResult codeResult = deployCode();
    if (!codeResult.ok()) {
        spdlog::warn("Rate limit binding'i kabul edilmemis olabilir; binding olmadan "
                     "bir kez daha deneniyor");
        if (!fileutil::writeAtomic(configPath.string(),
                                   makeWranglerConfig(accountId, workerName, false))) {
            return deployment;
        }
        codeResult = deployCode();
    }
    if (!codeResult.ok()) {
        if (codeResult.timedOut) std::cerr << "Wrangler deploy zaman asimina ugradi.\n";
        return deployment;
    }

    const std::string secretInput = sharedSecret + "\n";
    const ProcessResult secretResult = runProcess(
        nodePath_,
        npxArguments(npxCliPath_,
                     {L"secret", L"put", L"SHARED_SECRET", L"--config",
                      configPath.wstring()}),
        directory.path().wstring(), secretInput, true, kDeployTimeoutMs);
    if (!secretResult.ok()) {
        if (secretResult.timedOut) std::cerr << "Wrangler secret yukleme zaman asimina ugradi.\n";
        return deployment;
    }

    deployment.workerUrl = parseWorkersDevUrl(codeResult.output);
    if (deployment.workerUrl.empty() && previousWorkerUrl.starts_with("wss://") &&
        previousWorkerUrl.ends_with(".workers.dev")) {
        deployment.workerUrl = previousWorkerUrl;
    }
    if (deployment.workerUrl.empty()) {
        std::cerr << "Wrangler deploy basarili, ancak workers.dev URL'si okunamadi.\n";
        return deployment;
    }

    deployment.success = true;
    return deployment;
}

} // namespace wrangler
