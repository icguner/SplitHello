#include "NetworkIdentity.hpp"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <netlistmgr.h>
#include <objbase.h>

namespace network_identity {
namespace {

std::string guidText(const GUID& value) {
    wchar_t text[40] = {};
    if (StringFromGUID2(value, text, (int)std::size(text)) == 0) return {};

    std::string ascii;
    for (const wchar_t c : text) {
        if (c == L'\0') break;
        if (c != L'{' && c != L'}') ascii.push_back((char)c);
    }
    return ascii;
}

uint64_t fnv1a(const std::string& text) {
    uint64_t hash = 14695981039346656037ULL;
    for (const unsigned char c : text) {
        hash ^= c;
        hash *= 1099511628211ULL;
    }
    return hash;
}

} // namespace

std::string current() {
    const HRESULT init = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool uninitialize = SUCCEEDED(init);
    if (FAILED(init) && init != RPC_E_CHANGED_MODE) return "network-default";

    INetworkListManager* manager = nullptr;
    HRESULT result = CoCreateInstance(CLSID_NetworkListManager, nullptr,
                                      CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&manager));
    if (FAILED(result) || !manager) {
        if (uninitialize) CoUninitialize();
        return "network-default";
    }

    IEnumNetworks* networks = nullptr;
    result = manager->GetNetworks(NLM_ENUM_NETWORK_CONNECTED, &networks);
    std::vector<std::string> ids;

    if (SUCCEEDED(result) && networks) {
        INetwork* network = nullptr;
        ULONG fetched = 0;
        while (networks->Next(1, &network, &fetched) == S_OK) {
            GUID id{};
            NLM_CONNECTIVITY connectivity = NLM_CONNECTIVITY_DISCONNECTED;
            const bool hasInternet = SUCCEEDED(network->GetConnectivity(&connectivity)) &&
                ((connectivity & NLM_CONNECTIVITY_IPV4_INTERNET) != 0 ||
                 (connectivity & NLM_CONNECTIVITY_IPV6_INTERNET) != 0);
            if (hasInternet && SUCCEEDED(network->GetNetworkId(&id))) {
                const std::string text = guidText(id);
                if (!text.empty()) ids.push_back(text);
            }
            network->Release();
            network = nullptr;
        }
        networks->Release();
    }

    manager->Release();
    if (uninitialize) CoUninitialize();

    if (ids.empty()) return "network-default";

    std::sort(ids.begin(), ids.end());
    std::string joined;
    for (const std::string& id : ids) {
        joined += id;
        joined.push_back('|');
    }

    std::ostringstream out;
    out << "nla-" << std::hex << std::setw(16) << std::setfill('0') << fnv1a(joined);
    return out.str();
}

} // namespace network_identity
