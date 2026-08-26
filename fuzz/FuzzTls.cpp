#include "TlsHello.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Keep individual mutations bounded so CI smoke runs spend time exploring
    // parser states rather than allocating giant records.
    if (size > 64 * 1024) return 0;

    tls::ClientHello hello;
    (void)tls::parseClientHello(data, size, hello);
    (void)tls::classifyServerResponse(data, size);
    (void)tls::isServerHello(data, size);
    (void)tls::looksLikeTlsRecord(data, size);
    return 0;
}
