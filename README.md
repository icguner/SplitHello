# SplitHello

TLS ClientHello fragmentation tool for bypassing internet censorship in Turkey.

## How It Works

Turkish ISPs block websites (Discord, etc.) using two techniques:

1. **DNS Poisoning** - ISP returns fake IP addresses for blocked domains
2. **SNI Inspection** - DPI (Deep Packet Inspection) reads the Server Name Indication field in TLS ClientHello to identify and block connections

SplitHello defeats both:

### DNS Bypass
SplitHello resolves domain names through a Cloudflare Worker endpoint (DNS-over-HTTPS), completely bypassing the ISP's poisoned DNS.

### TLS Record Fragmentation
Instead of sending the TLS ClientHello as a single record, SplitHello splits it into **two separate valid TLS records**, cutting the SNI hostname right in the middle:

```
Original (blocked):
[TLS Record: ClientHello with SNI "discord.com"] --> DPI reads SNI --> BLOCKED

SplitHello (passes through):
[TLS Record 1: ClientHello partial ... "disc"]  --> DPI can't find full SNI
[TLS Record 2: "ord.com" ... rest of hello]     --> DPI can't find full SNI
                                                 --> Connection established!
```

This is a completely valid TLS operation - the RFC allows handshake messages to span multiple records. The server reassembles them normally, but the DPI system fails to extract the SNI.

## Architecture

```
Application (Discord, Browser, etc.)
    | Uses system proxy automatically
    v
[SplitHello - Local Proxy] (127.0.0.1:1080)
    | 1. DNS resolution via Cloudflare Worker (bypasses DNS poisoning)
    | 2. Direct TCP connection to real IP
    | 3. TLS Record Fragmentation (splits SNI in half)
    v
[Target Server] (e.g., Discord 162.159.x.x)
```

- No VPN, no tunnel, no external relay server
- Direct connection to the target - minimal latency impact
- System proxy: all apps use it automatically, no per-app configuration needed
- Cloudflare Worker is only used for DNS resolution (free tier, no data relayed)

## Quick Start

### Prerequisites
- Windows 10/11
- [CMake](https://cmake.org/download/) 3.20+
- [Visual Studio](https://visualstudio.microsoft.com/) with C++ workload (or Build Tools)
- A free [Cloudflare](https://dash.cloudflare.com/sign-up) account

### Build
```bash
git clone https://github.com/icguner/SplitHello.git
cd SplitHello
cmake -B build
cmake --build build --config Release
```

### First Run (Setup)
```bash
build\Release\splithello.exe --setup
```

This will:
1. Open your browser to create a Cloudflare API token
2. Ask you to paste the token
3. Automatically deploy the DNS resolver Worker to your Cloudflare account
4. Save config to `%APPDATA%\splithello\config.json`

### Usage
```bash
# Start (sets system proxy automatically)
splithello.exe

# All apps will use the proxy automatically
# Press Ctrl+C to stop (system proxy is restored)
```

### Options
```
--setup              Set up Cloudflare account and deploy Worker
--redeploy           Redeploy Worker code (after updates)
--worker <url>       Override Worker URL manually
--port <port>        Local proxy port (default: 1080)
--no-system-proxy    Don't set system proxy (manual configuration)
--verbose            Enable debug logging
```

## How Is This Different from GoodbyeDPI?

| | GoodbyeDPI | SplitHello |
|---|---|---|
| **Level** | Packet (WinDivert kernel driver) | Application (proxy) |
| **Technique** | Fake packets, TCP segmentation, TTL tricks | TLS Record Fragmentation |
| **DNS** | Doesn't handle DNS poisoning | Resolves via Cloudflare Worker (DoH) |
| **Scope** | All TCP traffic | HTTP/HTTPS (apps using system proxy) |
| **Dependencies** | WinDivert driver | None (uses Windows built-in WinHTTP) |
| **Admin required** | Yes (kernel driver) | No |
| **Gaming impact** | Can affect all traffic | Games unaffected (don't use system proxy) |

## Technical Details

- **Language:** C++20
- **Dependencies:** spdlog (auto-fetched), WinHTTP + ws2_32 (Windows built-in)
- **Proxy protocols:** HTTP CONNECT + SOCKS5 (auto-detected)
- **Worker:** Cloudflare Workers free tier (100K requests/day, only used for DNS)
- **Config:** `%APPDATA%\splithello\config.json`

## License

MIT
