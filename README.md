# SplitHello

Adaptive, direct-path DPI diagnosis and bypass for Windows. SplitHello learns
the least invasive profile that works for each network and hostname, while
leaving already healthy HTTPS and QUIC traffic on their native paths.

## How It Works

Turkish ISPs block websites (Discord, etc.) using two techniques:

1. **DNS Poisoning** - ISP returns fake IP addresses for blocked domains
2. **SNI Inspection** - DPI (Deep Packet Inspection) reads the Server Name Indication field in TLS ClientHello to identify and block connections

SplitHello handles both without a VPN or a remote payload relay on the normal
data path.

### Default operating mode: adaptive learning

Adaptive learning is the default; no strategy flag is required:

1. Intercept the application's outbound TCP/443 flow and recover its hostname.
2. Try the original ClientHello unchanged as a differential baseline.
3. Only if that baseline fails, probe the bounded TLS-record and packet-level
   profile set on fresh direct connections.
4. Accept a profile only after a complete ServerHello or HelloRetryRequest.
5. Persist only the successful bypass profile for the current Windows network
   identity and hostname. Healthy destinations require no learned record.

On later connections, a learned winner is tried first. A stale winner is
downgraded after one failure and evicted after two; if the untouched baseline
works again, the stale mapping is removed immediately. Entries expire after
seven days so the engine periodically relearns changed network behavior.

### Transparent WinDivert interception

SplitHello no longer depends on the Windows system-proxy setting. Its signed
WinDivert driver reflects every non-loopback outbound TCP/443 connection into
the local relay, including connections from applications that ignore Internet
Options. IPv4 and IPv6 are handled. Only the HTTPS port family is diverted;
unrelated game, voice and LAN traffic stays on the normal Windows path.

The reflector records the original destination when it sees the TCP SYN. The
local listener accepts a reflected socket only if that exact server-address +
client-port tuple is present in the short-lived registry, so binding the relay
on all local interfaces does not create an open proxy.

UDP/443 passes unchanged by default, keeping HTTP/3 media and other already
working QUIC traffic on its native fast path. Optional adaptive mode precedes a
new QUIC Initial with a deliberately non-QUIC datagram and temporarily forces an
unresponsive target to TCP; `--quic-mode allow|adaptive|block` selects the
behavior. Other UDP traffic, including Discord voice ports, is not redirected
or blocked.

### DNS Bypass

SplitHello transparently captures UDP/53. A/AAAA lookups warm one shared
dual-stack cache so the relay can race IPv4 and IPv6; other query types preserve
the original wire message through an authenticated Cloudflare Worker endpoint.
HTTPS/SVCB (type 65), ECH configuration, ipv4hint/ipv6hint and DNS error codes
all reach the application unchanged. Direct relay resolution still caches A and
AAAA by TTL and races them with Happy Eyeballs (RFC 8305).

In transparent mode the relay reuses the application's already-DoH-validated
destination IP instead of issuing a second DNS query for every TLS connection.
Manual SOCKS/CONNECT mode still resolves through the Worker and uses Happy
Eyeballs.

### Packet and TLS transformation

WinDivert is also used as a packet rewriter on the relay's direct connection.
When the untouched baseline fails, the learning pool can try reverse-order TCP
segments, fake cover ClientHellos with bad sequence/checksum/AutoTTL disposal,
sequence overlap, IPv4 fragmentation, and valid TLS record fragmentation. IPv6
uses the reverse-order fallback for the IP-fragment profile because IPv6 needs
a Fragment extension header rather than the IPv4 fragment fields.

### TLS record fragmentation (one profile family)

This profile family splits one TLS ClientHello into **multiple valid TLS
records**, cutting the SNI hostname apart:

```
Original (blocked):
[TLS Record: ClientHello with SNI "discord.com"] --> DPI reads SNI --> BLOCKED

SplitHello (passes through):
[TLS Record 1: ClientHello partial ... "disc"]  --> DPI can't find full SNI
[TLS Record 2: "ord.com" ... rest of hello]     --> DPI can't find full SNI
                                                 --> Connection established!
```

This is a valid TLS operation: the RFC allows handshake messages to span
multiple records. The server reassembles them normally; DPI implementations
that do not perform equivalent reassembly fail to extract the complete SNI.

### DPI diagnosis and profile learning

One split point does not defeat every DPI box: some reassemble TLS records, some
only inspect the first TCP segment, and some key on the record boundary. The
engine therefore compares several profiles, but pays that discovery cost only
for an unknown or changed blocked path. Learned bypass winners are kept in
`%APPDATA%\splithello\strategies.json`, scoped by Windows network identity and
hostname (maximum 1,000 live entries, seven-day TTL).

| Profile | What it does |
|---|---|
| `none` | Untouched ClientHello; the baseline for an unknown path and never persisted as a bypass winner |
| `sni-mid` | One cut in the middle of the SNI hostname |
| `record-1` | Cut after the first payload byte (splits the handshake header) |
| `packet-reverse` | Send the second ClientHello segment before the first |
| `packet-ipfrag` | Fragment below TCP on IPv4; reverse disorder fallback on IPv6 |
| `packet-fake-badseq` | Prepend an out-of-window cover-SNI ClientHello |
| `packet-autottl` | Infer path hops and expire the cover before the server |
| `packet-seqovl` | Use sequence overlap so DPI and the server see different bytes |
| `sni-pre` | Cut immediately before the hostname starts |
| `sni-multi` | Four cuts: header, before, inside and after the hostname |
| `packet-fake-badsum` | Prepend a bad-checksum cover-SNI ClientHello |
| `sni-mid-slow` | SNI cut plus 4-byte writes and a longer pause |

A profile only "worked" after a complete TLS ServerHello or HelloRetryRequest.
TLS Alerts, non-TLS block pages, partial records, silent drops, FIN and RST are
different diagnostic signals rather than generic success. If the untouched
ClientHello fails while a fragmented copy receives ServerHello, SplitHello
classifies the path as likely SNI interference and caches the winner for seven
days. A cached profile is scoped to the current Windows network identity, so a
rule learned on home broadband is not reused on a hotspot or VPN. This is
differential evidence, not a claim that an outage or reset alone proves DPI.
A ServerHello taking at least 1.5 seconds is recorded separately as low-confidence
`throttling-suspected`; one slow origin sample is deliberately not treated as
proof of censorship.

ClientHello can be followed by TLS 1.3 0-RTT data. During diagnosis only the
ClientHello is replayed; pipelined data is sent exactly once to the winning
connection. `--strategy <name>` pins a profile for controlled testing and
disables learning for that run; it is not needed for normal operation.

The **ECH** extension (RFC 9849) is not treated as proof that the inner hello is
encrypted: Chromium also sends GREASE ECH when the DNS HTTPS record has no ECH
configuration. SplitHello keeps safe profiles available and uses the visible
outer SNI for scoping; a ClientHello that already spans TLS records is still
left untouched.

## Architecture

```
Application (Discord, Browser, etc.)
    | Normal TCP/443 connection; no proxy configuration
    v
[WinDivert - signed WFP driver]
    | Reflects the flow and preserves its original destination
    v
[SplitHello - Local Relay] ([::]:1080)
    | 1. Reassembles ClientHello and recovers SNI
    | 2. Reuses the application's validated IP and shared DNS cache
    | 3. Opens a direct TCP connection (dual-stack Happy Eyeballs)
    | 4. Tries learned winner, or untouched baseline before bounded probes
    | 5. Persists only a proven bypass winner per network + hostname
    v
[Target Server] (e.g., Discord 162.159.x.x)
```

- No VPN, no tunnel, no external relay server on the data path
- Direct connection to the target; learned winners avoid repeated profile scans
- All applications' TCP/443 flows are covered without per-app proxy settings
- SplitHello's own Worker traffic uses a private bypass port to avoid recursion
- The Cloudflare Worker normally handles DNS only; payload relay is used only
  when the explicit `--tunnel-fallback` option is enabled

## Security Model

- **Worker authentication.** `/dns-query`, `/resolve` and `/tunnel` require
  `Authorization: Bearer <SHARED_SECRET>`. The secret is generated during
  `--setup`, uploaded as a `secret_text` binding, and rotated on every
  `--redeploy`. Without the binding the Worker fails closed - an unauthenticated
  deployment would be an open DNS proxy and an open TCP relay billed to your
  account.
- **Request limits.** The Worker rate-limits per client IP through Cloudflare's
  rate-limiting binding, falling back to a per-isolate counter where that
  binding is unavailable. `/tunnel` only accepts ports 80, 443 and 853, validates
  the hostname, and refuses to open sockets to private or loopback addresses.
- **Secrets at rest.** The Cloudflare API token and the shared secret are
  encrypted with Windows DPAPI before being written to `config.json`, so only
  the same Windows user on the same machine can read them. Configs written by
  older versions are migrated on first run. `--forget-token` deletes the token
  entirely; the Worker keeps running without it.
- **Driver provenance.** CMake downloads the official WinDivert 2.2.2 binary
  archive with a pinned SHA-256 hash. The signed driver, DLL and WinDivert
  license are copied beside the executable. A mismatched archive fails the
  configure step.
- **Fail-closed listener.** Transparent sockets are authorized by a short-lived
  SYN registry. Unsolicited connections to the relay port are rejected before
  any proxy protocol or payload is processed.
- **Legacy cleanup.** Builds before transparent mode changed Internet Options.
  A leftover backup is restored on startup; `--restore-proxy` remains available
  solely for migration/recovery.

## Quick Start

### Prerequisites
- Windows 10/11
- [CMake](https://cmake.org/download/) 3.20+
- [Visual Studio](https://visualstudio.microsoft.com/) with C++ workload (or Build Tools)
- A free [Cloudflare](https://dash.cloudflare.com/sign-up) account
- Administrator permission at runtime (required to load WinDivert's signed WFP driver)

### Build
```bash
cmake -B build -S .
cmake --build build --config Release
ctest --test-dir build -C Release
```

Note: with the Ninja generator, configure and build from a Developer Command
Prompt so the MSVC include paths are set. The Visual Studio generator (the
default) needs no special shell.

### First Run (Setup)
```bash
build\Release\splithello.exe --setup
```

This will:
1. Open your browser to create a Cloudflare API token
2. Ask you to paste the token (input is hidden)
3. Generate a random shared secret and deploy the Worker to your account
4. Verify the deployment end to end
5. Save config to `%APPDATA%\splithello\config.json` (secrets DPAPI-encrypted)

### Usage
```bash
splithello.exe
```

The first normal run displays a Windows UAC prompt and then lives in the system
tray. Start/Stop controls remove or restore the WinDivert path without closing
the tray controller. TCP DPI learning is always adaptive unless `--strategy`
pins a diagnostic profile. QUIC is a separate policy: it passes unchanged by
default so working HTTP/3 services such as YouTube keep their native fast path;
adaptive and block modes remain available through `--quic-mode`.

The network path is fail-open. Transient WinDivert resource errors are retried
three times with short backoff; a persistent reader or relay failure closes the
WinDivert handle before engine teardown, immediately restoring the normal
Internet path. The tray then restarts the engine automatically, capped at three
attempts in ten minutes to avoid a crash loop.

Persistent diagnostics rotate at 512 KiB with two backups and SplitHello log
archives older than seven days are removed during startup.

### Options
```
--setup              Set up Cloudflare account and deploy Worker
--redeploy           Redeploy Worker code and rotate the shared secret
--worker <url>       Override Worker URL manually
--port <port>        Transparent relay port (default: 1080)
--split-delay <ms>   Pause between TLS record fragments (default: 20)
--strategy <name>    Diagnostic: pin one profile and disable learning
--tunnel-fallback    Fall back to the Worker tunnel when every profile fails
--manual-proxy       Disable WinDivert; listen for explicit SOCKS5/CONNECT
--quic-mode <mode>   allow (default), adaptive or block
--allow-quic         Backward-compatible alias for --quic-mode allow
--restore-proxy      Restore a proxy backup left by a crash, then exit
--forget-token       Delete the stored Cloudflare token, then exit
--forget-strategies  Reset learned per-domain strategies, then exit
--list-strategies    List DPI adaptation profiles, then exit
--console            Run in a console instead of the system tray
--verbose            Enable console-mode debug logging
```

## Worker

`worker/src/index.js` is the **only** copy of the Worker. It is embedded into
the client binary at build time by `cmake/EmbedWorker.cmake`, so
`splithello --setup` and `wrangler deploy` always ship identical code.

Deploying by hand:
```bash
cd worker
wrangler secret put SHARED_SECRET
wrangler deploy
```
The same secret must be in `%APPDATA%\splithello\config.json`; the simplest way
to keep both sides in sync is to let `--setup` do it.

## How Is This Different from GoodbyeDPI?

| | GoodbyeDPI | SplitHello |
|---|---|---|
| **Level** | Packet (WinDivert kernel driver) | Packet rewriting + stateful TLS relay (WinDivert) |
| **Technique** | Fake packets, TCP segmentation, TTL tricks | Differential baseline + learned fake/disorder/overlap/AutoTTL/IP-fragment/TLS-record profiles |
| **DNS** | Doesn't handle DNS poisoning | Transparent raw DNS wire forwarding via authenticated DoH |
| **Scope** | Filter-dependent TCP traffic | All non-loopback TCP/443; UDP/443 unchanged by default |
| **Dependencies** | WinDivert driver | WinDivert 2.2.2 + Windows WinHTTP |
| **Admin required** | Yes | Yes, only for transparent mode |
| **Gaming impact** | Can affect broad traffic | Non-443 game/voice traffic bypasses the filter |

## Technical Details

- **Language:** C++20
- **Dependencies:** spdlog and pinned WinDivert 2.2.2 (auto-fetched), WinHTTP / ws2_32 / crypt32 / bcrypt / ole32 (Windows built-in)
- **Ingress:** WinDivert transparent TCP/443 reflection; pass-through UDP/443 by default (IPv4 + IPv6)
- **Manual recovery:** HTTP CONNECT + SOCKS5 (`--manual-proxy`)
- **Worker:** authenticated raw DNS, direct-resolution and optional tunnel endpoints
- **Config:** `%APPDATA%\splithello\config.json`
- **Learned strategies:** `%APPDATA%\splithello\strategies.json` (proven bypass winners only; network-scoped, maximum 1,000 live entries, seven-day TTL)
- **Runtime log:** `%APPDATA%\splithello\splithello.log` (512 KiB plus two backups; no secrets; seven-day archive retention).
  It records startup/shutdown, learned bypasses, profile changes, QUIC fallback,
  slow paths and failures; ordinary DNS and successful `none` traffic is omitted.
  `--verbose` adds detail to the console without bloating the persistent log.
- **Tests:** `ctest --test-dir build -C Release` (ClientHello/server response parsing, DPI diagnosis, strategy planning, transparent routing and SYN authorization, JSON)

## Not Yet Implemented

- Tray connection test and live active-strategy/flow statistics (Start/Stop,
  startup control, automatic recovery and log access are implemented)
- `wrangler login --use-keyring` OAuth instead of pasting an API token
- Fuzzing, GitHub Actions CI, signed releases, auto-update
- Full QUIC Initial decryption/re-encryption and CRYPTO-frame fragmentation. The
  current adaptive QUIC mode implements the lower-risk pre-Initial prime and a
  measured TCP fallback; it does not alter encrypted QUIC CRYPTO frames.
- Per-process include/exclude controls.

## License

SplitHello is MIT licensed. WinDivert is distributed separately under its
LGPLv3/GPLv2 dual license; `WinDivert-LICENSE.txt` is copied beside every build.
