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

### Native WFP interception

SplitHello no longer depends on the Windows system-proxy setting or WinDivert.
Its own WFP callout driver redirects selected outbound TCP/443 connections at
the ALE layer and keeps exact packet transformations in narrowly scoped IP
packet callouts. IPv4 and IPv6 are handled. Unrelated game, voice and LAN
traffic stays on the normal Windows path.

The redirect callout attaches the original destination to WFP redirect context.
The local listener accepts only sockets carrying that context and passes WFP's
redirect records to same-family replacement sockets. Cross-family Happy
Eyeballs attempts rely on the relay process's ALE bypass, preventing loops
without applying incompatible redirect records.

UDP/443 passes unchanged by default. Adaptive mode gives a new QUIC flow a
bounded response window and temporarily forces an unresponsive target to TCP;
`--quic-mode allow|adaptive|block` selects the behavior. Other UDP traffic,
including Discord voice ports, is not redirected or blocked.

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

The native packet callout rewrites the relay's direct connection only when a
one-shot policy has been armed.
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

### Local diagnostics dashboard

Double-click the SplitHello tray icon, or choose **Teşhis panelini aç**, to see
the current engine session and the last 1, 7 or 30 days of completed TLS
decisions. The live strip reports active and still-unclassified flows, session
decisions and active/used strategies. The dashboard keeps the differential
evidence together instead of reducing every failure to a generic "blocked"
counter:

- untouched baseline result (`ServerHello`, timeout, RST, TLS Alert, FIN or an
  unexpected response),
- every attempted profile and its elapsed time,
- winning profile, diagnosis and confidence,
- learned-profile cache hits, unresolved decisions and daily totals.

The panel deliberately labels a timeout/reset-only sequence as a transport
failure, not confirmed censorship. "SNI interference likely" requires a
successful transformed counter-test, or is shown at lower confidence when a
previously learned winner succeeds without repeating the baseline.

Events are stored only in `%APPDATA%\splithello\telemetry.db`. SQLite writes
run on one background writer thread in WAL mode; the relay hot path only moves
a small record into a bounded 4,096-item queue. A saturated queue drops panel
events instead of delaying network traffic. Data is pruned after 30 days and
capped at 50,000 decisions. Live session counters use a versioned named-memory
block with atomic integer updates, so the one-second dashboard refresh neither
scans SQLite nor adds per-packet I/O. Historical data refreshes every ten
seconds.

The embedded dashboard has no external assets and normally makes no network
requests. **Bağlantıyı test et** is the only exception: when explicitly clicked,
it sends one HTTPS `HEAD` request to `www.example.com` through the normal
transparent relay. A successful result verifies the local relay chain; by
itself it is not proof that a site is or is not subject to DPI interference.
The test also checks that the live opened-flow counter advanced; an ordinary
HTTPS response without a relay observation is reported separately instead of
as a false-positive relay success.

### Per-process scope

The **Süreç kapsamı** section in the dashboard persists include/exclude rules
and restarts only the network-engine child process to apply them. Rules accept
case-insensitive executable names, full paths, `*` and `?` wildcards. Exclude
rules always win; if the include list is non-empty, unmatched processes stay on
the normal Windows path. The same rules can be supplied repeatedly on the
command line or stored in `%APPDATA%\splithello\config.json`:

```json
{
  "process_include": ["chrome.exe", "firefox*.exe"],
  "process_exclude": ["steam*.exe", "C:\\Games\\Legacy\\*"]
}
```

Process identity is evaluated at WFP's ALE authorization/redirect layers. Later
UDP packets perform only a bounded tuple lookup and never enumerate processes
or connection tables. A missing application identity is fail-open.

## Architecture

```
Application (Discord, Browser, etc.)
    | Normal TCP/443 connection; no proxy configuration
    v
[SplitHello WFP callout driver]
    | ALE redirect + original-target context; bounded packet policies
    v
[SplitHello - Local Relay] ([::]:1080)
    | 1. Reassembles ClientHello and recovers SNI
    | 2. Reuses the application's validated IP and shared DNS cache
    | 3. Opens a direct TCP connection (dual-stack Happy Eyeballs)
    | 4. Tries learned winner, or untouched baseline before bounded probes
    | 5. Persists only a proven bypass winner per network + hostname
    | 6. Queues completed evidence for local SQLite statistics
    v
[Target Server] (e.g., Discord 162.159.x.x)

Tray controller
    | Reads the same WAL database without blocking the engine
    v
[Local WebView2 diagnostics panel]
```

- No VPN, no tunnel, no external relay server on the data path
- Direct connection to the target; learned winners avoid repeated profile scans
- All applications' TCP/443 flows are covered without per-app proxy settings
- SplitHello's own Worker traffic is excluded by ALE process identity to avoid recursion
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
- **Secrets at rest.** Cloudflare authentication is handled by
  `wrangler login --use-keyring`: Wrangler keeps an encrypted credential file
  whose key lives in Windows Credential Manager. SplitHello never reads or
  stores that OAuth token. Only the Worker shared secret enters `config.json`,
  encrypted with Windows DPAPI. API-token fields written by older releases are
  removed automatically on first run; `--forget-token` remains as a compatible
  manual cleanup command.
- **Driver provenance.** The in-tree callout driver uses pinned official WDK/SDK
  packages. Release artifacts are hash-manifested; production distribution
  still requires a Microsoft-trusted production signature.
- **Fail-closed listener.** Transparent sockets must carry valid WFP redirect
  context. Unsolicited connections are rejected before payload processing.
- **Legacy cleanup.** Builds before transparent mode changed Internet Options.
  A leftover backup is restored on startup; `--restore-proxy` remains available
  solely for migration/recovery.

## Quick Start

### Prerequisites
- 64-bit Windows 10 version 2004 or newer, or 64-bit Windows 11
- [CMake](https://cmake.org/download/) 3.20+
- [Visual Studio](https://visualstudio.microsoft.com/) with C++ workload (or Build Tools)
- [Node.js](https://nodejs.org/) 20+ with npm/npx (used to run Wrangler 4)
- [Microsoft Edge WebView2 Runtime](https://learn.microsoft.com/microsoft-edge/webview2/concepts/distribution) (normally already present on Windows 10/11)
- A free [Cloudflare](https://dash.cloudflare.com/sign-up) account
- Administrator permission at runtime (required to manage the WFP driver/service)

### Build
```bash
pwsh -File driver/build.ps1 -Configuration Release -Rebuild
cmake -B build -S .
cmake --build build --config Release
ctest --test-dir build -C Release
```

The WDK output is test-signed for development. Load it only in a disposable VM
with the test certificate trusted; public releases need production signing.

Note: with the Ninja generator, configure and build from a Developer Command
Prompt so the MSVC include paths are set. The Visual Studio generator (the
default) needs no special shell.

### Fuzzing and CI

The standalone `fuzz/` build keeps production Windows dependencies out of the
sanitizer binaries and targets the three untrusted-input surfaces directly:
TLS records, DNS messages and JSON. With Clang and Ninja installed:

```bash
cmake -S fuzz -B build-fuzz -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz --parallel
./build-fuzz/fuzz_tls -max_total_time=60 -dict=fuzz/tls.dict
./build-fuzz/fuzz_dns -max_total_time=60 -dict=fuzz/dns.dict
./build-fuzz/fuzz_json -max_total_time=60 -dict=fuzz/json.dict
```

`.github/workflows/ci.yml` runs the full Windows Release build/tests and a
Clang AddressSanitizer fuzz smoke job on every push and pull request. Crashing
inputs are uploaded as short-lived workflow artifacts; successful Windows
builds publish an explicitly **unsigned** seven-day artifact until release
signing is configured.

### First Run (Setup)
```bash
build\Release\splithello.exe --setup
```

This will:
1. Run Wrangler 4 and open Cloudflare's browser OAuth flow
2. Store the OAuth session through Wrangler's Windows keyring backend
3. Generate a random shared secret and pipe it to `wrangler secret put`
4. Deploy the embedded Worker and verify it end to end
5. Save only the DPAPI-encrypted Worker secret to
   `%APPDATA%\splithello\config.json`

`--setup` and `--redeploy` explicitly remove API-token environment variables
from the Wrangler child process and force the keyring backend. The shared
secret is passed over an anonymous stdin pipe; it is never written to a
temporary file, command line or deployment log. `npx` may download/cache the
latest compatible Wrangler 4 release on its first run.

### Usage
```bash
splithello.exe
```

The first normal run displays a Windows UAC prompt and then lives in the system
tray. Start/Stop controls remove or restore the WFP path without closing
the tray controller. Double-clicking the icon opens the local diagnostics
dashboard. TCP DPI learning is always adaptive unless `--strategy`
pins a diagnostic profile. QUIC is a separate policy: it passes unchanged by
default so working HTTP/3 services such as YouTube keep their native fast path;
adaptive and block modes remain available through `--quic-mode`.

The network path is fail-open. The owner first disables the driver, then closes
its dynamic WFP session; an unexpected control-handle close also disables
classification, and filters permit traffic if callouts are absent. The tray
restart budget remains capped at three attempts in ten minutes.

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
--manual-proxy       Disable WFP; listen for explicit SOCKS5/CONNECT
--quic-mode <mode>   allow (default), adaptive or block
--allow-quic         Backward-compatible alias for --quic-mode allow
--include-process <pattern>  Process allow-list rule; repeat as needed
--exclude-process <pattern>  Process bypass rule; repeat as needed
--restore-proxy      Restore a proxy backup left by a crash, then exit
--forget-token       Remove a legacy API-token config field, then exit
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
npx wrangler login --use-keyring
npx wrangler secret put SHARED_SECRET
npx wrangler deploy
```
The same secret must be in `%APPDATA%\splithello\config.json`; the simplest way
to keep both sides in sync is to let `--setup` do it.

## How Is This Different from GoodbyeDPI?

| | GoodbyeDPI | SplitHello |
|---|---|---|
| **Level** | Packet (WinDivert kernel driver) | ALE redirect + packet callouts + stateful TLS relay |
| **Technique** | Fake packets, TCP segmentation, TTL tricks | Differential baseline + learned fake/disorder/overlap/AutoTTL/IP-fragment/TLS-record profiles |
| **DNS** | Doesn't handle DNS poisoning | Transparent raw DNS wire forwarding via authenticated DoH |
| **Scope** | Filter-dependent TCP traffic | All non-loopback TCP/443; UDP/443 unchanged by default |
| **Dependencies** | WinDivert driver | Native SplitHello WFP driver + SQLite + WebView2 Runtime + Windows WinHTTP |
| **Admin required** | Yes | Yes, only for transparent mode |
| **Gaming impact** | Can affect broad traffic | Non-443 game/voice traffic bypasses the filter |

## Technical Details

- **Language:** C++20
- **Dependencies:** spdlog, the pinned official SQLite amalgamation, pinned
  Microsoft WebView2 SDK loader, and the in-tree pinned-WDK WFP driver;
  WebView2 Runtime, WinHTTP / IP Helper / ws2_32 / crypt32 / bcrypt / ole32 are supplied by Windows
- **Ingress:** WFP ALE TCP/443 redirect; pass-through UDP/443 by default (IPv4 + IPv6)
- **Manual recovery:** HTTP CONNECT + SOCKS5 (`--manual-proxy`)
- **Worker:** authenticated raw DNS, direct-resolution and optional tunnel endpoints
- **Config:** `%APPDATA%\splithello\config.json`
- **Learned strategies:** `%APPDATA%\splithello\strategies.json` (proven bypass winners only; network-scoped, maximum 1,000 live entries, seven-day TTL)
- **Local telemetry:** `%APPDATA%\splithello\telemetry.db` (SQLite WAL; completed
  TLS evidence only; 30-day / 50,000-decision retention; never uploaded)
- **Live telemetry:** a per-tray-session named-memory block (atomic active-flow,
  decision and profile counters; recreated on engine restart; never uploaded)
- **Runtime log:** `%APPDATA%\splithello\splithello.log` (512 KiB plus two backups; no secrets; seven-day archive retention).
  It records startup/shutdown, learned bypasses, profile changes, QUIC fallback,
  slow paths and failures; ordinary DNS and successful `none` traffic is omitted.
  `--verbose` adds detail to the console without bloating the persistent log.
- **Tests:** `ctest --test-dir build -C Release` (ClientHello/server response
  parsing, DPI diagnosis, strategy planning, SQLite telemetry snapshots,
  live-session counters, process-rule matching and live PID ownership,
  WFP packet parsing/rewrites, JSON)

## Not Yet Implemented

- Signed releases and auto-update
- Full QUIC Initial decryption/re-encryption and CRYPTO-frame fragmentation. The
  current adaptive QUIC mode implements the lower-risk pre-Initial prime and a
  measured TCP fallback; it does not alter encrypted QUIC CRYPTO frames.

## License

SplitHello is MIT licensed. SQLite is in the public domain. The Microsoft WebView2 SDK license and notices
are copied beside every build as `WebView2-LICENSE.txt` and
`WebView2-NOTICE.txt`.
