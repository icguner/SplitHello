# SplitHello

DPI diagnosis and bypass for Windows, without a VPN. For each network and hostname it finds the least invasive method that works and leaves traffic that already works alone.

## What it does

Turkish ISPs block sites in two ways:

1. **DNS poisoning.** A blocked hostname resolves to a fake IP.
2. **SNI inspection.** A DPI box reads the hostname in the TLS ClientHello and kills the connection.

SplitHello deals with both. There is no VPN and no remote server on the data path; it connects to the destination directly.

## How it works

```
app --TCP/443--> WinDivert --> local relay --> destination
                                  |
                                  |  1. read the hostname from the ClientHello
                                  |  2. send it untouched (baseline)
                                  |  3. if that fails, try profiles one by one
                                  '  4. remember the winner per network + hostname
```

WinDivert redirects outbound TCP/443 to a relay on this machine. The relay reads the SNI, sends the first ClientHello unmodified, and only when that fails does it try other profiles. The one that works is remembered.

Only TCP/443 is touched. Games, voice and anything on other ports never go through the relay. UDP/443 (QUIC) passes by default.

### SNI splitting

The most useful profile family splits one ClientHello across several valid TLS records so the hostname is cut in two. The RFC allows a handshake message to span records, so the server reassembles it normally. A DPI box that does not reassemble cannot see the hostname.

### Cost

Ordinary sites keep their TLS bytes, but every connection still passes through the relay, so there is some added latency. Measured on one development machine over 25,703 connections, counting only the TLS profile decision (DNS, the TCP connect to the destination and data transfer are not included):

| Case | Result |
|---|---|
| Normal site | decision median 62 ms, p90 78 ms, p99 203 ms |
| Learned blocked site | +30 to +115 ms |
| First discovery of a blocked site | a few seconds, once |

99.3% of connections went out unchanged and 0.5% needed a profile. Domain-selective routing, which would avoid the relay for normal sites, is discussed in [docs/selective-routing.md](docs/selective-routing.md).

## Learning

One failure is not evidence. A network hiccup fails the baseline and whatever profile was tried at the same moment, which looks exactly like a successful bypass. So a profile is only learned after **two independent failures** of the baseline, at least 60 seconds apart, with no healthy baseline in between.

- Learned entries are scoped to the Windows network identity, so a rule learned at home is not used on a hotspot.
- Entries expire after 7 days.
- Every 30 minutes a learned entry is re-checked against an untouched baseline. If the baseline passes, the entry is dropped, so a wrong lesson fixes itself within the hour.

A profile counts as working only after a complete ServerHello arrives. TLS alerts, block pages, partial records, silent drops and RST are recorded as separate signals.

## DNS and the Worker

### The problem

Beating SNI inspection is not enough if the site never resolves to the right address. Many ISPs poison DNS: you ask their resolver for a blocked hostname and get back a fake IP, or nothing. Changing your DNS server by hand often does not help either, because the ISP can intercept plain UDP/53 to any server, and it can block the well-known public DoH endpoints.

### What the Worker does

In the default **Worker DNS** mode SplitHello captures UDP/53 on your machine and answers it itself:

```
app --DNS query--> WinDivert --> SplitHello --HTTPS--> your Worker --> upstream resolver
                                      |                     (Cloudflare, on your account)
                                      '-- answers the app with the real result
```

The Worker is a small piece of code (`worker/src/index.js`) that runs on your own Cloudflare account. SplitHello sends it the DNS question over ordinary HTTPS, the Worker asks Cloudflare's resolver, and the real answer comes back. From the ISP's side this is just a TLS connection to a `*.workers.dev` hostname that belongs to you, not a DNS query it can rewrite, and not a known DoH server it can blacklist.

Details that matter:

- **Only DNS goes through it.** Your actual traffic still goes straight from your machine to the destination. The Worker never sees page content.
- **It is yours.** `--setup` deploys it to your Cloudflare account with a random secret. Nobody else's Worker is used, and no SplitHello server exists. Without the secret the Worker answers 401, so it cannot be used as an open DNS proxy by anyone who finds the URL.
- **It is free for normal use.** The Cloudflare free plan covers typical home usage. Answers are cached locally, so repeated lookups do not hit the Worker.
- **Nothing else changes.** A/AAAA answers fill a shared cache. Other query types (HTTPS/SVCB, TXT, MX and so on) are forwarded as the original wire message, and real response codes, including NXDOMAIN and ECH configs, reach the application unchanged.
- **No chicken-and-egg problem.** SplitHello looks up the Worker's own address itself, so it does not depend on the DNS it is replacing.
- **Private answers are filtered.** The Worker drops private and loopback addresses from public answers.

### When to pick which mode

| | Worker DNS (default) | System DNS (Worker'sız) |
|---|---|---|
| Poisoned DNS | Fixed | Not fixed |
| Needs a Cloudflare account | Yes, free | No |
| DNS/53 captured | Yes | No, left alone |
| TCP/443 DPI profiles | Active | Active |
| Extra hop for DNS | One HTTPS request per uncached lookup | None |

Choose **Worker DNS** if your ISP poisons DNS, which is the usual case for blocked sites in Turkey. Choose **System DNS** if your resolver already returns correct answers (for example you use a trusted resolver or your own DoH setup), or if you do not want a Cloudflare account involved. In System mode no request is ever made to a Worker, but if your resolver is poisoned, blocked sites will not resolve.

Switch with **DNS: Worker** / **DNS: Sistem (Worker'sız)** in the tray menu, or set `"dns_mode": "system"` in `config.json`. The choice is saved and the engine restarts. Picking Worker with no Worker configured starts the Cloudflare setup.

## Install

Requirements: Windows 10/11, CMake 3.20+, Visual Studio with the C++ workload, admin rights. Worker DNS setup also needs Node.js 20+ and a free Cloudflare account.

```
cmake -B build -S .
cmake --build build --config Release
ctest --test-dir build -C Release
```

```
splithello.exe --setup    # Cloudflare login and Worker deploy
splithello.exe            # normal run
```

`--setup` opens a Cloudflare login in the browser, generates a random shared secret, deploys the Worker and stores the secret encrypted with DPAPI. To run without a Worker, set `"dns_mode": "system"` in `config.json`. A normal run asks for UAC once and then sits in the system tray; double-click the icon to open the dashboard. If no Worker is configured yet, the tray opens the same setup in its own console on first start, and again when you pick **DNS: Worker** without one. When it finishes, the engine starts on its own. The tray menu also has **Cloudflare Worker kurulumunu çalıştır** to run it by hand.

Prebuilt zips are on the [releases page](https://github.com/icguner/SplitHello/releases). Keep `splithello.exe`, `WinDivert.dll` and `WinDivert64.sys` in the same folder.

<details>
<summary>Command-line options</summary>

```
--setup              Connect a Cloudflare account and deploy the Worker
--redeploy           Update the Worker code and rotate the secret
--worker <url>       Set the Worker URL by hand
--port <port>        Relay port (default 1080)
--split-delay <ms>   Delay between TLS record fragments (default 20)
--strategy <name>    Diagnostics: pin one profile and disable learning
--tunnel-fallback    Use the Worker tunnel if every profile fails
--manual-proxy       No WinDivert; listen as SOCKS5 / HTTP CONNECT
--quic-mode <mode>   allow (default), adaptive or block
--allow-quic         Old name for --quic-mode allow
--include-process <pattern>  Only handle matching executables (repeatable)
--exclude-process <pattern>  Skip matching executables (repeatable)
--restore-proxy      Restore a leftover proxy backup after a crash, then exit
--forget-token       Delete a leftover API token field, then exit
--forget-strategies  Clear learned hostname profiles, then exit
--list-strategies    List learned profiles, then exit
--console            Run in the console instead of the tray
--verbose            Verbose console log (implies --console)
--help               Show help
```

`--manual-proxy` never opens WinDivert, so `--quic-mode`, `--allow-quic` and the process filters do nothing there. `--tunnel-fallback` is ignored in system DNS mode because there is no Worker. `--include-process` and `--exclude-process` reject empty patterns and patterns longer than 1,024 bytes.
</details>

<details>
<summary>Process scope</summary>

You can limit which applications are handled. Exclude rules always win. If the include list is non-empty, processes that do not match stay on the normal Windows path.

```json
{
  "process_include": ["chrome.exe", "firefox*.exe"],
  "process_exclude": ["steam*.exe", "C:\\Games\\Legacy\\*"]
}
```

If `process_include` is non-empty but none of its entries is usable (for example only empty strings), the scope is not widened to everything: the engine refuses to start, traffic stays on the normal path and the tray says why. Fix or clear the list.

Rules passed on the command line apply to that run only. The dashboard cannot edit them and only shows how many there are.
</details>

<details>
<summary>Start with Windows, and failures</summary>

**Windows ile başlat** in the tray menu registers a logon scheduled task that runs elevated, with no execution time limit and also on battery. Because it launches the exe elevated every session, it only enables from a folder standard users cannot modify (for example `C:\Program Files\SplitHello`). A profile folder or the desktop is refused with an explanation. Disabling works from anywhere.

If the engine cannot start, the tray shows the reason: port in use, WinDivert could not open or `WinDivert.dll` is missing, invalid process rules, Worker setup missing, or unreadable config. An engine that does not start or stop within 10 seconds is terminated. When the driver handle closes the filter is removed and traffic returns to normal.

A Worker secret that cannot be decrypted (for example one written by another Windows user) is left untouched in `config.json` and a warning is logged.
</details>

## Profiles

| Profile | What it does |
|---|---|
| `none` | Untouched ClientHello, the baseline |
| `sni-mid` | Cut in the middle of the hostname |
| `record-1` | Cut after the first byte |
| `sni-pre`, `sni-multi`, `sni-mid-slow` | Other cut points |
| `packet-reverse` | Send TCP segments in reverse order |
| `packet-ipfrag` | Fragment the IPv4 packet |
| `packet-fake-*` | Send a decoy ClientHello (bad sequence number or checksum) |
| `packet-autottl` | Decoy packet that expires before it reaches the server |

## Compared with GoodbyeDPI

| | GoodbyeDPI | SplitHello |
|---|---|---|
| Method | Fixed packet tricks | Differential baseline plus learned profiles |
| DNS | Not handled | Worker DNS (transparent DoH), or leave DNS alone |
| Scope | Depends on filter | All TCP/443; UDP/443 untouched |
| Other traffic | Wide filters can affect games | Anything not on 443 is untouched |
| Evidence | None | Local SQLite log and a dashboard |

## Security

- Worker endpoints require a bearer secret. With no secret configured the Worker refuses requests, so it cannot become an open DNS proxy.
- The relay only accepts connections that WinDivert saw as a SYN in the last few seconds. It is not an open proxy.
- The Cloudflare login stays in Wrangler's keyring; SplitHello never reads it. The Worker secret is stored encrypted with DPAPI. Wrangler is pinned to an exact version.
- WinDivert 2.2.2 and SQLite are downloaded with pinned SHA-256 hashes; a mismatch stops the build.
- Fail-open: if the driver handle or the relay dies, the filter is removed and traffic returns to normal.
- Telemetry stays on your machine and is never uploaded.

## Technical notes

- C++20, spdlog, SQLite, WinDivert 2.2.2 (fetched at configure time).
- Ingress is WinDivert TCP/443 over IPv4 and IPv6. `--manual-proxy` is the fallback.
- One owned thread per connection, at most 1,024 live connections, idle connections close after 10 minutes, and shutdown cancels and joins every connection.
- Files live in `%APPDATA%\splithello\`: `config.json`, `strategies.json` (1,000 entries, 7 days), `telemetry.db` (capped event history) and `splithello.log` (512 KiB x 3).
- Tests: `ctest --test-dir build -C Release`. They cover TLS parsing, diagnosis, profile planning and re-verification, telemetry migration, process rules, transparent redirect, DNS resolver and cache, and connection lifecycle.

### Fuzzing

```
cmake -S fuzz -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz --parallel
./build-fuzz/fuzz_tls -max_total_time=60 -dict=fuzz/tls.dict
```

The fuzz targets cover TLS records, DNS messages and JSON. CI runs the Windows Release tests and a short sanitizer fuzz job on every push.

## Not done yet

- Signed releases and auto-update.
- Full QUIC Initial decryption and CRYPTO-frame fragmentation. The adaptive QUIC mode only primes the connection and falls back to TCP when needed.

## License

MIT. WinDivert is distributed under its own LGPLv3/GPLv2 dual license; `WinDivert-LICENSE.txt` is copied next to every build. SQLite is public domain. The dashboard uses the Direct2D and DirectWrite components that ship with Windows, so no third-party UI runtime is bundled.
