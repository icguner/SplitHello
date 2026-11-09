# SplitHello

Censorship bypass and AdGuard-style ad blocking for Windows, in one small app. No VPN, no proxy server in the middle.

- **Opens blocked sites.** Beats SNI-based DPI by learning, per network and hostname, the least invasive ClientHello change that works, and fixes poisoned DNS through your own Cloudflare Worker.
- **Blocks ads, trackers and threats** in every application, at the DNS and TLS level, with HaGeZi lists. No browser extension.
- **Light.** About 27 MB of memory with the default list, under 40 MB with every protection list loaded, and no UAC prompt after installation (the engine runs as a Windows service).

Version 2 is a rewrite in Rust. The C++ engine of v1 is still in `src/` for reference but is no longer shipped.

## What it does

Turkish ISPs block sites in two ways:

1. **DNS poisoning.** A blocked hostname resolves to a fake IP.
2. **SNI inspection.** A DPI box reads the hostname in the TLS ClientHello and kills the connection.

SplitHello deals with both, and connects to the destination directly: there is no VPN and no remote server on the data path.

```
app --TCP/443--> WinDivert --> local relay --> destination
                                  |
                                  |  1. read the hostname from the ClientHello
                                  |  2. blocked by a protection list? refuse it
                                  |  3. send it untouched (baseline)
                                  |  4. if that fails, try profiles one by one
                                  '  5. remember the winner per network + hostname
```

WinDivert redirects outbound TCP/443 to a relay on this machine. The relay sends the first ClientHello unmodified, and only when that fails does it try other profiles. Only TCP/443 (and, in Worker DNS mode, UDP/53) is touched. Games, voice and anything on other ports never go through the relay. UDP/443 (QUIC) passes by default.

### SNI splitting

The most useful profile family splits one ClientHello across several valid TLS records so the hostname is cut in two. The RFC allows a handshake message to span records, so the server reassembles it normally. A DPI box that does not reassemble cannot see the hostname. Packet-level profiles (reordered segments, IPv4 fragments, decoy hellos) cover DPI boxes that do reassemble.

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

### Learning

One failure is not evidence. A network hiccup fails the baseline and whatever profile was tried at the same moment, which looks exactly like a successful bypass. So a profile is only learned after **two independent failures** of the baseline, at least 60 seconds apart, with no healthy baseline in between.

- Learned entries are scoped to the Windows network identity, so a rule learned at home is not used on a hotspot.
- Entries expire after 7 days, and every 30 minutes a learned entry is re-checked against an untouched baseline. A wrong lesson fixes itself within the hour.
- A profile counts as working only after a complete ServerHello arrives. TLS alerts, block pages, partial records, silent drops and RST are recorded as separate signals.

## Protection

The **Koruma** page of the panel turns these on and off. Everything is enforced twice: DNS queries for a blocked name get an empty answer, and a TLS connection whose SNI is blocked is refused, so apps with their own DNS are covered too.

| Feature | What is blocked | List |
|---|---|---|
| Reklam engelleme | Banner, video, pop-up and in-app ads, with a strength choice | HaGeZi Light (89k) / Normal (207k) / Pro (224k, default) / Pro++ (241k) |
| İzleyici koruması | Windows and Office telemetry (web trackers come with the ad list) | HaGeZi Native Windows/Office |
| Rahatsız edici öğeler | Pop-up ad networks | HaGeZi Pop-Up Ads (78k) |
| DNS koruması | Encrypted DNS through your Worker; optionally blocks apps' own DoH servers so their lookups are covered too | HaGeZi DoH (3.5k) |
| Gezinme güvenliği | Malware, phishing and fake shops | HaGeZi TIF medium + Fake (387k) |
| Ebeveyn denetimi | Gambling, adult content (off by default) | HaGeZi Gambling, NSFW |

Lists are downloaded from the HaGeZi repository, never bundled, and refreshed at most once a day; they are cached on disk, so a restart does not download them again. A failed download backs off (10 minutes up to an hour) and a download with too few entries never replaces a good list. A false positive is one click away: **Serbest bırak** in the panel or the tray's recent-blocks menu.

What it cannot do: cookie banners and other in-page elements are part of the page itself, so they need a browser extension. Blocking works on whole hostnames, not on URL paths.

## DNS and the Worker

Beating SNI inspection is not enough if the site never resolves to the right address. Many ISPs poison DNS, intercept plain UDP/53 to any server, and block the well-known public DoH endpoints.

In **Worker DNS** mode SplitHello captures UDP/53 on your machine and answers it itself:

```
app --DNS query--> WinDivert --> SplitHello --HTTPS--> your Worker --> upstream resolver
                                      |                     (Cloudflare, on your account)
                                      '-- answers the app with the real result
```

The Worker (`worker/src/index.js`) runs on your own free Cloudflare account. From the ISP's side this is a TLS connection to a `*.workers.dev` hostname that belongs to you, not a DNS query it can rewrite or a known DoH server it can blacklist.

- **Only DNS goes through it** (and, if you enable **Tünel yedeği**, connections no profile could open). Page content does not.
- **It is yours.** Setup deploys it with a random 256-bit secret; without the secret it answers 401, so it is never an open resolver. No SplitHello server exists.
- **Answers are real.** NXDOMAIN, HTTPS/SVCB and ECH records reach applications unchanged; private addresses are filtered out of public answers. Answers are cached locally.

Pick **System DNS** if your resolver already returns correct answers or you do not want a Cloudflare account involved; DPI profiles and blocking still work, but poisoned names will not resolve. The **Bağlantı** page of the panel (or the tray menu) switches modes, runs the Cloudflare setup, and redeploys the Worker.

## Performance

Measured on one Windows 11 machine, same network, same load (600 HTTPS requests, 30 at a time), v1 (C++) against v2 (Rust), both intercepting with WinDivert:

| | v1 (C++) | v2 (Rust) |
|---|---|---|
| Memory (working set after load) | 52 MB | **27 MB** |
| Private memory | 42 MB | **15 MB** |
| Threads | 67 | **13** |
| Handles | 539 | **291** |
| CPU for the load | 24.3 s | 27.9 s |

The packet loop itself costs about **205 ns per packet** (rewrite and checksums included); nearly all CPU time is spent in WinDivert and the Windows TCP stack, which both versions share. The CPU difference is within the run-to-run variation of a live network.

Blocklists are held as sorted 64-bit hashes, 8 bytes per name, instead of a string set:

| Every protection feature on (1.25 M names) | String set | v2 |
|---|---|---|
| Resident memory | 96 MB | **11 MB** |
| Peak while loading | 130 MB | **34 MB** |
| Load time | 0.96 s | **0.27 s** |

Bounded by design: at most 1,024 relayed connections (16 KiB of buffer per direction), idle connections close after 10 minutes, every cache has a cap and amortized eviction, and a burst of new connections reuses one process-table snapshot instead of walking the table per packet.

Latency (v1 telemetry over 25,703 connections, TLS decision only): normal sites median 62 ms, p90 78 ms; a learned blocked site +30 to +115 ms; the first discovery of a blocked site takes a few seconds, once. 99.3% of connections went out unchanged.

## Install

Download `SplitHello-Setup-<version>.exe` from the [releases page](https://github.com/icguner/SplitHello/releases) and run it (Windows 10/11 x64). It installs to `C:\Program Files\SplitHello` and registers the **SplitHello** service; this is the only time administrator rights are asked for. The tray then starts with Windows as your normal user and starts the service, without a UAC prompt.

On first start, if no Worker is configured, the tray opens the Cloudflare setup (needs Node.js 20+ and a free Cloudflare account): approve the login in the browser, and the engine starts when it finishes. To skip the Worker, choose **DNS: Sistem (Worker'sız)** in the tray menu.

Double-click the tray icon for the panel: **Durum** (live state), **Koruma**, **Bağlantı**, **Uygulamalar** (process rules), **Teşhis** (local decision history) and **Kayıtlar** (log).

Settings and history live in `C:\ProgramData\SplitHello`, readable only by SYSTEM, administrators and the user who installed it. The uninstaller removes the service and asks before deleting them. An existing v1 setup (`%APPDATA%\splithello`) is migrated on install.

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
--include-process <pattern>  Only handle matching executables (repeatable)
--exclude-process <pattern>  Skip matching executables (repeatable)
--install-service    Register the service and the shared folder (installer)
--uninstall-service  Remove the service (uninstaller)
--enable-startup     Start the tray with Windows, then exit
--forget-token       Delete a leftover API token field, then exit
--forget-strategies  Clear learned hostname profiles, then exit
--list-strategies    List the profiles, then exit
--console            Run the engine in the console instead of the tray
--verbose            Verbose console log (implies --console)
--help               Show help
```

`--manual-proxy` never opens WinDivert and needs no administrator rights; apps must be pointed at the SOCKS5/HTTP proxy. Without the service (a portable copy), the tray asks for UAC once per start.
</details>

<details>
<summary>Process scope</summary>

The **Uygulamalar** page limits which applications are handled. Exclude rules always win. If the include list is non-empty, processes that do not match stay on the normal Windows path. Patterns are case-insensitive with `*` and `?`; a pattern with a backslash matches the full path, any other the file name.

If the include list is non-empty but none of its entries is usable, the scope is not widened to everything: the engine refuses to start, traffic stays on the normal path and the tray says why.
</details>

<details>
<summary>Failures</summary>

If the engine cannot start, the tray shows the reason: port in use, WinDivert could not open, invalid process rules, Worker setup missing, or unreadable config. Transient failures are restarted automatically (three times in ten minutes); a crash of the service is restarted by Windows. An engine that does not start or stop in time is ended; when its driver handle closes the filter is removed and traffic returns to normal (fail-open).
</details>

## Compared with others

| | GoodbyeDPI | AdGuard for Windows | SplitHello |
|---|---|---|---|
| DPI bypass | Fixed packet tricks | No | Baseline first, learned profiles per network |
| Poisoned DNS | Not handled | Its own DNS servers | Your own Worker (encrypted) |
| Ad and tracker blocking | No | Yes (filters, cosmetic rules) | Yes (DNS + SNI, hostname lists) |
| Cookie banners, in-page elements | No | Yes | No |
| Traffic not on 443 | Depends on filters | Filtered by app | Untouched |
| Price, source | Free, open | Paid, closed | Free, open (MIT) |

## Security

- Worker endpoints require a bearer secret; with none configured the Worker refuses requests.
- The relay only accepts connections whose SYN WinDivert saw in the last few seconds; it is not an open proxy.
- The service is installed only from a folder standard users cannot modify. Interactive users may start, stop, query and reload it, but not reconfigure it, so it cannot be pointed at another binary.
- The Worker secret is stored with DPAPI (machine scope, in the access-restricted service folder). The Cloudflare login stays in Wrangler's keyring; SplitHello never reads it. Wrangler is pinned to an exact version.
- Fail-open: if the packet loop, the relay or the DNS reader dies, the filter is removed and traffic returns to normal.
- Telemetry stays on your machine and is never uploaded.

## Building

Requirements: Rust 1.99 (pinned in `rust-toolchain.toml`), the Windows SDK (for the icon resource), and the WinDivert 2.2.2 x64 runtime (`WinDivert.dll`, `WinDivert64.sys`) next to the exe. `cmake -B build -S .` fetches WinDivert with a pinned SHA-256 into `build\`.

```
cargo build --release
cargo test --workspace
installer\build.ps1 -Version 2.0.0 -BuildDir target\release
```

The installer script needs [Inno Setup 6](https://jrsoftware.org/isinfo.php) and `WinDivert.dll`, `WinDivert64.sys` and `WinDivert-LICENSE.txt` in the build folder.

The workspace is split by layer: `sh-proto` (TLS, DNS, QUIC parsing and packet builders), `sh-strategy` (profiles, diagnosis, learning store), `sh-flow` (flow registries), `sh-core` (config, logging, live stats), `sh-telemetry` (SQLite history), `sh-adblock`, `sh-net` (HTTP, Worker tunnel), `sh-dns`, `sh-relay`, `sh-divert` (WinDivert loop and process scope), `sh-engine` (composition, service), `sh-setup` (Cloudflare setup), `sh-ui` (tray, panel). Parsers are fuzzed with cargo-fuzz (`fuzz-rs/`); CI runs fmt, clippy, the tests and a short fuzz pass on every push.

## Not done yet

- Signed releases and auto-update.
- Cosmetic (in-page) filtering.
- Full QUIC Initial decryption and CRYPTO-frame fragmentation. The adaptive QUIC mode only primes the connection and falls back to TCP when needed.

## License

MIT. WinDivert is distributed under its own LGPLv3/GPLv2 dual license; `WinDivert-LICENSE.txt` ships next to the exe. HaGeZi lists are GPL-3.0 and are downloaded at run time, not bundled. Rust dependencies (tokio, rustls, egui/eframe, rusqlite with bundled SQLite and others) are under their own MIT/Apache-2.0-style licenses.
