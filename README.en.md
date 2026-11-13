<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
  <img src="assets/logo.svg" width="96" alt="SplitHello logo">
</picture>

# SplitHello

[Türkçe](README.md) · English

Censorship bypass and AdGuard-style ad blocking for Windows, in one small app. No VPN, no proxy server in the middle.

- **Opens blocked sites.** Beats SNI-based DPI by learning, per network and hostname, which sites are blocked and which packet trick opens them, and fixes poisoned DNS with encrypted lookups at the provider you pick.
- **Blocks ads, trackers and threats** in every application, at the DNS and TLS level, with HaGeZi lists. No browser extension.
- **Light.** About 27 MB of memory with the default list, under 40 MB with every protection list loaded, and no UAC prompt after installation (the engine runs as a Windows service).

Version 2 is a rewrite in Rust; the C++ engine of v1 lives on only in the git history (tag `v1.0.1`).

## What it does

Turkish ISPs block sites in two ways:

1. **DNS poisoning.** A blocked hostname resolves to a fake IP.
2. **SNI inspection.** A DPI box reads the hostname in the TLS ClientHello and kills the connection.

SplitHello deals with both, and connects to the destination directly: there is no VPN and no remote server on the data path.

```
app ----------------------- TCP/443 -----------------------> destination
        |                                        ^
        '-- WinDivert hands over only the packet that starts a ClientHello
             1. hostname on a protection list? reset the connection
             2. site not known as blocked? forward it untouched
             3. blocked site: send a decoy first, then the real packet
```

Connections stay between the application and the server; nothing is relayed. Of TCP/443 the driver captures only the packet that starts a TLS ClientHello, plus the server's SYN-ACK, ServerHello, reset and close, which are read and passed on. With encrypted DNS on, UDP/53 is captured too. Everything else, including games, voice and all other ports, never leaves the kernel's normal path. UDP/443 (QUIC) passes by default.

### Packet profiles

| Profile | What it does |
|---|---|
| `packet-autottl` | A decoy ClientHello with a harmless name goes first, with a TTL that carries it past the DPI box but not to the server |
| `packet-seqovl` | The hello is cut inside the hostname and sent out of order, with decoy bytes overlapping the cut |
| `packet-reverse` | The two halves of the hello are sent in reverse order |
| `packet-ipfrag` | The IPv4 packet is fragmented inside the hostname |
| `packet-fake-badseq`, `packet-fake-badsum` | A decoy the server discards by its sequence number or checksum |

The decoy's TTL comes from the path length seen in the SYN-ACK, minus a margin, because a decoy that reached the server would break the connection.

### Learning

Nothing can be replayed when the connection belongs to the application, so learning is passive:

- A site is left alone until its untouched ClientHello is answered by a reset or a close instead of a ServerHello. That marks it as blocked; the application sees that one failure.
- Its next connection gets a packet profile. A ServerHello proves the profile and it is saved; another teardown moves on to the next profile. When every profile has failed the site is left alone for 30 minutes.
- A proven profile survives one stray reset. A silent drop is never a verdict: it looks the same as a server that is down.
- Entries are scoped to the Windows network identity, so a site learned at home is not touched on a hotspot, and a profile that worked on a network is where its next blocked site starts.

`--strategy <name>` skips learning and applies one profile to every ClientHello.
## Protection

The **Reklam Engelleme** and **DNS** pages of the panel turn these on and off. Everything is enforced twice. A DNS query for a blocked name is answered with a sinkhole address, with encrypted DNS on by the DNS proxy (which also checks the CNAME chain, so a tracker hidden behind a first-party alias is caught) and with it off by the packet loop, which answers only listed names and lets every other query go to your resolver untouched. And a TLS connection whose SNI is blocked is reset, which covers apps with their own DNS when the name is in the first packet of the ClientHello.

| Feature | What is blocked | List |
|---|---|---|
| Reklam engelleme | Banner, video, pop-up and in-app ads, with a strength choice | HaGeZi Light (89k) / Normal (207k) / Pro (224k, default) / Pro++ (241k) |
| İzleyici koruması | Windows and Office telemetry (web trackers come with the ad list) | HaGeZi Native Windows/Office |
| Rahatsız edici öğeler | Pop-up ad networks | HaGeZi Pop-Up Ads (78k) |
| Şifreli DNS | Encrypted DNS at the provider you pick; optionally blocks apps' own DoH servers so their lookups are covered too | HaGeZi DoH (3.5k) |
| Gezinme güvenliği | Malware, phishing and fake shops | HaGeZi TIF medium + Fake (387k) |
| Ebeveyn denetimi | Gambling, adult content (off by default) | HaGeZi Gambling, NSFW |

Lists are downloaded from the HaGeZi repository, never bundled, and refreshed at most once a day; they are cached on disk, so a restart does not download them again. A failed download backs off (10 minutes up to an hour) and a download with too few entries never replaces a good list. A false positive is one click away: **Serbest bırak** in the panel or the tray's recent-blocks menu.

What it cannot do: cookie banners and other in-page elements are part of the page itself, so they need a browser extension. Blocking works on whole hostnames, not on URL paths.

## Encrypted DNS

Beating SNI inspection is not enough if the site never resolves to the right address. Many ISPs poison DNS and intercept plain UDP/53 to any server.

With **Şifreli DNS** on, SplitHello captures UDP/53 on your machine and answers it itself:

```
app --DNS query--> WinDivert --> SplitHello --HTTPS (DoH)--> the provider you picked
                                      |                         then the others, then your Worker
                                      '-- answers the app with the real result
```

- **Providers.** Cloudflare, Google, AdGuard and DNS.SB, reached by IP address so no plain lookup is involved. The **DNS** page of the panel has the choice; no setup is needed.
- **Failover.** A provider that does not answer is skipped for a minute and the next one is asked. If none answers, queries go to the system resolver until one does, and encrypted DNS resumes by itself; the engine keeps running throughout.
- **Answers are real.** NXDOMAIN, HTTPS/SVCB and ECH records reach applications unchanged. Answers are cached locally.

### Optional fallback: your own Worker

Some networks block the well-known DoH servers. For those, the DNS page can deploy a Worker (`worker/src/index.js`) to your own free Cloudflare account (needs Node.js 20+). It is asked only when no public provider answers. From the ISP's side it is a TLS connection to a `*.workers.dev` hostname that belongs to you, not a known DoH server it can blacklist.

- **Only DNS goes through it.** Page content does not.
- **It is yours.** Setup deploys it with a random 256-bit secret; without the secret it answers 401, so it is never an open resolver. The secret is sent to the Worker only, never to a public provider.

Turn **Şifreli DNS** off (DNS page or tray menu) if your resolver already returns correct answers; DPI profiles and blocking still work, but poisoned names will not resolve.

## Performance

Measured on one Windows 11 machine, same network, same load (600 HTTPS requests, 30 at a time), v1 (C++) against v2.0 (Rust), both intercepting with WinDivert. Both still relayed every connection; the packet-only engine carries no connections and has not been re-measured:

| | v1 (C++) | v2 (Rust) |
|---|---|---|
| Memory (working set after load) | 52 MB | **27 MB** |
| Private memory | 42 MB | **15 MB** |
| Threads | 67 | **13** |
| Handles | 539 | **291** |
| CPU for the load | 24.3 s | 27.9 s |

The CPU difference is within the run-to-run variation of a live network.

Blocklists are held as sorted 64-bit hashes, 8 bytes per name, instead of a string set:

| Every protection feature on (1.25 M names) | String set | v2 |
|---|---|---|
| Resident memory | 96 MB | **11 MB** |
| Peak while loading | 130 MB | **34 MB** |
| Load time | 0.96 s | **0.27 s** |

Bounded by design: the engine holds no connections and no buffers; every table (pending handshakes, path lengths, learned sites) has a cap and amortized eviction, and a burst of new connections reuses one process-table snapshot instead of walking the table per packet.

## Install

Download [SplitHello-Setup.exe](https://github.com/icguner/SplitHello/releases/latest/download/SplitHello-Setup.exe) (always the latest release; older ones are on the [releases page](https://github.com/icguner/SplitHello/releases)) and run it (Windows 10/11 x64). It installs to `C:\Program Files\SplitHello` and registers the **SplitHello** service; this is the only time administrator rights are asked for. The tray then starts with Windows as your normal user and starts the service, without a UAC prompt.

Nothing else needs setting up: protection starts with the tray.

Double-click the tray icon for the panel: **DPI** (learned sites), **Reklam Engelleme**, **DNS** (encrypted DNS, provider, optional Worker), **Uygulamalar** (process rules) and **Kayıtlar** (log).

Settings and learned sites live in `C:\ProgramData\SplitHello`, readable only by SYSTEM, administrators and the user who installed it. The uninstaller removes the service and asks before deleting them. An existing v1 setup (`%APPDATA%\splithello`) is migrated on install.

<details>
<summary>Command-line options</summary>

```
--setup              Connect a Cloudflare account and deploy the Worker
--redeploy           Update the Worker code and rotate the secret
--worker <url>       Set the Worker URL by hand
--strategy <name>    Apply one packet profile to every site and disable learning
--quic-mode <mode>   allow (default), adaptive or block
--include-process <pattern>  Only handle matching executables (repeatable)
--exclude-process <pattern>  Skip matching executables (repeatable)
--install-service    Register the service and the shared folder (installer)
--uninstall-service  Remove the service (uninstaller)
--enable-startup     Start the tray with Windows, then exit
--forget-token       Delete a leftover API token field, then exit
--forget-strategies  Clear learned sites, then exit
--list-strategies    List the packet profiles, then exit
--console            Run the engine in the console instead of the tray
--verbose            Verbose console log (implies --console)
--help               Show help
```

Without the service (a portable copy), the tray asks for UAC once per start.
</details>

<details>
<summary>Process scope</summary>

The **Uygulamalar** page limits which applications are handled. Exclude rules always win. If the include list is non-empty, processes that do not match stay on the normal Windows path. Patterns are case-insensitive with `*` and `?`; a pattern with a backslash matches the full path, any other the file name.

If the include list is non-empty but none of its entries is usable, the scope is not widened to everything: the engine refuses to start, traffic stays on the normal path and the tray says why.
</details>

<details>
<summary>Failures</summary>

If the engine cannot start, the tray shows the reason: DNS port in use, WinDivert could not open, invalid process rules, or unreadable config. Transient failures are restarted automatically (three times in ten minutes); a crash of the service is restarted by Windows. An engine that does not start or stop in time is ended; when its driver handle closes the filter is removed and traffic returns to normal (fail-open).
</details>

## Compared with others

| | GoodbyeDPI | AdGuard for Windows | SplitHello |
|---|---|---|---|
| DPI bypass | Fixed packet tricks | No | Baseline first, learned profiles per network |
| Poisoned DNS | Not handled | Its own DNS servers | Encrypted DNS at a provider you pick, your own Worker as fallback |
| Ad and tracker blocking | No | Yes (filters, cosmetic rules) | Yes (DNS + SNI, hostname lists) |
| Cookie banners, in-page elements | No | Yes | No |
| Traffic not on 443 | Depends on filters | Filtered by app | Untouched |
| Price, source | Free, open | Paid, closed | Free, open (MIT) |

## Security

- Worker endpoints require a bearer secret; with none configured the Worker refuses requests.
- There is no listening proxy. The only local socket is the DNS proxy of encrypted DNS, which answers only queries WinDivert reflected to it; it is not an open resolver.
- The service is installed only from a folder standard users cannot modify. Interactive users may start, stop, query and reload it, but not reconfigure it, so it cannot be pointed at another binary.
- The Worker secret is stored with DPAPI (machine scope, in the access-restricted service folder). The Cloudflare login stays in Wrangler's keyring; SplitHello never reads it. Wrangler is pinned to an exact version.
- Fail-open: if the packet loop or the DNS reader dies, the filter is removed and traffic returns to normal.
- Learned sites stay on your machine and are never uploaded.

## Building

Requirements: Rust 1.99 (pinned in `rust-toolchain.toml`) and the Windows SDK (for the icon resource).

```
cargo build --release
cargo test --workspace
installer\fetch-windivert.ps1      # WinDivert 2.2.2 runtime next to the exe, SHA-256 pinned
installer\build.ps1                # dist\SplitHello-Setup-<version>.exe
```

`splithello.exe` needs `WinDivert.dll` and `WinDivert64.sys` beside it. The installer script needs [Inno Setup 6](https://jrsoftware.org/isinfo.php) and fetches WinDivert itself if it is missing.

The workspace is split by layer: `sh-proto` (TLS, DNS, QUIC parsing and packet builders), `sh-strategy` (passive per-site learning), `sh-flow` (path lengths, DNS reflection registry, QUIC), `sh-core` (config, logging), `sh-adblock`, `sh-net` (HTTPS client), `sh-dns`, `sh-divert` (WinDivert loop and process scope), `sh-engine` (composition, service), `sh-setup` (Cloudflare setup), `sh-ui` (tray, panel). Parsers are fuzzed with cargo-fuzz (`fuzz/`); CI runs fmt, clippy, the tests and a short fuzz pass on every push.

## Not done yet

- Signed releases and auto-update.
- Cosmetic (in-page) filtering.
- Full QUIC Initial decryption and CRYPTO-frame fragmentation. The adaptive QUIC mode only primes the connection and falls back to TCP when needed.

## License

MIT. WinDivert is distributed under its own LGPLv3/GPLv2 dual license; `WinDivert-LICENSE.txt` ships next to the exe. HaGeZi lists are GPL-3.0 and are downloaded at run time, not bundled. Rust dependencies (tokio, rustls, egui/eframe, rusqlite with bundled SQLite and others) are under their own MIT/Apache-2.0-style licenses.
