# SplitHello WFP backend

## Architecture

SplitHello now uses its own WFP callout driver instead of WinDivert. The split
keeps connection policy at the highest layer that preserves the required
semantics:

- `ALE_CONNECT_REDIRECT_V4/V6` redirects selected TCP/443 connections to the
  local relay and attaches a versioned original-target context. Loopback,
  private, link-local and multicast targets stay on their native LAN path.
- `ALE_AUTH_CONNECT_V4/V6` resolves application identity once for outbound
  UDP/53 and UDP/443 tuples and records relay-owned TCP/443 target tuples for
  AutoTTL. The packet path never opens a process.
- `OUTBOUND_IPPACKET_V4/V6` performs only behavior that needs physical packet
  control: DNS reflection, QUIC fallback, TCP sequence variants, fake
  ClientHello packets, and IPv4 fragmentation.
- `INBOUND_IPPACKET_V4/V6` observes QUIC responses for adaptive policy and
  TCP hop distance for AutoTTL.

The accepted relay socket queries WFP redirect context and redirect records.
Those records are applied to same-address-family replacement sockets before
`connect`, which preserves redirect-chain semantics. Cross-family Happy
Eyeballs candidates do not reuse incompatible records; the SplitHello process
ID is always bypassed in ALE classification, so those candidates cannot loop.

## Kernel contract

The shared ABI in `driver/shared/Protocol.hpp` is versioned and fixed-width.
Only administrators and Local System can open the control device. Configuration
is published as an immutable snapshot with rundown protection. Classify paths
are bounded, nonblocking, nonpageable, and use fixed-capacity policy/flow tables.

Packet bytes are flattened from a possibly noncontiguous `NET_BUFFER` into
tagged nonpaged memory. Every injected NBL owns exactly one byte buffer and MDL;
the asynchronous completion callback frees all three. A hard limit of 4096
outstanding injections provides backpressure. Self-injected packets are detected
with `FwpsQueryPacketInjectionState0`.

ALE filters narrow connection authorization by protocol and port. WFP's
`IPPACKET` layers do not expose transport fields as filter conditions, so their
callouts use a bounded header-prefix gate: only selected DNS/QUIC packets and
TCP packets with an armed one-shot policy are copied in full. Inbound TCP hop
sampling reads at most a 256-byte header prefix, checks the relay-owned tuple
and records SYN/ACK packets; it never copies response payloads.

Shutdown is fail-open and ordered:

1. The user-mode owner sends `IOCTL_STOP`; closing its file object also disables
   classification.
2. No new classify callback can acquire rundown protection.
3. Existing callbacks and asynchronous injection completions drain.
4. Injection/redirect handles and NBL pools are destroyed.
5. Runtime callouts unregister and the device is deleted.

The user-mode filter session is dynamic. Filters use
`FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED`, so a missing or unloaded
driver does not black-hole traffic. Only the ALE redirect filters are
terminating; authorization and packet filters are inspection callouts that
return `FWP_ACTION_CONTINUE` unless they actually absorb a replaced packet, so
other firewall/security providers retain their normal classification rights.

## DNS and process isolation

Selected DNS queries are reflected to the local DNS relay with loopback source
and destination addresses. The original client/resolver tuple and DNS
transaction ID plus compartment/interface identity are retained in a bounded
kernel table. Queries use network-send injection; replies are restored to the
original tuple and reinjected on the original network-receive path. The
user-mode DNS relay accepts the WFP path only from loopback; other unsolicited
datagrams are rejected.

Include/exclude rules are case-insensitive and support `*` and `?`. Excludes
win. With at least one include rule, the include list is an allowlist. Rules are
evaluated against both the WFP application path and its basename.

## Reproducible build and verification

The driver workspace pins the official WDK/SDK NuGet packages at
`10.0.28000.2526` and verifies the downloaded NuGet executable hash.

```powershell
.\driver\build.ps1 -Configuration Debug -Rebuild
.\driver\build.ps1 -Configuration Release -Rebuild -Analyze
.\driver\package.ps1 -Configuration Release
```

Both configurations run Universal API validation, signability checks, INF/CAT
generation and test signing. `-Analyze` additionally runs the WDK
`DriverMinimumRules` ruleset. Main application tests compile the kernel-safe
packet core in user mode and cover parsing, rewrite variants, DNS reflection,
fragment construction and malformed input.

Test signatures are not production signatures. Driver loading, unload cycling,
Driver Verifier and network behavior validation must happen only in a disposable
VM as described in `docs/wfp-vm-validation.md`.
