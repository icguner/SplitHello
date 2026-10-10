# Domain-selective routing

## Goal

Modify the TLS ClientHello only for HTTPS hostnames that are verified as blocked. Normal hostnames should stay on the application's own TCP connection, with no change to any program's executable or proxy settings. A new block cannot be known on the first connection, so this needs passive observation and a check on a later attempt.

## Current limit

Transparent WinDivert mode redirects the TCP/443 SYN to the local relay before the hostname is known. The SNI only arrives in the ClientHello after the TCP connection is up. The relay does not change TLS bytes for normal sites, but it stays in the data path for the life of the connection. So with the current relay it is not possible to decide per hostname and also have zero relay cost for normal sites. WinDivert's network layer also has no process ID directly. See the [WinDivert layers and filters](https://reqrypt.org/windivert-doc.html).

## Intermediate approach that was tried

A PAC file returned `DIRECT` for normal hostnames and the local proxy for Discord. Chromium applied this in a fresh session. The Discord desktop client on the test machine did not use the system PAC setting for its network connections and did not connect to Discord servers through the local proxy. Electron's explicit `--proxy-server` switch worked, but it also sent the Discord process's other hostnames through the proxy. Per-executable or per-application settings were ruled out, so this was not shipped. The experiment code was kept in a local Git stash and the working build was not affected. See the [Electron proxy switches](https://www.electronjs.org/docs/latest/api/command-line-switches).

## Proposed architecture

Based on the documentation and the relay's limits, the best fit is a small **WFP stream callout** plus a user-mode policy service. The callout can hold the first TLS data, read the SNI, and immediately `PERMIT` normal flows. For a verified target it blocks only the first TLS record and injects the modified stream data. TCP sequence number handling stays with the network stack, and the whole connection does not have to move to a user-mode relay. Microsoft documents waiting on and modifying stream data: [stream inspection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/stream-inspection), [modifying stream data](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/modifying-stream-data).

User mode would keep DNS/DoH, network identity, candidate hostnames, the two-failure rule, verification of the working profile, and logging. The driver should only inspect the short, bounded first handshake, and on a parse or service failure it should pass the flow through unchanged. QUIC/UDP/443 and real ECH need a separate design. The first request to a blocked host can still fail before learning completes.

## Prerequisites

The WDK `fwpsk.h` headers and kernel libraries are not installed on the development machine. A new Windows kernel driver also needs a suitable signature, and on a Secure Boot system a test signature alone may not be enough. So it should not be installed on a production machine yet. First, in a test environment with the WDK, build a small permit/continue driver from Microsoft's WFP sample. Then verify modifying a TLS record in one direction and a fail-open shutdown. See the [Windows driver signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-).
