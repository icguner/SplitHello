# WFP VM validation runbook

Driver loading and Driver Verifier are intentionally restricted to a disposable
Windows VM. Building and packaging on a development machine do not install a
service, trust a certificate, or add a WFP filter.

## Prepare the package

From the repository root:

```powershell
.\driver\build.ps1 -Configuration Release -Rebuild -Analyze
.\driver\package.ps1 -Configuration Release
```

Copy `driver/out/package/Release` to a disposable VM snapshot. In an elevated
PowerShell inside that VM:

```powershell
.\Install-TestDriver.ps1 -DisposableVmAcknowledged
.\Run-VerifierCycles.ps1 -DisposableVmAcknowledged -EnableVerifier
Restart-Computer
```

After reboot, return to the package directory and exercise load/query/unload:

```powershell
.\Run-VerifierCycles.ps1 -DisposableVmAcknowledged -Cycles 100
```

Review Event Viewer, `C:\Windows\Minidump`, and kernel debugger output for
Verifier findings. Functional TCP redirect, DNS, QUIC, IPv4/IPv6 and packet
profile tests must be run with `splithello.exe` in the VM; the probe utility
deliberately registers no traffic filters.

## Cleanup

```powershell
.\Uninstall-TestDriver.ps1 -DisposableVmAcknowledged
Restart-Computer
```

The cleanup resets Driver Verifier, removes the demand-start service/package,
and removes the test certificate from Local Machine trust stores.
