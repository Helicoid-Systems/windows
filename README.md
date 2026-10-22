<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="logos/hs%20logo%20white.svg">
    <source media="(prefers-color-scheme: light)" srcset="logos/hs%20logo%20dark.svg">
    <img src="logos/hs%20logo%20dark.svg" width="80" alt="Helicoid Systems">
  </picture>
</p>

<h1 align="center">Helicoid for Windows</h1>

<p align="center">
Native Windows 11 computer monitoring and remote assistance — manager console and monitored-computer status.
</p>

<br>

<div align="center">
<table width="100%">
<thead>
<tr>
<td align="center" colspan="2" width="1200">

### About this repo

Native Windows 11 x64 sources for **Helicoid Manager** (operator console) and **Helicoid Computer** (monitored-computer status), plus a platform-independent domain and development server client. WinUI 3 apps on the Windows App SDK, from Helicoid Systems. Durable package and service identifiers remain pending a product decision.

<br>

</td>
</tr>
</thead>
<tbody>
<tr>
<td align="center" colspan="2" width="1200">

### Our Purpose

Computers first: inclusion, preview grid, and selected-or-displayed actions, with honest empty, offline, and engine-unavailable states. No default fake computers — sample data is behind an explicit development fixture toggle, labeled as sample data. Capture, input forwarding, and server installation stay out of this build.

The 20 October native UI checkpoint adds automatic session-bound inventory loading, stable Grid/List selection, four preview-size presets, a complete Computers panel, and independent view-only windows with revocation cleanup. Computer status is compact and reflects actual supervisor metadata. Unsupported installation and remote-engine actions remain unavailable. The coordinator reproduced 496 portable tests; native WinUI build and installed visual acceptance are separate checks.

A later source-only continuation adds a grant-bound Windows Computer observation peer and bounded GDI primary-display capture, plus the shared Qt Manager signaling and frame-receive path. Native observation capability bits remain disabled and the Windows native DLL is absent from this checkout, so the source does not provide an active preview in a packaged build. This work has no Windows compile or installed runtime acceptance yet.

The Windows Computer status window can redeem a Manager endpoint invitation from **Enroll this computer**. It requires the server HTTPS origin, deployment ID, invitation ID and one-time code, plus the deployment CA certificate and its SHA-256 fingerprint obtained through the organization's trusted setup channel. The client pins that CA and origin for the request, stores the Ed25519 endpoint identity with current-user DPAPI, and saves the accepted enrollment receipt and pinned transport trust as DPAPI-protected metadata. One Windows Computer installation keeps one endpoint identity bound to its accepted deployment. The receipt means the invitation was accepted at that time; it does not report current approval, capture, observation, or input authority. Before endpoint authentication, the client checks `/health` and stops unless `features.file_jobs=true`; the current server source advertises `true`. The source receiver binds its signed endpoint session to the current process SID and signs the OS account label only while that process is in the active physical-console session, then rechecks the SID and session before each chunk and local commit. The server binds new targets to that SID. On a detected console-user change, the client uses an unbound session proof to revoke the previous file session when its protected identity is available; that session cannot lease files. Files publish without overwriting into the per-user `LocalAppData/Helicoid/Computer/Received Files` folder. The Manager preflights a fresh endpoint session and confirms the named account and computer; job creation is bound to that exact session ID. It polls every two minutes when enabled. D29 now has a source-level identity, pause, and unbound-session update path, but this source implementation has not yet been built or exercised on Windows, and V48 acceptance remains outstanding. The endpoint enrollment and file-session proof formats follow `../../modules/server/contracts/http-v2.md`.

The enrolled Computer status window also has an explicit **Review File Requests** action. It lists only requests assigned to that computer, shows instructions and limits, displays the signed current user's submission history, and opens the native multi-file picker. Selected files are opened through handles that reject reparse points and directories, bounded to the request's count and 128 MiB total, and hashed before their manifest is reserved. Upload uses 256 KiB chunks, validates each returned chunk receipt, checks the complete upload digest, and requires a verified `received` response. A replacement requires selecting an exact received submission ID and confirming the replacement in a second dialog. Windows source is not built or exercised in this environment; this is source coverage only.

<br>

</td>
</tr>
</tbody>
</table>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="icons/stripes.svg">
  <source media="(prefers-color-scheme: light)" srcset="icons/stripes-white.svg">
  <img src="icons/stripes.svg" width="100%" height="32" align="absbottom" alt="">
</picture>
<p></p>
<table width="100%">
<tbody>
<tr>
<td align="center" colspan="2" width="1200">

### <picture><source media="(prefers-color-scheme: dark)" srcset="icons/windows-white.svg"><img src="icons/windows-dark.svg" height="24" align="absmiddle" alt=""></picture> Helicoid Manager

Operator console: Connection, Computers inventory with grid/list/search, inclusion panel, and Server Setup. Overview state keeps inclusion, displayed IDs, selection, action snapshots, and admitted streams separate.

```
dotnet build Helicoid.Windows.slnx -c Release
```

<a href="src/Helicoid.Manager">Manager sources</a>
<br><br>

</td>
</tr>
<tr>
<td align="center" colspan="2" width="1200">

### <picture><source media="(prefers-color-scheme: dark)" srcset="icons/windows-white.svg"><img src="icons/windows-dark.svg" height="24" align="absmiddle" alt=""></picture> Helicoid Computer

Monitored-computer status: honest operator status with no user Stop Control command. Window icon and taskbar identity come from the role-specific Windows icon.

<a href="src/Helicoid.Computer">Computer sources</a>
<br><br>

</td>
</tr>
</tbody>
</table>
</div>

## Status

Native pinned-HTTPS v2 device-key challenge sign-in (contract rev2 completion-key
binding), conditional TOTP UI, DPAPI device-key storage and automatic session
expiry pass coordinator checks and native Windows CI at `93f14f9`. CI runs on
Windows Server 2025; installed Windows 11 and live UI acceptance remain
Not Verified. Media/control/hosting feature flags stay closed.

Product identity: Helicoid, from Helicoid Systems. Durable package and service identifiers remain pending a product decision.

## Layout

| Path | Role | Builds on |
| --- | --- | --- |
| `src/Helicoid.Domain` | Domain model, overview state, setup wizard, agent status, loopback development HTTP client | Any OS with .NET 10 SDK |
| `src/Helicoid.Domain.Tests` | xUnit tests (domain + HTTP client with mock handlers) | Any OS with .NET 10 SDK |
| `src/Helicoid.Manager` | WinUI 3 manager (Computers grid/list/search, inclusion panel, connection page, server setup) | Windows 11 x64 only |
| `src/Helicoid.Computer` | WinUI 3 monitored-computer status (honest operator status, no user Stop Control) | Windows 11 x64 only |
| `contracts/` | Byte-identical copy of the server HTTP contract v1 with provenance | n/a |
| `.github/workflows/windows.yml` | Windows CI: domain tests, Release build, unsigned dev artifact | runs on GitHub `windows-latest` |

WinUI projects target `net10.0-windows10.0.19041.0` and use Windows App SDK 2.5.1. They require a Windows host.

Development bundle defaults (CI-verified): `Platform=x64`, `RuntimeIdentifier=win-x64`, `WindowsPackageType=None`, self-contained. Packaged .NET apps cannot be ProcessorArchitecture neutral; these pins avoid that MSIX failure. Override on the command line only with the same values.

## Build and test

### Domain and tests (macOS and Windows)

Portable fixture proof — wire parsing, fencing algebra, timing validation.
Runs on any OS with the .NET 10 SDK:

```bash
dotnet test src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj -c Release --nologo
```

Last portable run (macOS, 17 October 2026, callback-crossing expiry notification): **458 passed, 0 failed, 0 skipped**, including **13/13** independent CoordinatorReview cases (stale authorized body fencing, high-frequency rearm, queued UI inventory preserve, delayed-timer dispatch, expiry-between-callback-checks). [Native CI39018316028](https://github.com/Helicoid-Systems/windows/actions/runs/39018316028) at `93f14f9373d23bcef839a8117bbb658ae97e6259` passes **458 domain / 67 native integration tests** and both WinUI release builds on Windows Server 2025. Installed Windows 11 acceptance remains Not Verified.

### Worker / supervisor integration tests

```powershell
dotnet test src/Helicoid.WindowsIntegrationTests/Helicoid.WindowsIntegrationTests.csproj -c Release --nologo
```

Portable pure-protocol facts run everywhere. Windows-native facts
(`[WindowsFact]` — named pipes, Job Objects, kernel PID/session/SID identity,
process launch) report a real xUnit **skip** on non-Windows and are mandatory
on Windows CI. Last local run (macOS): **10 passed, 37 skipped** — the 37
skips are not native proof.

Native CI is bounded: job/step `timeout-minutes`, `dotnet test --blame-hang
--blame-hang-timeout 5m`, and `if: always()` upload of TRX results and dumps.
The complete self-contained CaptureWorker runtime bundle is staged in a
`CaptureWorker` subdirectory beside the test assembly so its runtime files do
not overwrite the test host's files.

### Full Windows apps (Windows 11 x64)

```powershell
dotnet restore Helicoid.Windows.slnx
dotnet build Helicoid.Windows.slnx -c Release
dotnet test src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj -c Release --nologo
dotnet test src/Helicoid.WindowsIntegrationTests/Helicoid.WindowsIntegrationTests.csproj -c Release --nologo
```

Native Windows CI (`.github/workflows/windows.yml`) publishes a reproducible,
self-contained CaptureWorker bundle (`SHA256SUMS` manifest). The worker can
capture one bounded primary-display frame only after an authenticated,
generation-fenced IPC request from the Computer process; it has no server
credentials or input operation. CI also checks fail-closed worker startup when
mandatory environment and fencing fields are missing or malformed.

### Development evidence status

| Claim | Status |
| --- | --- |
| Domain and real HTTPS transport suite | **Verified on macOS and Windows Server 2025 CI** (458 tests at `93f14f9`) |
| Portable integration facts | **Verified locally** (10 tests) |
| Windows-native IPC / supervisor / Job Object paths | **Verified at `93f14f9`** (67 tests on Windows Server 2025 CI) |
| Capture / input / network | **Closed** — no admitted ABI yet |

## Development server mode

The default build uses a closed production client and does not sign in.

To try the loopback development server:

```powershell
.\Helicoid.Manager.exe --development-server --development-manager-identity my-dev-manager
```

| Switch | Meaning |
| --- | --- |
| `--development-server` | Enable the loopback HTTP client (default `http://127.0.0.1:8787`) |
| `--development-server=http://127.0.0.1:8787` | Explicit loopback address |
| `--development-manager-identity <label>` | Development manager identity string |

Rules enforced by the client:

- Literal loopback HTTP only (`127.0.0.1`, `localhost`, `::1`). Remote hosts are refused before any request.
- Redirect responses are refused and never followed.
- Session tokens are held in memory only. They are never logged or written to disk.
- Passwords and tokens never appear in status messages or exceptions.
- Response bodies are size-bounded.
- Manager identity values are development labels, not production cryptographic identities.

The development server (`modules/server`) is loopback development only. It reports no live computer presence or frames, so inventory shows honest offline/pending states.

## What this source tree does and does not do

Does:

- Overview state keeps inclusion, displayed IDs, selection, action snapshots, and admitted streams separate.
- No default fake computers. Sample data is behind an explicit development fixture toggle, labeled as sample data.
- Remote engine reports unavailable in plain language. No ABI exports are invented.
- Server setup wizard offers Windows local and Linux SSH only; install stays honest about not changing the host.
- Helicoid Computer has no user Stop Control command.
- Development HTTP client matches the server contract DTOs with named failures and tests.

Does not:

- Build or run the WinUI apps on macOS (see `BUILD-REPORT.md`).
- Capture screens, forward input, or install servers.
- Produce production identity or authentication grants. The separately constructed pinned HTTPS transport is implemented, but production sign-in and trust adoption are not wired into the applications.

## Wireframe assets

Header, section, and product-list styling follows the templates repo wireframe: centered `picture` logo with dark/light `srcset`, full-width `About` / `Purpose` tables, `icons/stripes.svg` separator, and the stacked product list with `icons/windows-*.svg` headings. `icons/` and `logos/` here are verbatim copies from `Helicoid-Systems/templates` so the above `srcset` paths resolve.

## Package pins (checked on nuget.org, 10 October 2026)

| Package | Version |
| --- | --- |
| Microsoft.WindowsAppSDK | 2.5.1 |
| Microsoft.Windows.SDK.BuildTools | 10.0.28000.2705 |
| Microsoft.NET.Test.Sdk | 18.10.1 |
| xunit | 2.9.3 |
| xunit.runner.visualstudio | 4.0.1 |

CI uses `actions/checkout@v7` and `actions/setup-dotnet@v6` with `dotnet-version: '10.0.x'`.

Native [UI checkpoint CI 39343145295](https://github.com/Helicoid-Systems/windows/actions/runs/39343145295) passes at `b6f17fb61879c970242bf6784affb7f27f6a6146`: both WinUI applications compile and publish, 496 domain tests and 67 native integration tests pass, and supplied icons/launcher checks pass. The [unsigned x64 development bundle](https://github.com/Helicoid-Systems/windows/actions/runs/39343145295/artifacts/12230215088) is available for installed-device acceptance. Installed graphical/DPI/accessibility tests, actual capture/input, installation, production signing and deployment acceptance remain Not Verified.
