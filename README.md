# Helicoid Windows apps

Native Windows 11 x64 sources for **Helicoid Manager** (operator console) and **Helicoid Computer** (monitored-computer status), plus a platform-independent domain and development server client.

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

Last local run (macOS, 10 October 2026): **292 passed, 0 failed**.

### Worker / supervisor integration tests

```powershell
dotnet test src/Helicoid.WindowsIntegrationTests/Helicoid.WindowsIntegrationTests.csproj -c Release --nologo
```

Portable pure-protocol facts run everywhere. Windows-native facts
(`[WindowsFact]` — named pipes, Job Objects, kernel PID/session/SID identity,
process launch) report a real xUnit **skip** on non-Windows and are mandatory
on Windows CI. Last local run (macOS): **10 passed, 30 skipped** — the 30
skips are not native proof.

### Full Windows apps (Windows 11 x64)

```powershell
dotnet restore Helicoid.Windows.slnx
dotnet build Helicoid.Windows.slnx -c Release
dotnet test src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj -c Release --nologo
dotnet test src/Helicoid.WindowsIntegrationTests/Helicoid.WindowsIntegrationTests.csproj -c Release --nologo
```

Native Windows CI (`.github/workflows/windows.yml`) also publishes a
reproducible metadata-only CaptureWorker bundle (`SHA256SUMS` manifest) and
runs worker IPC admission checks (missing/malformed fencing env → exit 1).

### Development evidence status

| Claim | Status |
| --- | --- |
| Domain fixture suite | **Verified locally** (292 tests) |
| Portable integration facts | **Verified locally** (10 tests) |
| Windows-native IPC / supervisor / Job Object paths | **Pending Windows CI** — not run on macOS |
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
- Produce production identity, authentication grants, or TLS.

## Package pins (checked on nuget.org, 10 October 2026)

| Package | Version |
| --- | --- |
| Microsoft.WindowsAppSDK | 2.5.1 |
| Microsoft.Windows.SDK.BuildTools | 10.0.28000.2705 |
| Microsoft.NET.Test.Sdk | 18.10.1 |
| xunit | 2.9.3 |
| xunit.runner.visualstudio | 4.0.1 |

CI uses `actions/checkout@v7` and `actions/setup-dotnet@v6` with `dotnet-version: '10.0.x'`.
