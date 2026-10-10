# BUILD-REPORT — Helicoid Windows (`apps/windows`)

Date: 10 October 2026 (CI reconcile + artwork correction)
Host: macOS (Darwin), arm64
SDK: .NET 10.0.401 at `/tmp/hs-toolchain/dotnet` (coordinator-provided; not installed globally)

Local commands below ran on this Mac. **Native WinUI compile is verified by the coordinator on Windows CI; this host cannot compile Windows targets** (`NETSDK1100`).

## Verified on this host

| Check | Command | Result |
| --- | --- | --- |
| Domain + client tests | `dotnet test src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj` | **PASS** — 106 tests, 0 failed |
| Windows brand hashes vs root `assets/brand/HS App icon.icon` | `shasum -a 256` | **PASS** — matches approved Windows source |

## Coordinator Windows CI (not claimed locally)

| Step | Result |
| --- | --- |
| Initial MSIX build | **FAILED** — `Packaged .NET applications with an app host exe cannot be ProcessorArchitecture neutral` |
| Coordinator fix | `-r win-x64 -p:Platform=x64 -p:WindowsPackageType=None` |
| Domain tests on `windows-latest` | **PASS** (coordinator run) |
| Build Helicoid Manager | **PASS** (coordinator run) |
| Build Helicoid Computer | **PASS** (coordinator run) |
| Publish unsigned development output | **PASS** (coordinator run) |

## Changes in this follow-up

### 1. Preserve the working development bundle (architecture failure)

Both WinUI csproj files now embed the CI-verified defaults so a plain
`dotnet build` cannot hit the AnyCPU/MSIX failure again:

| Property | Value |
| --- | --- |
| `Platform` / `Platforms` | `x64` |
| `RuntimeIdentifier` / `RuntimeIdentifiers` | `win-x64` |
| `WindowsPackageType` | `None` (unsigned development output) |
| `WindowsAppSDKSelfContained` / `SelfContained` | `true` |

The workflow keeps the same explicit flags the coordinator used. `Package.appxmanifest` remains in the tree for a future packaging gate.

### 2. Artwork correction (Mac manager icon is not for Windows)

`docs/ui.md` and the brand manifest assign **HS App icon.icon** to Windows
manager **and** monitored computer. The grid **HS Manager App icon.icon** is
**Mac manager only**.

| Path | Assignment | Status |
| --- | --- | --- |
| `Helicoid.Manager/Assets/brand/HS App icon.icon` | Windows manager source | **Active** — hashes match root (`ae154c55…`, `0d41b93c…`, `24c05bca…`) |
| `Helicoid.Computer/Assets/brand/HS App icon.icon` | Windows endpoint source | **Active** — unchanged |
| `Helicoid.Manager/Assets/brand/HS Manager App icon.icon` | Mac manager-only artwork | **Unused scratch retained (not deleted); NOT assigned to Windows** |
| `PROVENANCE.json` (both apps) | — | **Corrected** — Windows assignment is `HS App icon.icon`; Mac grid icon listed under `unusedScratch` |

Native Windows raster/icon exports remain **NOT DONE / NOT PROVEN**.

### 3. Preserved from prior follow-up

- Bounded HTTP timeout (headers + body), async overflow probes, cancel vs timeout.
- Strict DTO/manager-identity validation; 102 domain/client tests including regression suite.

Exact local test output (this turn):

```
Passed!  - Failed: 0, Passed: 106, Skipped: 0, Total: 106, Duration: 307 ms
```

## Test inventory (106)

Inclusion/overview/snapshot, agent/engine, fixtures, setup wizard, closed client, loopback/address/launch options, development HTTP client (contract mocks), address contract, and regression tests (blocked-body timeout, delayed EOF, size boundary, DTO fields, manager identity).

## Accurate commands

Local (macOS/Windows):

```bash
dotnet restore src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj
dotnet test src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj --nologo
```

Windows 11 x64 (matches CI):

```powershell
dotnet build src/Helicoid.Manager/Helicoid.Manager.csproj -c Release -r win-x64 -p:Platform=x64 -p:WindowsPackageType=None
dotnet build src/Helicoid.Computer/Helicoid.Computer.csproj -c Release -r win-x64 -p:Platform=x64 -p:WindowsPackageType=None
dotnet test src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj -c Release --nologo
```

## Open items

1. MSIX **packaged** install still needs a packaging gate (`WindowsPackageType=MSIX` with x64) and native icon export proof.
2. Durable package/service IDs pending a product decision.
3. Production identity / auth remain open; manager identity strings are development fixtures.
4. Screen capture / control / host install remain unimplemented.

## Tests vs platform proof

102 passing tests are domain and HTTP-client unit tests (mock handlers). Coordinator CI proves **native compile + domain tests on Windows**. That is not capture, input, installer, accessibility, or live-server proof.

## Coordinator final checks

Final source passes 112 domain/client tests locally. Literal loopback parsing rejects DNS names beginning with 127.; inventory rejects duplicate IDs and overflow; impossible expiries and required MFA fail closed. The actual client library also passes the live loopback server integration probe. These checks do not prove WinUI runtime behavior; the user will download Windows CI output and report results.
