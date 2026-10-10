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

---

## Follow-up: Windows physical-console diagnostic (D26/RD03/V40 prerequisite)

Date: 10 October 2026
Host: macOS (Darwin), arm64
SDK: .NET 10.0.401 at `/tmp/hs-toolchain/dotnet` (coordinator-provided; not installed globally)

### Verified on this host

| Check | Command | Result |
| --- | --- | --- |
| Domain + client + policy tests | `dotnet restore --locked-mode` then `dotnet test src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj -c Release` | **PASS** — 157 tests, 0 failed (112 prior + 45 new) |
| ConsoleProbe compile | `dotnet build src/Helicoid.ConsoleProbe/Helicoid.ConsoleProbe.csproj -c Release` | **PASS** — 0 warnings, 0 errors |
| ConsoleProbe `--help` | `dotnet exec … Helicoid.ConsoleProbe.dll --help` | **PASS** — exit 0 |
| ConsoleProbe unknown args | `dotnet exec … --bogus` | **PASS** — exit 2 |
| ConsoleProbe fail-closed (no WTS on macOS) | `dotnet exec … Helicoid.ConsoleProbe.dll` | **PASS** — exit 0, `eligible: false`, `reason: ApiUnavailable`, sentinel `physicalConsoleSessionId: 4294967295` preserved (no int wrap) |
| Workflow YAML | `ruby -ryaml -e YAML.load_file(...)` | **PASS** |

### Added (owned: `apps/windows/**` only)

| Path | Role |
| --- | --- |
| `src/Helicoid.Domain/PhysicalConsole/*` | Pure eligibility policy records (no native APIs) |
| `src/Helicoid.Domain.Tests/PhysicalConsoleEligibilityPolicyTests.cs` | 45 denial tests (sentinel, session 0, wrong/changed IDs, RDP/legacy/unknown protocol, non-Active/unknown connect state, lock/secure/missing/other desktop, API failure, fail-closed ordering) |
| `src/Helicoid.ConsoleProbe/*` | Windows x64 .NET10 console diagnostic (separate artifact; not in WinUI bundle) |
| `.github/workflows/windows.yml` | Independent ConsoleProbe build/publish + result-shape assertion + `helicoid-windows-console-probe` artifact |

Preserved untouched: WinUI app source, brand/icons, HTTP client contract, existing 112 tests (still present inside the 157), WinUI bundle contents and artifact name `helicoid-windows-unsigned-dev`.

### Coordinator Windows CI (not claimed locally)

| Step | Result |
| --- | --- |
| Domain tests (`--locked-mode` restore) | **NOT RUN** (coordinator) |
| ConsoleProbe publish self-contained win-x64 | **NOT RUN** (coordinator) |
| ConsoleProbe run + result-shape assertion | **NOT RUN** (coordinator) |
| `helicoid-windows-console-probe` artifact upload | **NOT RUN** (coordinator) |

### NOT VERIFIED — installed-system matrix

The full installed **console + RDP + lock/transition** matrix is **NOT VERIFIED**.
CI asserts JSON result shape only (CI may have no physical console). No claim of
V40/B03, admission, capture authorization, or enrollment is made.

Remaining unverified combinations include at least:

| Console | RDP | Lock / secure / transition | Expected | Status |
| --- | --- | --- | --- | --- |
| unlocked Active, protocol 0, Default desktop, process in console | absent | none | Eligible (diagnostic only) | **NOT VERIFIED** |
| unlocked Active console | present | none | Physical console only | **NOT VERIFIED** |
| none (sentinel) | any | attach/detach transition | NoConsoleSessionAttached | **NOT VERIFIED** |
| any | only RDP | any | ProtocolNotConsole / No Console User | **NOT VERIFIED** |
| any | any | Winlogon / Secure desktop | DesktopProtected | **NOT VERIFIED** |
| any | any | locked / disconnected | ConnectStateNotActive | **NOT VERIFIED** |
| any | any | session change during probe | ObservationUnstable | **NOT VERIFIED** |
| process not in console session | any | any | ProcessSessionMismatch | **NOT VERIFIED** |
| any | any | WTS API failure | ApiUnavailable | **NOT VERIFIED** (host-only fail-closed observed) |

This artifact is a **working candidate diagnostic**, not production authorization.

---

## Follow-up 2: reviewer fixes + development launcher

Date: 10 October 2026
Host: macOS (Darwin), arm64
SDK: .NET 10.0.401 at `/tmp/hs-toolchain/dotnet`

### Changes

| Item | Files |
| --- | --- |
| UOI_NAME probe bugfix | `Native/DesktopNameReader.cs` (new), `Native/DesktopNative.cs`, `PhysicalConsoleObserver.cs` — accept FALSE+ERROR_INSUFFICIENT_BUFFER=122 probe; allocate exact needed; validate terminated UTF-16; never truncate; never close borrowed `GetThreadDesktop` handle |
| WTS buffer hygiene | `PhysicalConsoleObserver.cs` — free nonzero buffer even when API false; primitive lengths exact 4/2 |
| `--native-query-check` | `Program.cs`, `DesktopNative.cs` — `GetThreadDesktop(GetCurrentThreadId())` borrowed handle + same reader; sanitized bool only; exit 3 on failure |
| Development launcher | `scripts/start-development-manager.cmd` — explicit `--development-server=http://127.0.0.1:8787 --development-manager-identity dev-manager-key`; quoted sibling path; exit 1 if missing |
| Bundle tester README | `scripts/BUNDLE-TESTING.md` |
| Native launcher tests | `scripts/test-start-development-manager.ps1` — fake `Helicoid.Manager.exe` argv record (path with spaces, foreign cwd) + missing-exe exit 1; no real GUI |
| Exact launcher args domain test | `DevelopmentServerClientTests.cs` `LauncherBundleExactArgs_EnableDevelopmentLoopback` |
| CI wiring | `windows.yml` — stage launcher+README beside manager; run launcher tests; run `--native-query-check` and require `nativeQueryCheck == true` |

### VERIFIED on this host

| Check | Command | Result |
| --- | --- | --- |
| Locked restore + domain tests | `dotnet restore --locked-mode` then `dotnet test` | **PASS** — 158 tests, 0 failed |
| ConsoleProbe build | `dotnet build src/Helicoid.ConsoleProbe/… -c Release` | **PASS** — 0 warnings, 0 errors |
| `--help` | `dotnet exec … --help` | **PASS** — exit 0 |
| Unknown args | `dotnet exec … --bogus` | **PASS** — exit 2 |
| `--native-query-check` (macOS, no user32) | `dotnet exec … --native-query-check` | **PASS** (fail-closed) — `nativeQueryCheck: false`, exit 3 |
| Full diagnostic fail-closed | `dotnet exec …` | **PASS** — exit 0, `eligible: false`, `ApiUnavailable`, sentinel 4294967295 preserved |
| Workflow YAML | `ruby -ryaml` | **PASS** |

### NOT VERIFIED (coordinator Windows CI)

| Check | Status |
| --- | --- |
| `--native-query-check` == true on real Windows | **NOT VERIFIED** — CI asserts it; not run here |
| Launcher argv forwarding via fake `Helicoid.Manager.exe` | **NOT VERIFIED** — test script ready; needs native Windows |
| Missing-executable exit 1 | **NOT VERIFIED** — same |
| Paths-with-spaces + foreign cwd | **NOT VERIFIED** — same |
| Actual Manager GUI + development badge + admin sign-in | **NOT VERIFIED** — do not launch GUI in noninteractive CI |
| Installed console+RDP+lock/transition matrix | **NOT VERIFIED** (unchanged) |

No WinUI security mode, visuals, or default production mode were changed.
No credentials are embedded in the launcher.

## Coordinator review, 10 October 2026

A fresh compiled-decoder probe reproduced `Default\0Winlogon\0` being
accepted as the `Default` prefix. The decoder now requires one final terminator
and rejects empty, odd, overlong, unpaired-surrogate and inconsistent-length
buffers. Thirteen regression cases compile the exact native-reader sources
into the portable test assembly. Locked restore and all **171** domain/client/
console-policy/decoder tests pass; ConsoleProbe builds with zero warnings. The
same compiled-decoder probe now rejects the malformed name. This is buffer
validation evidence, not physical-console authorization.

The missing-executable CMD branch now pauses so a double-click retains the
diagnostic; the native Windows fixture supplies a dismissal key and asserts
retained text plus exit 1. Native launch forwarding and positive UOI query
remain pending the new CI run.

The user confirmed the already-published app pair launches, the development
server launcher works, and Manager sign-in works when explicitly launched with
development switches. The new CMD wrapper itself still requires a Windows
runtime check. Full console/RDP/lock and navigation matrices remain unverified.
