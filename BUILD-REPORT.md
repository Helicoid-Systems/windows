# BUILD-REPORT — Helicoid Windows (`apps/windows`)

Date: 10 October 2026 (review fixes)  
Host: macOS (Darwin), arm64  
SDK: .NET 10.0.401 at `/tmp/hs-toolchain/dotnet` (coordinator-provided; not installed globally)

This report records commands actually executed on this machine. Windows UI, MSIX packaging, capture, and input were **not** run here.

## Verified on this host

| Check | Command | Result |
| --- | --- | --- |
| Domain + client tests | `dotnet test src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj` | **PASS** — 88 tests, 0 failed (exit 0) |
| NuGet lock files for domain | `dotnet restore src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj` | **PASS** |
| Contract copy integrity | `shasum -a 256` source vs `contracts/http-v1.md` | **PASS** — identical `20a3e649…f28d5` |

Exact test output (this turn):

```
Passed!  - Failed: 0, Passed: 88, Skipped: 0, Total: 88, Duration: 34 ms
```

## Review findings fixed

| Finding | Fix | Regression test |
| --- | --- | --- |
| `ActionSnapshot` exposed mutable `List` behind `IReadOnlyList` | Collections wrapped in `Array.AsReadOnly` (`ReadOnlyCollection`) | `ActionSnapshotImmutabilityTests.Freeze_CollectionsCannotBeMutatedThroughCast` |
| `LoginAsync` left a previous bearer alive when a later sign-in failed | `ClearSession()` before every attempt and on all failure paths (validation, transport, denial, parse) | `FailedSecondLogin_DoesNotRetainFirstIdentity`, `FailedSecondLogin_OnValidationError_AlsoClearsFirstIdentity` |
| `MapInventory` treated missing `computers` as empty and skipped empty IDs | Missing `computers` list, missing `id`, and missing `enrollment_state` are rejected as `InvalidResponse` | `MalformedInventory_EmptyObject_IsRejected`, `Inventory_MissingComputersList_IsRejected`, `Inventory_ComputerWithoutId_IsRejected` |
| Direct `DevelopmentServerClient(Uri)` accepted credentials/fragments unlike the factory | Shared `LoopbackAddress.RequireDevelopmentBaseAddress` used by every construction path | `AddressContractTests.Constructor_RefusesEmbeddedCredentials`, `Constructor_RefusesFragment`, `Factory_RefusesEmbeddedCredentials`, `Factory_RefusesFragment` |
| `localhost` resolved via DNS | `CanonicalizeLoopback` rewrites localhost/`::1` names to `127.0.0.1` before use | `Localhost_IsCanonicalizedToLiteralLoopback`, `Constructor_AlsoCanonicalizesLocalhost` |
| `HttpClient` not disposed when handler was caller-owned | `Dispose()` always disposes `_http` (`disposeHandler: false` preserves the injected handler) | code fix; covered by lifetime of existing tests |
| Required DTO fields not validated | Health requires `status` + `schema_version > 0`; login requires `token`, `account.id`, `expires_at_unix > 0`; session requires `account.id` | `Health_MissingRequiredFields_IsRejected`, `Login_MissingAccount_IsRejectedAndSessionCleared`, `Login_MissingToken_IsRejectedAndSessionCleared`, `Session_MissingAccount_IsRejected` |
| Cancellation not a named failure | `OperationCanceledException` mapped to `Cancelled` / `Timeout` | `Cancellation_IsNamedFailure` |
| Exact-size response boundary | Overflow probe: EOF at limit is allowed, any further byte rejects | `ExactSizeResponse_IsAccepted`, `ResponseOneByteOverLimit_IsRejected` |

Unchanged guarantees: status-based non-2xx errors, tokens private (never logged/persisted), redirects refused.

## Test inventory (88)

| Area | Count |
| --- | --- |
| `MonitoringInclusionTests` | 7 |
| `OverviewStateTests` | 11 |
| `ActionSnapshotTests` + `ActionSnapshotImmutabilityTests` | 3 |
| `AgentStatusTests` | 5 |
| `RemoteEngineStatusTests` | 1 |
| `DevelopmentFixtureModeTests` | 3 |
| `SetupWizardTests` | 6 |
| `ClosedProductionClientTests` | 3 |
| `LoopbackAddressTests` | 11 |
| `DevelopmentLaunchOptionsTests` | 4 |
| `DevelopmentServerClientTests` | 16 |
| `AddressContractTests` | 6 |
| `DevelopmentServerClientRegressionTests` | 12 |
| **Total** | **88** |

## Not verified on this host (Windows-required)

Observed Mac attempt:

```
dotnet build src/Helicoid.Manager/Helicoid.Manager.csproj
→ error NETSDK1100: To build a project targeting Windows on this operating system,
  set the EnableWindowsTargeting property to true.
```

`EnableWindowsTargeting` is intentionally **not** enabled.

| Claim | Status | Why |
| --- | --- | --- |
| WinUI 3 Manager builds | **NOT VERIFIED** | Windows 11 x64 + WinUI workload required |
| WinUI 3 Computer builds | **NOT VERIFIED** | Same |
| MSIX packaging / launch | **NOT VERIFIED** | Windows-only tooling |
| Connection page sign-in UI | **NOT VERIFIED** | UI not run here |
| CI workflow green | **UNKNOWN** | Coordinator runs `.github/workflows/windows.yml` next |
| Native icon exports | **NOT DONE** | Source copies only |
| Screen capture / control / host install | **NOT IMPLEMENTED** | Engine and install backend open |

## Accurate commands

Cross-platform:

```bash
dotnet restore src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj
dotnet test src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj --nologo
```

Windows 11 x64:

```powershell
dotnet restore Helicoid.Windows.slnx
dotnet build Helicoid.Windows.slnx -c Release
dotnet test src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj -c Release --nologo
```

## Open items

1. **CI result unknown** until GitHub Actions runs `windows.yml`.
2. **WinUI first Windows compile** may need minor XAML fixes; not claimed green.
3. **WinUI `packages.lock.json`** should be generated on Windows.
4. **Durable package/service IDs** still pending a product decision.
5. **Production identity / auth** remain open; manager identity strings are development fixtures only.

## Tests vs platform proof

The 88 passing tests are **domain and HTTP-client unit tests** with mock handlers. They are not OS-session, capture, input, installer, accessibility, or live-server proof.
