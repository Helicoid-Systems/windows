## Coordinator native Windows acceptance, 17 October 2026

[CI39018316028](https://github.com/Helicoid-Systems/windows/actions/runs/39018316028)
at exact source `93f14f9373d23bcef839a8117bbb658ae97e6259` passes 458 domain
and 67 native integration tests, both WinUI release builds, launcher, icon,
worker metadata and console-probe checks. The actual runner is Windows Server
2025. Coordinator independently passes all 13 frozen causal expiry regressions,
458 portable tests, warning-as-error integration compilation and real Rust HTTPS
interop (7 Swift / 6 C# checks, owned listeners reaped).

The downloaded unsigned development archive (artifact12095832540,191487356bytes)
has SHA256 `26653b0d43c4a48daa81e408f72441f3c3d674ab19923a4444d54f724ba76b10`,
matching GitHub metadata; all1070 members pass ZIP CRC. The expected Manager,
Computer and CaptureWorker executables have actual PE x64 headers and empty
certificate directories (unsigned). Installed Windows11, real capture/input,
normal enrollment and the complete worker/admission checkpoint remain Not Verified.
The following candidate and failure entries are historical.

## Windows callback-crossing expiry acceptance candidate, 17 October 2026

The coordinator independently reproduced a lost notification when the deadline
crossed between two early-timer checks (expected1, observed0). Expiration now
has its own state flag, separate from returned timer ownership, and notifies
outside the gate. The monotonic deadline sum is checked for overflow.
Fresh independent frozen-source checks pass all13 causal regressions; the
complete portable suite reports458 passed. The native integration project
builds with warnings as errors (0 warnings/errors). Actual Rust HTTPS
interoperability passes7 Swift/6 C# checks and reaps both owned listeners.
Exported session metadata verifies Europe MiMo-V2.6-Pro/high for both the
expiry package and final callback correction. Native Windows CI for this
candidate, installed Windows11, capture/input and normal enrollment remain
Not Verified or unavailable; earlier native429/67 applies only to57bea57.

## Windows expiry timer disposal ownership, 17 October 2026

Independent RED showed the shared authorized response fence discarded the
`ITimer` returned by `ClearSessionLocked()`, leaving a matching deadline timer
active after a delayed-dispatch expiry. That clear path now captures the timer
under the gate and disposes it **outside** the lock before notification,
matching every other clear path. `ReviewEarlyClock.ActiveTimerCount` asserts
zero active timers in `DelayedTimerDispatchCannotPermitLateInventoryBody`.
Portable domain **457 passed, 0 failed** (12/12 CoordinatorReview);
`Helicoid.WindowsIntegrationTests` `-warnaserror` 0 w / 0 e; `git diff --check`
clean. Native Windows installed acceptance not claimed. Earlier entries follow.

## Windows native v2 session expiry final boundaries, 17 October 2026

Two independently reproduced remaining failures are repaired: (1) authorized
HTTP200 bodies that outlived a delayed timer dispatch were accepted because
`IsCurrentSession` ignored the lease deadline — the shared response fence now
re-checks the current monotonic/UTC deadline before any successful body leaves
`SendJsonAsync` and expires only that installed generation; (2) generic
`SessionLost` unconditionally cleared a replacement's freshly loaded inventory
when queued A-expiry events drained — loss cleanup is generation-fenced via
`SessionIdentityChanged`, with generic `SessionLost` scoped to legacy/no-v2.

Portable acceptance this host (macOS): domain **457 passed, 0 failed**
including **12/12 CoordinatorReview** independent cases (late-inventory
theory, high-frequency rearm, queued UI loss/preserve, delayed-timer body,
plus prior eight). `Helicoid.WindowsIntegrationTests` builds with
`-warnaserror` 0 w / 0 e; `git diff --check` clean. Native CI remains previous
429/67 until a new Windows run. Earlier dated entries follow.

## Windows native v2 session expiry second review, 16 October 2026

Independent six-test review reproduced two remaining causal failures against
the first expiry package; both root causes are now repaired in-tree:
(1) early one-shot deadline callback disposed its own rearm because the fired
timer slot stayed non-null — the fired timer is detached and scheduling failure
now force-invalidates the exact generation with `SessionExpired`; (2) delayed
old expiry reset a replacement MFA `Completing` because `SessionGeneration` is
0 without a bearer — the coordinator fences on `_installedSessionGeneration` +
`_activeCts` + Phase under one gate and a UI epoch. All six independent
`CoordinatorReview_*` regressions (actual clock / `ReviewEarlyClock`) are
ported unweakened. Vacuous owner timer/notification tests replaced with
genuine early-fire and barrier-interleaved proofs.

Portable acceptance this host (macOS): domain **451 passed, 0 failed**
including the six CoordinatorReview tests; `Helicoid.WindowsIntegrationTests`
builds with `-warnaserror` 0 w / 0 e; `git diff --check` clean. Native Windows
CI and Rust interoperability remain coordinator gates. Earlier dated entries
follow.

## Windows native v2 session expiry, 16 October 2026

Bounded package on `codex/native-v2-auth-20261016` from baseline `57bea57`.
`V2DeviceKeyChallengeClient` now converts a validated completion into a checked
monotonic deadline at one reception sample (`TimeProvider.System` in production),
enforces expiry on `HasSession` and every authorized send, uses weak deadline-timer
ownership with early-fire rearm, and raises generation-fenced `SessionExpired`
so stale notifications cannot reset a replacement. Stale 401/session/logout
replies clear only their captured generation; session/inventory replies never
renew the deadline. `V2SignInCoordinator` rejects expired completions before UI
install; actual `ConnectionViewModel`/`MainViewModel` reset account/manager/TOTP
and clear inventory/selection on `SessionLost` with UI-context dispatch and
dispose/unsubscribe.

Portable acceptance this host (macOS): domain **448 passed, 0 failed** (includes
ported CoordinatorReview actual-clock/weak-retain/delayed-expiry regressions and
the new V2SessionExpiry suite); `Helicoid.WindowsIntegrationTests` builds with
`-warnaserror` 0 w / 0 e; `git diff --check` clean. Real WinUI builds, native
tests, and installed Windows 11 remain coordinator CI gates — not claimed here.
No protocol/schema/dependency changes. Earlier dated entries follow.

## Windows parent-handle access repair (pending native rerun), 16 October 2026

Actual second native CI [38925659773](https://github.com/Helicoid-Systems/windows/actions/runs/38925659773)
at `1af404c` failed **1 of 64** WindowsFact cases: only
`DeviceKeyStorage_ParentReplacement_WhileHeld_IsRefused` (expected Success from
`TryPinDirectory`, got `OwnershipMismatch`). The other **63 native cases
passed**; both WinUI apps and domain builds passed. That single native failure
is **pending coordinator Windows CI rerun** — not accepted, not relabeled.

Root cause: `TryPinDirectory` → `OpenAncestorChain(includeLeaf: true)` opened
the verified leaf without `READ_CONTROL`, so leaf `GetSecurityInfo`
owner/DACL verification failed closed as `OwnershipMismatch`. Leaf open rights
now include `READ_CONTROL`; share mode still omits `FILE_SHARE_DELETE`.
Owner/DACL checks are not skipped and the failing test is not weakened.

Also required and applied (product-private parent contract on read/removal):
- Production `Open`/`Forget` now pin+verify the product directory
  (current-user owner / private ACL) before the leaf, with ancestors held.
- Denied `Open`/`Forget` refuse without reading/deleting the key file; key
  bytes preserved (SDDL fixture, no account creation).
- `OpenAncestorChain` failure exits dispose the acquired chain (common owner
  finally); no stale handles block parent cleanup. Regression proves rename
  and removal succeed after denial.

Portable acceptance this host (macOS): domain **429 passed, 0 failed**;
`Helicoid.Domain`, `Helicoid.WindowsPlatform`, and
`Helicoid.WindowsIntegrationTests` compile with `-warnaserror` (0 w / 0 e).
Native Windows execution is **Not Verified** here; no native pass is claimed
from Mac. Private CreateSignReopen, explicit untrusted DACL fixture,
synchronized real-create barrier, and all prior cases retained. Symlink-leaf
fixture now uses a product-owned directory so parent verification cannot mask
the leaf `ReparsePointRefused` assertion.

## Native Windows CI fixture correction, 16 October 2026

Run `38923866275` built the real Manager and Computer applications and passed
429 domain tests, but native integration failed **5 of 63 tests**. Three setup
fixtures incorrectly trusted generic inherited folders; two ACL mutation fixtures
used invalid native layouts. The refusal boundary remains strict. Fixtures now
use actual product-owned directories and Unicode SDDL APIs, retain owner rights
when granting foreign access, and explicitly create the untrusted-directory ACL.
The existing private create/sign/reopen regression is retained.

Coordinator native-test compilation with `-warnaserror` passes. A fresh Windows
CI run is required; the prior failure is not relabeled as acceptance. No product
store, admission or UI behavior was weakened by this fixture-only correction.

## Coordinator native-auth candidate, 16 October 2026

Coordinator independently reran the complete domain suite: **429 passed, zero
failed/skipped**, and built WindowsIntegrationTests with `-warnaserror`: zero
warnings/errors. Reviewed private-store fixes create protected objects atomically,
pin ancestors before mutation, refuse foreign ACLs/reparse paths, retain exact
Win32 create-race handling and include synchronized native race scenarios.
Implementation metadata confirms `xiaomi-token-plan-ams/mimo-v2.6-pro`, `high`.

Actual Win32/DPAPI execution, WinUI packaging and native race acceptance remain
**Not Verified** pending the new feature-branch Windows CI run. Portable checks
do not pass installed Windows 11, capture/input or the worker/admission checkpoint.
No VM or production configuration was changed. Earlier dated entries follow.

# BUILD-REPORT — Helicoid Windows (`apps/windows`)

Current coordinator evidence (11 October 2026): `dotnet test src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj` passed **387 tests, zero failures/skips** on macOS; `dotnet build src/Helicoid.Domain/Helicoid.Domain.csproj -warnaserror` passed with zero warnings/errors. The new transport uses sole pinned CA trust, native chain/hostname/EKU validation, bounded streaming, whole-operation cancellation and request registration that retains TLS resources until drain. Tests use actual disposable TLS sockets, including deterministic handshake/close gates. Exported MiMo metadata confirms `xiaomi/mimo-v2.6-pro`.

Native attempt [38140826309](https://github.com/Helicoid-Systems/windows/actions/runs/38140826309) at `efccbbc` **Failed**: the TLS fixture closed handshakes with EOF, and unbounded coordination waits caused the step to time out. The revised fixture materializes private keys through PKCS12 into temporary native storage, tracks/drains connection handlers, owns its certificate, uses loopback-only listeners and bounds waits with server-side diagnostics. The coordinator also made teardown errors fail the suite rather than silently free resources after an incomplete drain. This repair preserves production certificate validation. The repair subsequently passed native CI; the precise cause of the original handshake failure remains an inference.

Native [CI38142367280](https://github.com/Helicoid-Systems/windows/actions/runs/38142367280) at exact code revision `f8f356d3f29419f1161952d38bfb6428f24b3666` **Passed**: 387 domain tests, 47 native integration tests, zero failures/skips, both app packages, worker and launcher checks. The coordinator downloaded [artifact11703970176](https://github.com/Helicoid-Systems/windows/actions/runs/38142367280/artifacts/11703970176) and verified all three PE binaries are x64 with the worker runtime companions present. Installed Windows 11 capture/input remains **Not Verified**. Production trust adoption and authentication remain closed. The following 10 October report is historical evidence, not the current test count or capability status.

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

## Supplied Windows role icons, 10 October 2026

The user's four exact PNG/SVG sources are retained in `branding/source`, with
byte hashes in `branding/PROVENANCE.json`. Manager uses the supplied blue icon;
Computer uses the supplied dark icon. Each ICO has 16,24,32,48,64,128,256 entries
from full-frame downsampling. Mac artwork is unchanged. `ApplicationIcon` embeds
the role resource and `AppWindow.SetIcon` uses a published sibling ICO.

Fresh source/hash/ICO verification passes. A disposable real C# compiler PE
fixture passes all seven referenced group payload checks; corrupting one group
resource ID is rejected. Windows CI now checks both actual published executables
and sibling ICOs. Native WinUI build and visible Explorer/taskbar rendering are
pending this revision's Windows CI and user check.

The user's original ConsoleProbe returned eligible twice on the unlocked PC,
but also returned eligible in the reported Win+L test. The lock refusal matrix
therefore FAILED for that candidate. WTSActive/Default alone are insufficient;
a separate session-lock query repair is in progress. This probe has no capture,
input, enrollment or production authorization integration.

Native Windows CI 38058004339 compiled and published both WinUI apps and
verified their exact referenced PE icon payloads and staged ICO files. The
source hash step refused checkout-modified SVGs: Windows Git CRLF conversion
reproduced both wrong hashes exactly. `branding/source/* -text` now preserves
the canonical source bytes; a forced-autocrlf checkout matches both originals.
A fresh native CI rerun is required.

## Reviewed lock repair, 10 October 2026

A MiMo-V2.5-Pro agent added independent WTSSessionInfoEx lock observations to
both WTS passes, safe unknown defaults, sanitized lock-state reporting and
policy/decoder regressions. Root reproduced an accepted malformed native
structure size, then required the SDK-verified 232-byte API structure and a
20-byte copied numeric header. The exact failing compiled decoder probe now
refuses sizes 20,231,233,512. No identity strings are copied or decoded.

Locked restore and all 210 domain/client/console/decoder tests pass locally;
ConsoleProbe builds with zero warnings/errors. Schema 2 includes a 30-second
metadata sampling mode for a pre-started process lock check. Native build,
query and sampling CI for this repair are pending; the user's actual repaired
lock/unlock result and RDP matrix remain unverified. The user reports RDP is
supported but not configured. No capture, input, installation or admission
integration is enabled.

---

## Worker / supervisor admission prerequisite, 10 October 2026

Host: macOS (Darwin), arm64 — **not a Windows runtime**. SDK:
`/tmp/hs-toolchain/dotnet` (.NET 10.0.401).

### Verified on this host (portable / fixture proof only)

| Check | Command | Result |
| --- | --- | --- |
| Domain tests (locked suite) | `dotnet test src/Helicoid.Domain.Tests/Helicoid.Domain.Tests.csproj -c Release` | **PASS** — 292 tests, 0 failed |
| Integration project (portable facts) | `dotnet test src/Helicoid.WindowsIntegrationTests/Helicoid.WindowsIntegrationTests.csproj -c Release` | **PASS** — 10 passed, **35 skipped** (real xUnit skip: `Requires Windows runtime`) |
| CaptureWorker build | `dotnet build src/Helicoid.CaptureWorker/Helicoid.CaptureWorker.csproj -c Release` | **PASS** — 0 warnings, 0 errors |
| Worker surface audit | `rg` for capture/input/network APIs | **PASS** — none in `Helicoid.CaptureWorker` + `Helicoid.Domain/Worker` |
| Role icons preserved | `shasum -a 256` | **PASS** — `HS App icon.icon/icon.json` = `ae154c55…` (both apps) |
| Workflow YAML | `ruby -ryaml -e YAML.load_file(...)` | **PASS** |

The 35 skipped tests are `[WindowsFact]`/`[WindowsTheory]` and are **not**
native proof. They execute on Windows CI only.

### What this revision added

- Mandatory boot ID, launch ID, session/user identity (PID + WTS session +
  token SID), and desktop generation on both handshake sides. Missing,
  malformed, or zero fields deny — never best-effort.
- Mutual named-pipe kernel identity (PID + session + SID) on both sides.
- Per-launch capability nonce (32 bytes) with constant-time comparison.
- Job Object `KILL_ON_JOB_CLOSE` + `PROC_THREAD_ATTRIBUTE_JOB_LIST` atomic bind.
- Bounded liveness: `HeartbeatInterval` + `HeartbeatTimeout` (timeout must
  strictly exceed interval; validated positive bounded timing).
- Fenced async callbacks: lock/logoff/console replacement/disconnect fence
  current work; a stale callback cannot act on a replacement.
- Bounded framing; unknown message types and unknown work operations fail
  closed (worker exit code 5).
- `DesktopGeneration` never wraps: exhaustion at `uint.MaxValue` fences and
  blocks restart.
- `MainWindow.StartTestMode` captures the exact supervisor instance; delayed
  startup against a disposed supervisor fails quietly and does not launch.
- Metadata-only CaptureWorker bundle with `SHA256SUMS` reproducibility
  manifest on Windows CI.

### NOT VERIFIED on this host

Named pipes, Job Objects, `CreateProcessW`, WTS, and token SID reads did not
run here. WinUI compile is CI-only (`NETSDK1100` on macOS). No pixels, input,
or network admission exists — by design, pending a real core/transport
contract.

### Windows-native CI (pending confirmation)

`windows.yml` on `windows-latest` runs: locked domain tests → Manager/Computer
builds → unsigned development publish → icon verification → launcher tests →
metadata-only worker publish + SHA256SUMS → worker IPC admission checks
(no-env / missing-fence / malformed-fence → exit 1) → ConsoleProbe steps →
Windows-native integration tests staged with real `Helicoid.CaptureWorker.exe`.

---

## Native IPC hang diagnosis, 10 October 2026

**Trigger:** CI run `38083093481` (commit `478d010`) built both apps, worker,
probe and domain tests successfully, but the real IPC integration tests had
been **running since 20:21:42 UTC** with no completion (observed 20:43 UTC).
That is a **FAILED/stalled verification**, not accepted native proof.

### Source-evidenced defects repaired

| Defect | Location | Fix |
| --- | --- | --- |
| Unbounded write: `SendHandshakeResponseAsync` → `TrySendMessageAsync(msg)` with **no token** | `IpcChannel.cs` supervisor | Every write bounded by `MaxWriteTimeout` (5s) + dispose CTS; `TrySendMessage` takes an explicit timeout |
| Unbounded write: worker `TrySendMessage` → `TrySendMessageAsync(message)` with no token | `IpcChannel.cs` worker | Same bound + dispose CTS |
| Unbounded write: `ct = default` (`CancellationToken.None`) reached `WriteAsync`/`FlushAsync` | both channels | `CancelAfter(MaxWriteTimeout)` always applied even when `ct` is unsignaled |
| Early identity rejects returned without a handshake response, leaving the peer waiting | supervisor handshake | `TrySendBoundedRejectAsync` sends a best-effort bounded reject on PID/session/SID failure |
| Disposal did not cancel in-flight I/O | both `Dispose` methods | `_disposeCts.Cancel()` first; connect/read/write link to it |
| Server comment claimed `CurrentUserOnly` but flag was **not set** | `PipeOptions` | `PipeOptions.Asynchronous \| PipeOptions.CurrentUserOnly` now set explicitly |
| Tests awaited counterpart tasks unbounded | integration tests | `AwaitBoundedAsync` (hard 5–15s bound → `TimeoutException`); early-reject sites use `AwaitAfterRejectAsync` (observe briefly, never hang) |
| CI staged **only the exe apphost** beside the test assembly | workflow | Stages the complete runtime bundle: `exe`, `dll`, `deps.json`, `runtimeconfig.json`, `Helicoid.WindowsPlatform.dll`, `Helicoid.Domain.dll` — each verified present |
| No CI hang bound | workflow | Job `timeout-minutes: 45`; step timeouts; `--blame-hang --blame-hang-timeout 5m`; TRX results; `if: always()` upload of `artifacts/test-results/` |

### ACL / session-0 note

`PipeOptions.CurrentUserOnly` restricts the ACL to the creating user. Remote
and cross-user clients are denied by the kernel. **A session-0 service
supervisor that must accept a distinct user-worker SID cannot rely on
CurrentUserOnly alone** — that deployment requires an explicit `PipeSecurity`
ACL granting only the worker SID. Current code is correct for same-user
supervisor/worker; the service case is documented and pending a real service
host. Physical-console eligibility requirements were **not** relaxed.

### Native regressions added

`IpcWrite_SilentPeer_BoundedNotHung`, `IpcChannel_Dispose_CancelsPendingConnect`,
`IpcWorker_Dispose_CancelsPendingConnect`, `IpcRead_PeerDisconnect_ReturnsDisconnectedNotHang`,
`SupervisorIpcChannel_PipeIsCurrentUserOnly` — all `[WindowsFact]` (skip on
non-Windows).

### Portable checks (this host)

| Check | Result |
| --- | --- |
| Domain tests | **292 passed, 0 failed** |
| Integration (portable facts) | **10 passed, 35 skipped** (real xUnit skip) |
| CaptureWorker build | 0 warnings/errors |
| Worker runtime bundle contents | exe + dll + deps.json + runtimeconfig.json + WindowsPlatform.dll + Domain.dll present |
| Capture/input/network surface | **None** in worker path |
| Workflow YAML | parses |

**Not claimed:** native Windows runtime proof. The stalled CI run is **not**
accepted as verification. A fresh Windows CI run with the bounded diagnostics
is required.

## DPAPI regression repair, 11 October 2026

Native Windows CI at `aa4e07e` completed in 26 seconds: 292 domain tests
passed; 44 of 45 integration tests passed. The remaining test flipped an
encrypted DPAPI byte but expected structural corruption. The production
`DecryptionFailed` denial was correct and remains unchanged. Three deterministic
tests now distinguish malformed version/length from authenticated blob tampering,
assert null plaintext and preserve the damaged file without automatic recreation.

Coordinator reproduction on macOS: `dotnet test` of the integration project
with locked restore passes ten portable tests and reports 37 native skips
(47 total). These skips are not Windows evidence. Sanitized MiMo metadata
confirms `xiaomi/mimo-v2.6-pro`; the coordinator reviewed the three-file diff.
A fresh native Windows CI run is required before the integration pin advances.
The earlier 35-skip rows above retain the results of their earlier revisions.


## Native v2 device-key challenge sign-in (uncommitted candidate), 13–15 October 2026

Package: pinned-HTTPS `POST /v2/auth/challenge` + `/complete` with Ed25519
device-key proofs, conditional TOTP UI/state, and DPAPI persistent device
identity. Wire contract: `native-auth-contract-v2.md` (completion binds
top-level `manager_public_key`; `manager.public_identity` is display-only).

### Proved on this host (macOS portable)

| Check | Result |
| --- | --- |
| Domain tests Release | **425 passed, 0 failed** |
| Domain + WindowsPlatform `-warnaserror` | 0 warnings / 0 errors |
| WindowsIntegrationTests compile | 0 warnings / 0 errors |
| NSec.Cryptography pin | 26.4.0 (MIT, libsodium; nuget.org contentHash in packages.lock.json) |

### Not claimed (remain Windows CI / coordinator gates)

- Native WinUI Manager build and live ConnectionPage TOTP UI threading
- Actual DPAPI create/open/sign/reopen, two-creator race, broad-ACL/foreign
  owner/link/hardlink denial, preexisting-temp preservation (tests exist in
  `SupervisorIpcIntegrationTests`; they run under `WindowsFact` on CI only)
- Normal-operation acceptance of production login (no live authority trust
  is wired in this candidate; absent trust stays explicitly unavailable)
- Media/control/hosting feature flags remain closed

Coordinator reviews 2026-10-14 and 2026-10-15 (including the confirmed
install-point cancel race) are addressed in this candidate and are subject
to the same unaccepted status until review closes.


### 15 October follow-ups (candidate, uncommitted)

- Obsolete completion cleanup is token-scoped (`ClearSessionIfBearer`); a late
  UI continuation cannot erase a replacement bearer. Cancel/SignOut still clear
  the current bearer at user intent.
- Client begin generation take-over is atomic under one lock.
- Session lifetime is measured at **reception** (fresh clock after await) with
  the same hard 7200s bound; no TTL padding. Delayed-7200s acceptance and
  oversized/expired denial have causal regressions.
- Domain suite: **429 passed, 0 failed** (Release).


### Native store acceptance repairs (15 October, uncommitted)

- Corrected `ACL_SIZE_INFORMATION` field offsets to the SDK layout.
- Replaced SID blacklist with an explicit trusted-principal allowlist for
  private key DACLs; foreign grants fail closed.
- Intermediate ancestor walk refuses junctions; held objects omit
  `FILE_SHARE_DELETE`; private ACL applied at leaf creation only.
- Domain suite still **429 passed**. Native Windows runtime remains
  **Not Verified** pending coordinator CI.


### Private-store functional repair (16 October, uncommitted)

- Correct protected-DACL flags on held-handle security updates (no SACL).
- Private product-directory and temp-file creation via `SECURITY_ATTRIBUTES`.
- Ancestors pinned before mutation; deterministic parent-replacement pin seam.
- Domain **429 passed**; WindowsPlatform/IntegrationTests compile `-warnaserror`;
  `actionlint` clean. Native Windows runtime remains **Not Verified** pending CI.


### Native CI 38923866275 fixture/ACL repair (16 October, uncommitted)

Five WindowsFact failures: three OwnershipMismatch from generic inherited
fixture directories, two ERROR_INVALID_PARAMETER 87 from hand-coded
EXPLICIT_ACCESS offsets. Fixtures now use actual store create/forget for
product-owned private dirs; ACL grants use SDDL with owner retained.
Domain **429 passed**. Native suite requires Windows CI rerun — **Not Verified**.
