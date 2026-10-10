# Helicoid.ConsoleProbe

Bounded **Windows physical-console diagnostic** for D26 / RD03 / V40.

Unzip and run `Helicoid.ConsoleProbe.exe`. No installer, no administrator
elevation, no Windows service, no remote access.

```
Helicoid.ConsoleProbe.exe
```

Writes one JSON object to stdout and exits `0` for any completed diagnostic,
including `eligible: false`. Exit `2` only for invocation parse errors
(`Helicoid.ConsoleProbe.exe --help` for usage).

## --native-query-check

```
Helicoid.ConsoleProbe.exe --native-query-check
```

Query-correctness proof only: runs the same bounded `UOI_NAME` reader on the
borrowed `GetThreadDesktop(GetCurrentThreadId())` handle and emits a sanitized
`nativeQueryCheck` bool (never the desktop name/path/user). Exit `0` on
success, `3` on failure. This is **not** physical-console eligibility,
admission, or lock-matrix evidence.

## What this is (and is not)

**Diagnostic metadata only. Not admitted. Not capture-authorized. Not
enrolled.** No desktop generation is manufactured from these WTS session
facts. No remote access is enabled by this tool. This is a **working candidate
diagnostic, not production authorization**.

It observes the active physical-console session twice (WTS
`WTSGetActiveConsoleSessionId`, `WTSQuerySessionInformationW` for
`WTSConnectState` and `WTSClientProtocolType`), compares the current process
session to the selected physical console, and classifies the current input
desktop (`OpenInputDesktop` + `GetUserObjectInformation` `UOI_NAME`) without
`SetThreadDesktop` or impersonation.

Any sentinel / no-console / session 0 / protected / remote / transition /
API-unavailable / error condition is reported as `eligible: false` with an
explicit reason.

## Output shape

Sanitized reason and session **numeric** facts only — no usernames, domains,
SIDs, host names, memory addresses, pixels, or passwords.

```json
{
  "tool": "Helicoid.ConsoleProbe",
  "disclaimer": "Diagnostic metadata only. ...",
  "eligible": false,
  "reason": "ProcessSessionMismatch",
  "facts": {
    "physicalConsoleSessionId": 1,
    "processSessionId": 2,
    "connectState": 0,
    "protocolType": 0,
    "desktopCategory": "Default",
    "observationStable": true,
    "wtsQuerySucceeded": true,
    "desktopQuerySucceeded": true
  }
}
```

`reason` is one of the `Helicoid.Domain.PhysicalConsole.PhysicalConsoleDenialReason`
values (`Eligible`, `NoConsoleSessionAttached`, `SessionZero`,
`ObservationUnstable`, `ApiUnavailable`, `DesktopQueryFailed`,
`ConnectStateNotActive`, `UnknownConnectState`, `ProtocolNotConsole`,
`UnknownProtocolType`, `ProcessSessionMismatch`, `DesktopMissing`,
`DesktopProtected`, `DesktopNotDefault`).

## Not verified

Installed-system console + RDP + lock/transition matrix is **not** proven by
this artifact. CI runs a result-shape assertion only (CI may have no physical
console). Treat the output as candidate diagnostic evidence for D26/RD03/V40,
never as admission or capture authority.
