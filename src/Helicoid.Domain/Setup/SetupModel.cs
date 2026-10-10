namespace Helicoid.Domain.Setup;

/// <summary>
/// Hosting routes the Windows manager offers. Version 1 is exactly these two
/// product routes plus optional containers as advanced; no local macOS server
/// and no remote Windows installation route.
/// </summary>
public enum HostingRoute
{
    WindowsLocal = 0,
    LinuxSsh = 1,
}

/// <summary>Wizard steps from W17. H13 is Deployment Verified and is separate.</summary>
public enum SetupStep
{
    ChooseHosting = 1,
    LocalHost = 2,
    SshConnect = 3,
    SshHostIdentity = 4,
    CheckHost = 5,
    Network = 6,
    DeploymentIdentity = 7,
    Administrator = 8,
    Storage = 9,
    Review = 10,
    Install = 11,
    Ready = 12,
    VerifyDeployment = 13,
}

public enum CheckResult
{
    Pending = 0,
    Checking = 1,
    Passed = 2,
    NeedsAttention = 3,
    Unimplemented = 4,
}

public sealed record HostCheckRow(string Name, CheckResult Result, string? Detail = null);

/// <summary>
/// Backend execution state for server setup. The Windows manager UI presents
/// the real route and step model; installation itself is not implemented in
/// this source tree and must not pretend to write host resources.
/// </summary>
public enum SetupBackendState
{
    NotStarted = 0,
    Unimplemented = 1,
    Running = 2,
    Succeeded = 3,
    Failed = 4,
}
