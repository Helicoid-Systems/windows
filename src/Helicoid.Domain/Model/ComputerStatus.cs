namespace Helicoid.Domain.Model;

/// <summary>
/// Readiness of one computer in the manager inventory. This is display status
/// only; it never confers observation or control authority.
/// </summary>
public enum ComputerStatus
{
    Unknown = 0,
    Offline = 1,
    Online = 2,
    NeedsAttention = 3,
    Connecting = 4,
    PendingApproval = 5,
    Failed = 6,
    Unavailable = 7,
}
