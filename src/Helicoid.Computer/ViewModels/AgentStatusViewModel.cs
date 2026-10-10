using Helicoid.Domain.Agent;

namespace Helicoid.Computer.ViewModels;

/// <summary>
/// Computer-user-facing status. The managed control contract has no user
/// Stop Control command; only operator/authorized IT stop and automatic
/// security teardown apply.
/// </summary>
public sealed class AgentStatusViewModel
{
    public AgentStatusViewModel()
    {
        Status = new AgentStatus();
        // Honest default before enrollment backend exists.
        Status.SetConnection(AgentConnectionState.NotEnrolled);
    }

    public AgentStatus Status { get; }

    public string Title => "Helicoid Computer";

    public string ConnectionSummary => Status.ConnectionState switch
    {
        AgentConnectionState.NotEnrolled => "Not enrolled",
        AgentConnectionState.PendingApproval => "Waiting for administrator approval",
        AgentConnectionState.Connected => "Connected to Helicoid server",
        AgentConnectionState.Disconnected => "Disconnected from Helicoid server",
        AgentConnectionState.NeedsPermissions => "Screen recording permission required",
        _ => "Unknown",
    };

    public string OperatorSummary => Status.StatusSummary();

    /// <summary>
    /// User command surface. Stop Control is intentionally absent.
    /// </summary>
    public IReadOnlyList<string> UserCommands => Status.AvailableUserCommands();

    public bool ShowsStopControl => false;

    public string StopControlNote =>
        "The computer user cannot stop remote control from this app. "
        + "The controlling operator or authorized IT can stop it, and security teardown still applies automatically.";

    public void ApplyDemoConnectedState(string controllerName, params string[] observers)
    {
        Status.SetConnection(AgentConnectionState.Connected);
        Status.SetObservers(observers);
        Status.SetControllingOperator(controllerName);
    }
}
