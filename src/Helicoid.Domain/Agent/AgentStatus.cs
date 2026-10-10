namespace Helicoid.Domain.Agent;

/// <summary>
/// Honest operator activity on the monitored computer (Helicoid Computer).
/// The managed control contract has no user Stop Control command.
/// </summary>
public enum AgentConnectionState
{
    NotEnrolled = 0,
    PendingApproval = 1,
    Connected = 2,
    Disconnected = 3,
    NeedsPermissions = 4,
}

public enum OperatorActivityKind
{
    None = 0,
    Observation = 1,
    Control = 2,
    Sharing = 3,
    Attention = 4,
}

public sealed record OperatorIdentity(string DisplayName, OperatorActivityKind Activity);

/// <summary>
/// One computer-user-facing status model. Observation lists every authorized
/// viewer; control names exactly one controlling operator. There is no product
/// Stop Control for the computer user; operator/authorized IT stop and
/// automatic security teardown remain the only stop paths.
/// </summary>
public sealed class AgentStatus
{
    private readonly List<OperatorIdentity> _observers = new();

    public AgentConnectionState ConnectionState { get; private set; } = AgentConnectionState.NotEnrolled;

    public IReadOnlyList<OperatorIdentity> Observers => _observers;

    public OperatorIdentity? ControllingOperator { get; private set; }

    public string? AttentionOwner { get; private set; }

    public string? SharingOwner { get; private set; }

    /// <summary>
    /// Always false. The computer user has no product Stop Control command,
    /// shortcut, or API (D09/D30 and the managed control contract).
    /// </summary>
    public bool UserCanStopControl => false;

    public bool HasActiveScreenAccess => _observers.Count > 0 || ControllingOperator is not null;

    public void SetConnection(AgentConnectionState state) => ConnectionState = state;

    public void SetObservers(IEnumerable<string> operatorNames)
    {
        ArgumentNullException.ThrowIfNull(operatorNames);
        _observers.Clear();
        foreach (var name in operatorNames)
        {
            _observers.Add(new OperatorIdentity(name, OperatorActivityKind.Observation));
        }
    }

    public void SetControllingOperator(string? displayName)
    {
        ControllingOperator = displayName is null
            ? null
            : new OperatorIdentity(displayName, OperatorActivityKind.Control);
    }

    public void SetAttentionOwner(string? displayName) => AttentionOwner = displayName;

    public void SetSharingOwner(string? displayName) => SharingOwner = displayName;

    /// <summary>Primary computer-user-facing status line.</summary>
    public string StatusSummary()
    {
        if (ConnectionState == AgentConnectionState.NotEnrolled)
        {
            return "Not enrolled";
        }

        if (ConnectionState == AgentConnectionState.PendingApproval)
        {
            return "Waiting for administrator approval";
        }

        if (ConnectionState == AgentConnectionState.NeedsPermissions)
        {
            return "Screen recording permission required";
        }

        if (ConnectionState == AgentConnectionState.Disconnected)
        {
            return "Disconnected from Helicoid server";
        }

        if (ControllingOperator is not null)
        {
            return $"{ControllingOperator.DisplayName} is controlling this computer";
        }

        if (_observers.Count == 1)
        {
            return $"Your screen is being viewed by {_observers[0].DisplayName}";
        }

        if (_observers.Count > 1)
        {
            return $"Your screen is being viewed by {_observers.Count} operators";
        }

        return "Connected. No active screen access";
    }

    /// <summary>
    /// Command surface for the computer user. Stop Control is intentionally
    /// absent. Request Help is available; messages/files follow later screens.
    /// </summary>
    public IReadOnlyList<string> AvailableUserCommands()
    {
        if (ConnectionState != AgentConnectionState.Connected)
        {
            return Array.Empty<string>();
        }

        return new[] { "Request Help", "View Details" };
    }
}
