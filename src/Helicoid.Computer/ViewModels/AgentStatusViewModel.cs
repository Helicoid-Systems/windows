using Helicoid.Domain.Agent;
using Helicoid.Domain.Worker;
using Helicoid.WindowsPlatform;

namespace Helicoid.Computer.ViewModels;

/// <summary>
/// Computer-user-facing status. The managed control contract has no user
/// Stop Control command; only operator/authorized IT stop and automatic
/// security teardown apply.
///
/// Surfaces current eligible/locked/unsupported/workerfailed status without
/// claiming enrollment/media. No pixels/input/networking enabled until a
/// real admitted ABI exists.
/// </summary>
public sealed class AgentStatusViewModel
{
    private WorkerSupervisor? _supervisor;

    public AgentStatusViewModel()
    {
        Status = new AgentStatus();
        // Honest default before enrollment backend exists.
        Status.SetConnection(AgentConnectionState.NotEnrolled);
    }

    public AgentStatus Status { get; }

    /// <summary>
    /// Set the worker supervisor for lifecycle tracking. Called by the app
    /// when the supervisor is created (test mode or production).
    /// </summary>
    public void SetSupervisor(WorkerSupervisor? supervisor)
    {
        _supervisor = supervisor;
    }

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
    /// Supervisor status summary. Shows worker lifecycle state without
    /// revealing secrets, SIDs, or host paths.
    /// </summary>
    public string SupervisorStatusSummary
    {
        get
        {
            if (_supervisor is null)
            {
                return "No supervisor";
            }

            return _supervisor.Status switch
            {
                SupervisorStatus.Idle => "Idle",
                SupervisorStatus.StartingWorker => "Starting worker...",
                SupervisorStatus.WorkerRunning => "Worker running",
                SupervisorStatus.WorkerFailed => $"Worker failed ({_supervisor.ConsecutiveFailures} consecutive)",
                SupervisorStatus.SessionLocked => "Session locked",
                SupervisorStatus.NotEnrolled => "Not enrolled",
                SupervisorStatus.ConsoleNotEligible => "Console not eligible",
                SupervisorStatus.GenerationInvalidated => "Generation invalidated",
                _ => "Unknown",
            };
        }
    }

    /// <summary>
    /// Worker status detail.
    /// </summary>
    public string WorkerStatusSummary
    {
        get
        {
            if (_supervisor is null)
            {
                return "No worker";
            }

            return _supervisor.WorkerStatus switch
            {
                WorkerStatus.NotStarted => "Not started",
                WorkerStatus.Starting => "Starting...",
                WorkerStatus.Connected => "Connected",
                WorkerStatus.Running => "Running",
                WorkerStatus.Working => "Working",
                WorkerStatus.ShuttingDown => "Shutting down...",
                WorkerStatus.Exited => "Exited",
                WorkerStatus.Failed => "Failed",
                WorkerStatus.Killed => "Killed",
                _ => "Unknown",
            };
        }
    }

    /// <summary>
    /// Current desktop generation.
    /// </summary>
    public uint DesktopGeneration => _supervisor?.Generation.Value ?? 0;

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