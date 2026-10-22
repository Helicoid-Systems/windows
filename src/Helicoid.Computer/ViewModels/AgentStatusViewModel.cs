using System.ComponentModel;
using System.Runtime.CompilerServices;
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
/// claiming live media. Enrollment metadata does not enable pixels or input;
/// no media transport is enabled until a real admitted ABI exists.
/// </summary>
public sealed class AgentStatusViewModel : INotifyPropertyChanged
{
    private WorkerSupervisor? _supervisor;
    private bool _isDetailsExpanded;
    private string? _enrollmentIssue;
    private string? _enrollmentComputerId;

    public AgentStatusViewModel()
    {
        Status = new AgentStatus();
        // A local enrollment receipt is loaded separately by the application.
        Status.SetConnection(AgentConnectionState.NotEnrolled);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public AgentStatus Status { get; }

    /// <summary>
    /// Set the worker supervisor for lifecycle tracking. Called by the app
    /// when the supervisor is created (test mode or production).
    /// </summary>
    public void SetSupervisor(WorkerSupervisor? supervisor)
    {
        _supervisor = supervisor;
        RaisePresentationChanged();
    }

    /// <summary>
    /// Collapsed technical details (supervisor, worker, generation).
    /// <see cref="ViewDetailsLabel"/> toggles this.
    /// </summary>
    public bool IsDetailsExpanded
    {
        get => _isDetailsExpanded;
        set
        {
            if (_isDetailsExpanded == value)
            {
                return;
            }

            _isDetailsExpanded = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ViewDetailsLabel));
            OnPropertyChanged(nameof(DetailsChevronGlyph));
        }
    }

    public string ViewDetailsLabel => IsDetailsExpanded ? "Hide Details" : "View Details";

    /// <summary>ChevronDown when collapsed, ChevronUp when expanded (Fluent).</summary>
    public string DetailsChevronGlyph => IsDetailsExpanded ? "\uE70E" : "\uE70D";

    public string Title => "Helicoid Computer";

    /// <summary>
    /// Connection identity, shown once. Unknown and not-enrolled never claim
    /// Connected or Ready.
    /// </summary>
    public string ConnectionSummary => Status.ConnectionState switch
    {
        AgentConnectionState.NotEnrolled => "Not enrolled",
        AgentConnectionState.PendingApproval when _enrollmentComputerId is not null =>
            $"Enrollment submitted for administrator approval · {_enrollmentComputerId}",
        AgentConnectionState.PendingApproval => "Enrollment submitted for administrator approval",
        AgentConnectionState.Connected => "Connected to Helicoid server",
        AgentConnectionState.Disconnected => "Disconnected from Helicoid server",
        // Windows wording only. No invented OS permission name; real cause
        // belongs in Details when a platform API actually supplies one.
        AgentConnectionState.NeedsPermissions => "Screen Access Unavailable",
        _ => "Unknown",
    };

    /// <summary>
    /// Screen-access identity from actual operator activity only. Worker
    /// diagnostic readiness does not prove media or disclosure liveness.
    /// Empty when connection state already carries the sole honest line.
    /// </summary>
    public string AccessHeadline
    {
        get
        {
            if (Status.ControllingOperator is { } controller)
            {
                return $"{controller.DisplayName} is controlling this computer";
            }

            if (Status.Observers.Count == 1)
            {
                return $"Your screen is being viewed by {Status.Observers[0].DisplayName}";
            }

            if (Status.Observers.Count > 1)
            {
                return $"Your screen is being viewed by {Status.Observers.Count} operators";
            }

            return Status.ConnectionState switch
            {
                AgentConnectionState.Connected => "No active screen access",
                _ => string.Empty,
            };
        }
    }

    public bool HasAccessHeadline => AccessHeadline.Length > 0;

    /// <summary>
    /// Required actual failures stay visible without expanding details.
    /// Healthy/idle states add no extra line.
    /// </summary>
    public string? FailureNote
    {
        get
        {
            if (_enrollmentIssue is not null)
            {
                return _enrollmentIssue;
            }

            if (_supervisor is null)
            {
                return null;
            }

            return _supervisor.Status switch
            {
                SupervisorStatus.WorkerFailed => $"Worker failed ({_supervisor.ConsecutiveFailures} consecutive)",
                SupervisorStatus.SessionLocked => "Session locked",
                SupervisorStatus.ConsoleNotEligible => "Console not eligible",
                SupervisorStatus.GenerationInvalidated => "Generation invalidated",
                _ => null,
            };
        }
    }

    public bool HasFailureNote => FailureNote is not null;

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
                SupervisorStatus.StartingWorker => "Starting worker",
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
    /// Worker status detail. Diagnostic only — never proof of media or
    /// screen-access liveness.
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
                WorkerStatus.Starting => "Starting",
                WorkerStatus.Connected => "Connected",
                WorkerStatus.Running => "Running",
                WorkerStatus.Working => "Working",
                WorkerStatus.ShuttingDown => "Shutting down",
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
    /// Help stays unavailable until a real help transport exists.
    /// ceiling: no help transport is configured or implemented.
    /// </summary>
    public bool CanRequestHelp => false;

    /// <summary>
    /// User command surface. Stop Control is intentionally absent.
    /// </summary>
    public IReadOnlyList<string> UserCommands => Status.AvailableUserCommands();

    public bool ShowsStopControl => false;

    /// <summary>
    /// One short contract note for the collapsed details region. Not repeated
    /// in the compact status body.
    /// </summary>
    public string StopControlNote =>
        "This computer user has no Stop Control. The operator or authorized IT can stop access.";

    public void ApplyDemoConnectedState(string controllerName, params string[] observers)
    {
        Status.SetConnection(AgentConnectionState.Connected);
        Status.SetObservers(observers);
        Status.SetControllingOperator(controllerName);
        RaisePresentationChanged();
    }

    public void SetConnection(AgentConnectionState state)
    {
        Status.SetConnection(state);
        RaisePresentationChanged();
    }

    public string? EnrollmentComputerId => _enrollmentComputerId;

    public void SetEnrollmentAccepted(EndpointEnrollmentResult enrollment)
    {
        ArgumentNullException.ThrowIfNull(enrollment);
        _enrollmentComputerId = enrollment.ComputerId;
        _enrollmentIssue = null;
        Status.SetConnection(AgentConnectionState.PendingApproval);
        RaisePresentationChanged();
    }

    public void SetEnrollmentForgotten()
    {
        _enrollmentComputerId = null;
        _enrollmentIssue = null;
        Status.SetConnection(AgentConnectionState.NotEnrolled);
        Status.SetObservers(Array.Empty<string>());
        Status.SetControllingOperator(null);
        RaisePresentationChanged();
    }

    public void SetEnrollmentIssue(string? message)
    {
        _enrollmentIssue = string.IsNullOrWhiteSpace(message) ? null : message;
        RaisePresentationChanged();
    }

    public void SetObservers(IEnumerable<string> operatorNames)
    {
        Status.SetObservers(operatorNames);
        RaisePresentationChanged();
    }

    public void SetControllingOperator(string? displayName)
    {
        Status.SetControllingOperator(displayName);
        RaisePresentationChanged();
    }

    private void RaisePresentationChanged()
    {
        OnPropertyChanged(nameof(ConnectionSummary));
        OnPropertyChanged(nameof(AccessHeadline));
        OnPropertyChanged(nameof(HasAccessHeadline));
        OnPropertyChanged(nameof(FailureNote));
        OnPropertyChanged(nameof(HasFailureNote));
        OnPropertyChanged(nameof(SupervisorStatusSummary));
        OnPropertyChanged(nameof(WorkerStatusSummary));
        OnPropertyChanged(nameof(DesktopGeneration));
        OnPropertyChanged(nameof(UserCommands));
        OnPropertyChanged(nameof(CanRequestHelp));
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
