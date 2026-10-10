using Helicoid.Computer.ViewModels;
using Helicoid.Domain.Worker;
using Helicoid.WindowsPlatform;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using WinRT.Interop;

namespace Helicoid.Computer;

public sealed partial class MainWindow : Window
{
    private WorkerSupervisor? _supervisor;
    private readonly AgentStatusViewModel _viewModel = new();

    public AgentStatusViewModel ViewModel => _viewModel;

    public MainWindow()
    {
        InitializeComponent();
        Title = "Helicoid Computer";
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        ApplyRoleWindowIcon("hs-computer-windowsicon.ico");
        Refresh();

        // Auto-stop supervisor on window close.
        Closed += (_, _) =>
        {
            StopTestMode();
        };
    }

    private void ApplyRoleWindowIcon(string fileName)
    {
        // Taskbar/window icon for unpackaged WinUI 3. PE Explorer icon comes from ApplicationIcon.
        var iconPath = Path.Combine(AppContext.BaseDirectory, fileName);
        if (!File.Exists(iconPath))
        {
            return;
        }

        var hwnd = WindowNative.GetWindowHandle(this);
        var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
        AppWindow.GetFromWindowId(windowId).SetIcon(iconPath);
    }

    /// <summary>
    /// Start test mode: create a supervisor and launch the CaptureWorker.
    /// Documented launch flag: --test-mode. Default production is closed.
    /// </summary>
    public void StartTestMode()
    {
        if (_supervisor is not null)
        {
            return;
        }

        // Locate the CaptureWorker executable relative to the app base directory.
        string workerPath = Path.Combine(AppContext.BaseDirectory, "Helicoid.CaptureWorker.exe");
        if (!File.Exists(workerPath))
        {
            // Try sibling directory (for non-bundled dev layout).
            workerPath = Path.GetFullPath(
                Path.Combine(AppContext.BaseDirectory, "..", "Helicoid.CaptureWorker", "Helicoid.CaptureWorker.exe"));
        }

        var config = new SupervisorConfig
        {
            WorkerExecutablePath = workerPath,
            WorkerConnectTimeout = TimeSpan.FromSeconds(30),
            WorkerMaxLifetime = TimeSpan.FromMinutes(30),
            // Heartbeat timeout must exceed the interval so scheduling jitter
            // does not manufacture a liveness failure.
            HeartbeatInterval = TimeSpan.FromSeconds(10),
            HeartbeatTimeout = TimeSpan.FromSeconds(25),
            MaxConsecutiveFailures = 3,
            RestartDelay = TimeSpan.FromSeconds(5),
        };

        // Hold the exact instance in a local. The field may be nulled by
        // StopTestMode/Closed while startup is still in flight; the delayed
        // work must never observe or revive a replacement supervisor.
        var supervisor = new WorkerSupervisor(config);
        _supervisor = supervisor;
        _viewModel.SetSupervisor(supervisor);
        Refresh();

        // Start the worker asynchronously against the captured instance only.
        Task.Run(() =>
        {
            // Disposal-before-start must fail quietly and not launch a worker.
            if (supervisor.IsDisposed)
            {
                return;
            }

            supervisor.TryStartWorker();

            // Refresh UI only if this instance is still the active one.
            if (ReferenceEquals(_supervisor, supervisor))
            {
                DispatcherQueue.TryEnqueue(() => Refresh());
            }
        });
    }

    /// <summary>
    /// Stop test mode: dispose the supervisor (kills worker via Job Object).
    /// </summary>
    public void StopTestMode()
    {
        if (_supervisor is null)
        {
            return;
        }

        var supervisor = _supervisor;
        _supervisor = null;
        _viewModel.SetSupervisor(null);
        supervisor.Dispose();
        Refresh();
    }

    /// <summary>
    /// Refresh all UI elements from the ViewModel. Called on initial load
    /// and when supervisor status changes.
    /// </summary>
    public void Refresh()
    {
        ConnectionText.Text = _viewModel.ConnectionSummary;
        OperatorText.Text = _viewModel.OperatorSummary;
        SupervisorText.Text = $"Supervisor: {_viewModel.SupervisorStatusSummary}";
        WorkerText.Text = $"Worker: {_viewModel.WorkerStatusSummary}";
        GenerationText.Text = $"Generation: {_viewModel.DesktopGeneration}";
        AccessInfo.Message = _viewModel.OperatorSummary;
        RequestHelpButton.IsEnabled = _viewModel.UserCommands.Contains("Request Help");
        ViewDetailsButton.IsEnabled = _viewModel.UserCommands.Contains("View Details");
    }
}