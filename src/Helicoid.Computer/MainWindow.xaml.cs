using System.ComponentModel;
using Helicoid.Computer.ViewModels;
using Helicoid.Domain.Worker;
using Helicoid.WindowsPlatform;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Windows.Graphics;
using WinRT.Interop;

namespace Helicoid.Computer;

public sealed partial class MainWindow : Window
{
    private WorkerSupervisor? _supervisor;
    private readonly AgentStatusViewModel _viewModel = new();
    private DispatcherTimer? _statusTimer;
    private bool _initialSizeApplied;

    public AgentStatusViewModel ViewModel => _viewModel;

    public MainWindow()
    {
        InitializeComponent();
        Title = "Helicoid Computer";
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        ApplyRoleWindowIcon("hs-computer-windowsicon.ico");

        // Size once after root is loaded so RasterizationScale is real.
        // Never re-apply after a user resize.
        AppTitleBar.Loaded += (_, _) => ApplyCompactWindowSizeOnce();

        _viewModel.PropertyChanged += OnViewModelPropertyChanged;

        // Auto-stop supervisor, timer, and model subscription on window close.
        Closed += (_, _) =>
        {
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
            StopStatusRefreshTimer();
            StopTestMode();
        };

        Refresh();
    }

    /// <summary>
    /// One initial window size in physical pixels for a logical 420x292
    /// endpoint status (260 content + 32 title row already in the client grid).
    /// Scale comes from XamlRoot.RasterizationScale; clamped to the work area.
    /// Native caption behavior is unchanged.
    /// </summary>
    private void ApplyCompactWindowSizeOnce()
    {
        if (_initialSizeApplied)
        {
            return;
        }

        _initialSizeApplied = true;

        var hwnd = WindowNative.GetWindowHandle(this);
        var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
        var appWindow = AppWindow.GetFromWindowId(windowId);

        double scale = 1.0;
        if (Content?.XamlRoot is { RasterizationScale: > 0 } root)
        {
            scale = root.RasterizationScale;
        }

        int width = (int)Math.Ceiling(420 * scale);
        int height = (int)Math.Ceiling(292 * scale);

        // Clamp to the current display work area (physical pixels).
        if (DisplayArea.GetFromWindowId(windowId, DisplayAreaFallback.Nearest) is { } area)
        {
            var work = area.WorkArea;
            width = Math.Min(width, Math.Max(work.Width, 1));
            height = Math.Min(height, Math.Max(work.Height, 1));
        }

        appWindow.Resize(new SizeInt32(width, height));
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
        StartStatusRefreshTimer();

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
    /// Stop test mode: stop status polling, dispose the supervisor
    /// (kills worker via Job Object).
    /// </summary>
    public void StopTestMode()
    {
        StopStatusRefreshTimer();

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
    /// Test-mode only: WorkerSupervisor publishes no status event, so while a
    /// test supervisor exists poll its actual metadata at most 1 Hz to refresh
    /// the status UI. Never starts without a supervisor; never touches
    /// authority, capture, or input. Worker diagnostic readiness is not media
    /// or disclosure liveness.
    /// </summary>
    private void StartStatusRefreshTimer()
    {
        if (_statusTimer is not null || _supervisor is null)
        {
            return;
        }

        _statusTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1),
        };
        _statusTimer.Tick += OnStatusTimerTick;
        _statusTimer.Start();
    }

    private void StopStatusRefreshTimer()
    {
        if (_statusTimer is null)
        {
            return;
        }

        _statusTimer.Stop();
        _statusTimer.Tick -= OnStatusTimerTick;
        _statusTimer = null;
    }

    private void OnStatusTimerTick(object? sender, object e)
    {
        if (_supervisor is null)
        {
            StopStatusRefreshTimer();
            return;
        }

        Refresh();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        Refresh();
    }

    private void ViewDetailsButton_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.IsDetailsExpanded = !_viewModel.IsDetailsExpanded;
    }

    /// <summary>
    /// Refresh all UI elements from the ViewModel. Called on initial load,
    /// model property changes, and when supervisor status is known to change.
    /// </summary>
    public void Refresh()
    {
        ConnectionText.Text = _viewModel.ConnectionSummary;

        AccessText.Text = _viewModel.AccessHeadline;
        AccessText.Visibility = _viewModel.HasAccessHeadline ? Visibility.Visible : Visibility.Collapsed;

        FailureText.Text = _viewModel.FailureNote ?? string.Empty;
        FailureText.Visibility = _viewModel.HasFailureNote ? Visibility.Visible : Visibility.Collapsed;

        SupervisorText.Text = $"Supervisor: {_viewModel.SupervisorStatusSummary}";
        WorkerText.Text = $"Worker: {_viewModel.WorkerStatusSummary}";
        GenerationText.Text = $"Generation: {_viewModel.DesktopGeneration}";
        StopControlNoteText.Text = _viewModel.StopControlNote;

        var expanded = _viewModel.IsDetailsExpanded;
        DetailsScroll.Visibility = expanded ? Visibility.Visible : Visibility.Collapsed;
        ViewDetailsLabel.Text = _viewModel.ViewDetailsLabel;
        DetailsChevron.Glyph = _viewModel.DetailsChevronGlyph;
        AutomationProperties.SetName(ViewDetailsButton, _viewModel.ViewDetailsLabel);
    }
}
