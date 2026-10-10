using Microsoft.UI.Xaml;

namespace Helicoid.Computer;

public partial class App : Application
{
    private Window? _window;

    /// <summary>
    /// True when launched with --test-mode flag. In test mode, the supervisor
    /// creates a CaptureWorker process for IPC/lifecycle validation. Default
    /// production mode is closed (no supervisor started). Documented launch
    /// flag: --test-mode.
    /// </summary>
    public static bool IsTestMode { get; private set; }

    public App()
    {
        InitializeComponent();

        // Parse command-line arguments for --test-mode.
        // WinUI 3 unpackaged apps receive args via Environment.GetCommandLineArgs().
        string[] cmdArgs = Environment.GetCommandLineArgs();
        IsTestMode = cmdArgs.Any(a =>
            string.Equals(a, "--test-mode", StringComparison.OrdinalIgnoreCase));
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        var mainWindow = new MainWindow();
        _window = mainWindow;
        mainWindow.Activate();

        // Start supervisor in test mode.
        if (IsTestMode)
        {
            mainWindow.StartTestMode();
        }
    }
}