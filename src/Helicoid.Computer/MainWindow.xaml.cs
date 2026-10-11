using Helicoid.Computer.ViewModels;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using WinRT.Interop;

namespace Helicoid.Computer;

public sealed partial class MainWindow : Window
{
    public AgentStatusViewModel ViewModel { get; } = new();

    public MainWindow()
    {
        InitializeComponent();
        Title = "Helicoid Computer";
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        ApplyRoleWindowIcon("hs-computer-windowsicon.ico");
        Refresh();
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

    private void Refresh()
    {
        ConnectionText.Text = ViewModel.ConnectionSummary;
        OperatorText.Text = ViewModel.OperatorSummary;
        AccessInfo.Message = ViewModel.OperatorSummary;
        RequestHelpButton.IsEnabled = ViewModel.UserCommands.Contains("Request Help");
        ViewDetailsButton.IsEnabled = ViewModel.UserCommands.Contains("View Details");
    }
}
