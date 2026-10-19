using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Helicoid.Manager.Views;

/// <summary>
/// Honest view-only window for a computer whose remote engine is unavailable.
/// Title is 'Viewing [Computer]'. System chrome owns Close. Never shows fake
/// pixels and never offers control.
/// </summary>
public sealed partial class ViewScreenWindow : Window
{
    private readonly Action<int>? _onClosed;
    private bool _notifiedClosed;

    public ViewScreenWindow(
        string computerName,
        string title,
        string detail,
        int sessionContext,
        Action<int>? onClosed = null)
    {
        InitializeComponent();
        _onClosed = onClosed;
        SessionContext = sessionContext;
        ComputerName = computerName;
        Title = $"Viewing {computerName}";
        TitleText.Text = title;
        DetailText.Text = detail;
        Closed += (_, _) => NotifyClosed();
        ViewerRoot.Loaded += (_, _) =>
        {
            var scale = ViewerRoot.XamlRoot.RasterizationScale;
            var id = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(WinRT.Interop.WindowNative.GetWindowHandle(this));
            var appWindow = Microsoft.UI.Windowing.AppWindow.GetFromWindowId(id);
            var area = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
            var width = (int)Math.Ceiling(960 * scale);
            var height = (int)Math.Ceiling(640 * scale);
            if (area is not null)
            {
                width = Math.Min(width, area.WorkArea.Width);
                height = Math.Min(height, area.WorkArea.Height);
            }
            appWindow.Resize(new Windows.Graphics.SizeInt32(width, height));
        };
    }

    /// <summary>Session context this viewer was opened under.</summary>
    public int SessionContext { get; }

    /// <summary>Computer display name for this viewer.</summary>
    public string ComputerName { get; }

    /// <summary>ViewerRegistry handle for this window.</summary>
    public int RegistryHandle { get; set; }

    /// <summary>Show this viewer and record its registry handle.</summary>
    public void ShowViewer(int registryHandle)
    {
        RegistryHandle = registryHandle;
        Activate();
    }

    private void NotifyClosed()
    {
        if (_notifiedClosed)
        {
            return;
        }

        _notifiedClosed = true;
        if (RegistryHandle != 0)
        {
            _onClosed?.Invoke(RegistryHandle);
        }
    }
}
