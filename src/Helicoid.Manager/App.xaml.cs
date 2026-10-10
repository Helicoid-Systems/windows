using Helicoid.Domain.Client;
using Microsoft.UI.Xaml;

namespace Helicoid.Manager;

public partial class App : Application
{
    private Window? _window;

    public App()
    {
        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        // Development loopback client requires an explicit launch option.
        // Without it the manager stays on the closed production client.
        var options = DevelopmentLaunchOptions.Parse(Environment.GetCommandLineArgs().Skip(1));
        _window = new MainWindow(options);
        _window.Activate();
    }
}
