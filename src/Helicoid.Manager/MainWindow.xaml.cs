using Helicoid.Domain.Client;
using Helicoid.Manager.ViewModels;
using Helicoid.Manager.Views;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Helicoid.Manager;

public sealed partial class MainWindow : Window
{
    public MainViewModel ViewModel { get; }

    public MainWindow(DevelopmentLaunchOptions launchOptions)
    {
        ArgumentNullException.ThrowIfNull(launchOptions);
        ViewModel = new MainViewModel(launchOptions);
        InitializeComponent();
        Title = "Helicoid Manager";
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        if (launchOptions.DevelopmentServerEnabled)
        {
            FixtureBadge.Visibility = Visibility.Visible;
            ContentFrame.Navigate(typeof(ConnectionPage), ViewModel.Connection);
        }
        else
        {
            ContentFrame.Navigate(typeof(ComputersPage), ViewModel);
        }
    }

    private void NavigationView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is NavigationViewItem item)
        {
            switch (item.Tag as string)
            {
                case "Connection":
                    ContentFrame.Navigate(typeof(ConnectionPage), ViewModel.Connection);
                    break;
                case "Computers":
                    ContentFrame.Navigate(typeof(ComputersPage), ViewModel);
                    break;
                case "ServerSetup":
                    ContentFrame.Navigate(typeof(ServerSetupPage), ViewModel);
                    break;
            }
        }
    }
}
