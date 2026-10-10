using Helicoid.Computer.ViewModels;
using Microsoft.UI.Xaml;

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
        Refresh();
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
