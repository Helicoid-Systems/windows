using System.Runtime.InteropServices;
using Helicoid.Domain.Setup;
using Helicoid.Manager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Helicoid.Manager.Views;

/// <summary>
/// H01-H05 guided server setup surface. The page drives the real
/// <see cref="SetupWizard"/> and stops at the honest host-check blocker;
/// installation and every later step remain unavailable in this build.
/// </summary>
public sealed partial class ServerSetupPage : Page
{
    private MainViewModel? _viewModel;
    private bool _syncingRoute;

    public ServerSetupPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is not MainViewModel vm)
        {
            _viewModel = null;
            ContinueButton.IsEnabled = false;
            BlockerText.Text = string.Empty;
            BlockerText.Visibility = Visibility.Collapsed;
            return;
        }

        _viewModel = vm;
        RefreshWizard();
        Loaded -= FocusInitialControl;
        Loaded += FocusInitialControl;
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        Loaded -= FocusInitialControl;
        _viewModel = null;
        base.OnNavigatedFrom(e);
    }

    private void FocusInitialControl(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        switch (_viewModel.Wizard.CurrentStep)
        {
            case SetupStep.ChooseHosting:
                WindowsLocalChoice.Focus(FocusState.Programmatic);
                break;
            case SetupStep.SshConnect:
                SshAddressBox.Focus(FocusState.Programmatic);
                break;
        }
    }

    private void HostingRoute_Checked(object sender, RoutedEventArgs e)
    {
        if (_syncingRoute || _viewModel is null)
        {
            return;
        }

        if (sender is not RadioButton { Tag: string tag }
            || !Enum.TryParse<HostingRoute>(tag, out var route)
            || _viewModel.Wizard.SelectedRoute == route)
        {
            return;
        }

        _viewModel.Wizard.SelectRoute(route);
        RefreshWizard();
        if (route == HostingRoute.LinuxSsh)
        {
            SshAddressBox.Focus(FocusState.Programmatic);
        }
        else
        {
            ContinueButton.Focus(FocusState.Programmatic);
        }
    }

    private void SshAddressBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _viewModel?.Wizard.SetSshAddress(SshAddressBox.Text);
        UpdateContinueState();
    }

    private void ContinueButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        var wizard = _viewModel.Wizard;
        if (wizard.TryAdvance() && wizard.CurrentStep == SetupStep.CheckHost)
        {
            // No verified host-check backend exists. Seed the honest
            // Unimplemented rows so the gate is explicit, not an empty green.
            wizard.SeedUnimplementedHostChecks();
        }

        RefreshWizard();
    }

    private void BackButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        _viewModel.Wizard.GoBack();
        RefreshWizard();
    }

    private void StartOverButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null)
        {
            return;
        }

        _viewModel.Wizard.Reset();
        RefreshWizard();
    }

    private void RefreshWizard()
    {
        if (_viewModel is null)
        {
            return;
        }

        var wizard = _viewModel.Wizard;
        var step = wizard.CurrentStep;
        var route = wizard.SelectedRoute;

        _syncingRoute = true;
        WindowsLocalChoice.IsChecked = route == HostingRoute.WindowsLocal;
        LinuxSshChoice.IsChecked = route == HostingRoute.LinuxSsh;
        _syncingRoute = false;

        RouteSummaryText.Text = route switch
        {
            HostingRoute.WindowsLocal => "Route: This Computer",
            HostingRoute.LinuxSsh => "Route: Existing Linux Server",
            _ => string.Empty,
        };
        RouteSummaryText.Visibility = route is null ? Visibility.Collapsed : Visibility.Visible;
        TaskTitle.Text = StepTitle(step, route);

        SetPanel(ChooseHostingPanel, step == SetupStep.ChooseHosting);
        SetPanel(LocalHostPanel, step == SetupStep.LocalHost);
        SetPanel(SshConnectPanel, step == SetupStep.SshConnect);
        SetPanel(SshIdentityPanel, step == SetupStep.SshHostIdentity);
        SetPanel(CheckHostPanel, step == SetupStep.CheckHost);

        SshAddressBox.Text = wizard.SshAddress;

        LocalComputerText.Text = Environment.MachineName;
        LocalOsText.Text = RuntimeInformation.OSDescription;
        LocalArchitectureText.Text = RuntimeInformation.OSArchitecture.ToString();

        HostCheckList.ItemsSource = wizard.HostChecks
            .Select(row => new SetupHostCheckRow(row))
            .ToList();
        var passed = wizard.HostChecks.Count(row => row.Result == CheckResult.Passed);
        var forced = wizard.HostChecks.Count(row => row.Result == CheckResult.Unimplemented);
        CheckHostSummary.Text = wizard.HostChecks.Count == 0
            ? "Required host checks have not run."
            : forced > 0
                ? passed == 0
                    ? "Host checks cannot run in this build. No check was verified."
                    : $"{passed} of {wizard.HostChecks.Count} required checks passed; the rest cannot run in this build."
                : $"{passed} of {wizard.HostChecks.Count} required checks passed.";

        StartOverButton.Visibility = route is null ? Visibility.Collapsed : Visibility.Visible;
        BackButton.Visibility = wizard.CanGoBack ? Visibility.Visible : Visibility.Collapsed;

        UpdateContinueState();
    }

    private void UpdateContinueState()
    {
        if (_viewModel is null)
        {
            return;
        }

        var wizard = _viewModel.Wizard;
        var step = wizard.CurrentStep;
        var canContinue = wizard.CanAdvance;
        ContinueButton.IsEnabled = canContinue;

        var blocker = canContinue ? string.Empty : BlockerTextFor(step);
        BlockerText.Text = blocker;
        BlockerText.Visibility = string.IsNullOrEmpty(blocker)
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    private static string BlockerTextFor(SetupStep step) => step switch
    {
        SetupStep.ChooseHosting => "Choose a hosting route.",
        SetupStep.SshConnect => "Enter an SSH address.",
        _ => string.Empty,
    };

    private static string StepTitle(SetupStep step, HostingRoute? route) => step switch
    {
        SetupStep.ChooseHosting => "Set Up Server",
        SetupStep.LocalHost => "This Computer",
        SetupStep.SshConnect => "Connect to Linux Server",
        SetupStep.SshHostIdentity => "Host Identity",
        SetupStep.CheckHost => route == HostingRoute.LinuxSsh ? "Check Server" : "Check This Computer",
        SetupStep.Network => "Network",
        SetupStep.DeploymentIdentity => "Deployment Identity",
        SetupStep.Administrator => "Administrator",
        SetupStep.Storage => "Storage and Backups",
        SetupStep.Review => "Review Installation",
        SetupStep.Install => "Installation",
        SetupStep.Ready => "Server Ready",
        SetupStep.VerifyDeployment => "Verify Deployment",
        _ => "Server Setup",
    };

    private static void SetPanel(UIElement panel, bool visible) =>
        panel.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
}
