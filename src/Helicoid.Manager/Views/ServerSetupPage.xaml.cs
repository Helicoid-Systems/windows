using Helicoid.Domain.Setup;
using Helicoid.Manager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Helicoid.Manager.Views;

public sealed partial class ServerSetupPage : Page
{
    public MainViewModel ViewModel { get; private set; } = null!;

    public ServerSetupPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is MainViewModel vm)
        {
            ViewModel = vm;
            RefreshWizard();
        }
    }

    private void WindowsLocal_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.Wizard.SelectRoute(HostingRoute.WindowsLocal);
        RefreshWizard();
    }

    private void LinuxSsh_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.Wizard.SelectRoute(HostingRoute.LinuxSsh);
        RefreshWizard();
    }

    private void RunChecks_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.Wizard.SeedUnimplementedHostChecks();
        RefreshWizard();
    }

    private void Install_Click(object sender, RoutedEventArgs e)
    {
        // Backend is unimplemented; the wizard records that honestly.
        ViewModel.Wizard.AttemptInstall();
        RefreshWizard();
    }

    private void RefreshWizard()
    {
        var wizard = ViewModel.Wizard;
        CurrentStepText.Text = wizard.CurrentStep switch
        {
            SetupStep.ChooseHosting => "H01 Choose Hosting",
            SetupStep.LocalHost => "H02 Local Host (Windows local)",
            SetupStep.SshConnect => "H03 Connect (Linux SSH)",
            SetupStep.SshHostIdentity => "H04 Host Identity (Linux SSH)",
            SetupStep.CheckHost => "H05 Check Host",
            SetupStep.Network => "H06 Network",
            SetupStep.DeploymentIdentity => "H07 Deployment Identity",
            SetupStep.Administrator => "H08 Administrator",
            SetupStep.Storage => "H09 Storage/Backups",
            SetupStep.Review => "H10 Review",
            SetupStep.Install => "H11 Install",
            SetupStep.Ready => "H12 Ready for Enrollment",
            SetupStep.VerifyDeployment => "H13 Verify Deployment",
            _ => wizard.CurrentStep.ToString(),
        };

        StepsList.ItemsSource = wizard.RemainingSteps()
            .Select(s => s.ToString())
            .ToList();

        HostChecksList.ItemsSource = wizard.HostChecks.ToList();
        ReadyInfo.IsOpen = wizard.IsReadyForEnrollment;
    }
}
