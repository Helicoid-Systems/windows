using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Helicoid.Computer.ViewModels;
using Helicoid.Domain.Client;
using Helicoid.Domain.Worker;
using Helicoid.WindowsPlatform;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Windows.Graphics;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Helicoid.Computer;

public sealed partial class MainWindow : Window
{
    private WorkerSupervisor? _supervisor;
    private WorkerSupervisor? _observationWorkerSupervisor;
    private Task? _observationWorkerStopTask;
    private PhysicalConsoleObserverLoop? _physicalConsoleObserverLoop;
    private readonly object _observationConsoleStateLock = new();
    private bool? _lastObservationConsoleEligibility;
    private readonly AgentStatusViewModel _viewModel = new();
    private DispatcherTimer? _statusTimer;
    private DispatcherTimer? _fileDeliveryTimer;
    private EndpointFileDeliveryClient? _fileDeliveryClient;
    private Task? _endpointFilePollTask;
    private Task? _observationGrantTask;
    private CancellationTokenSource? _observationGrantLoopCancellation;
    private bool _isPollingFiles;
    private bool _isReviewingFileRequests;
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

        try
        {
            if (EndpointEnrollmentClient.ReadSavedConfiguration() is { } configuration)
            {
                _viewModel.SetEnrollmentAccepted(configuration.Enrollment);
                EnrollEndpointButton.IsEnabled = false;
                StartEndpointFileDelivery(configuration);
            }
            else if (EndpointEnrollmentClient.ReadSavedEnrollment() is { } legacyEnrollment)
            {
                _viewModel.SetEnrollmentAccepted(legacyEnrollment);
                EnrollEndpointButton.IsEnabled = false;
                FileDeliveryText.Text = "Saved enrollment needs refreshed deployment trust before file delivery can start.";
            }
        }
        catch (ServerClientException exception)
        {
            _viewModel.SetEnrollmentIssue(exception.Message);
        }
        UpdateEndpointIdentityControls();

        // Auto-stop supervisor, timer, and model subscription on window close.
        Closed += (_, _) =>
        {
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
            StopStatusRefreshTimer();
            StopEndpointFileDelivery();
            StopTestMode();
        };

        OpenReceivedFilesButton.IsEnabled = _fileDeliveryClient is not null;
        Refresh();
    }

    /// <summary>
    /// One initial window size in physical pixels for a logical 420x352
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
        int height = (int)Math.Ceiling(352 * scale);

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

        var config = CreateCaptureWorkerSupervisorConfig();

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

    private void StartEndpointFileDelivery(EndpointEnrollmentConfiguration configuration)
    {
        StopEndpointFileDelivery();
        var observationWorker = new WorkerSupervisor(CreateCaptureWorkerSupervisorConfig());
        _observationWorkerSupervisor = observationWorker;
        lock (_observationConsoleStateLock)
        {
            _lastObservationConsoleEligibility = null;
        }
        var consoleObserver = new PhysicalConsoleObserverLoop(
            TimeSpan.FromMilliseconds(500),
            eligibility => ObserveCaptureWorkerConsoleState(observationWorker, eligibility));
        _physicalConsoleObserverLoop = consoleObserver;
        consoleObserver.Start();
        var client = new EndpointFileDeliveryClient(configuration, observationWorker);
        _fileDeliveryClient = client;
        OpenReceivedFilesButton.IsEnabled = true;
        OpenReceivedFilesButton.Visibility = Visibility.Visible;
        ReviewFileRequestsButton.Visibility = Visibility.Visible;
        FileDeliveryText.Text = "Checking for approved file jobs…";
        _fileDeliveryTimer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(2) };
        _fileDeliveryTimer.Tick += OnFileDeliveryTimerTick;
        _fileDeliveryTimer.Start();
        _endpointFilePollTask = PollEndpointFileJobsAsync();
        var observationGrantCancellation = new CancellationTokenSource();
        _observationGrantLoopCancellation = observationGrantCancellation;
        _observationGrantTask = PollObservationGrantsAsync(
            client,
            observationGrantCancellation);
    }

    private void StopEndpointFileDelivery()
    {
        _observationGrantLoopCancellation?.Cancel();
        _observationGrantLoopCancellation = null;
        Task? grantTask = _observationGrantTask;
        _observationGrantTask = null;
        WorkerSupervisor? observationWorker = _observationWorkerSupervisor;
        _observationWorkerSupervisor = null;
        PhysicalConsoleObserverLoop? consoleObserver = _physicalConsoleObserverLoop;
        _physicalConsoleObserverLoop = null;
        if (_fileDeliveryTimer is not null)
        {
            _fileDeliveryTimer.Stop();
            _fileDeliveryTimer.Tick -= OnFileDeliveryTimerTick;
            _fileDeliveryTimer = null;
        }
        _fileDeliveryClient?.Dispose();
        _fileDeliveryClient = null;
        ReviewFileRequestsButton.Visibility = Visibility.Collapsed;

        if (observationWorker is not null || consoleObserver is not null)
        {
            Task? previousStop = _observationWorkerStopTask;
            _observationWorkerStopTask = Task.Run(() => StopObservationWorkerAfterGrantLoopAsync(
                previousStop,
                grantTask,
                observationWorker,
                consoleObserver));
        }
    }

    private async Task StopEndpointFileDeliveryAndWaitAsync()
    {
        var filePoll = _endpointFilePollTask;
        var grantPoll = _observationGrantTask;
        StopEndpointFileDelivery();
        if (filePoll is not null)
        {
            await filePoll;
        }
        if (grantPoll is not null)
        {
            await grantPoll;
        }
        if (_observationWorkerStopTask is { } workerStop)
        {
            await workerStop;
            _observationWorkerStopTask = null;
        }
        _endpointFilePollTask = null;
    }

    private static async Task StopObservationWorkerAfterGrantLoopAsync(
        Task? previousStop,
        Task? grantTask,
        WorkerSupervisor? supervisor,
        PhysicalConsoleObserverLoop? consoleObserver)
    {
        consoleObserver?.Dispose();
        if (previousStop is not null)
        {
            await previousStop.ConfigureAwait(false);
        }
        if (grantTask is not null)
        {
            try
            {
                await grantTask.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Worker teardown must still run when a grant session faults.
            }
        }
        supervisor?.Dispose();
    }

    private void ObserveCaptureWorkerConsoleState(
        WorkerSupervisor supervisor,
        Helicoid.Domain.PhysicalConsole.PhysicalConsoleEligibility eligibility)
    {
        bool? previous;
        lock (_observationConsoleStateLock)
        {
            previous = _lastObservationConsoleEligibility;
            _lastObservationConsoleEligibility = eligibility.IsEligible;
        }

        if (supervisor.IsDisposed)
        {
            return;
        }
        if (previous == true && !eligibility.IsEligible)
        {
            if (eligibility.Reason == Helicoid.Domain.PhysicalConsole.PhysicalConsoleDenialReason.SessionLocked)
            {
                supervisor.OnSessionLocked();
            }
            else
            {
                supervisor.OnConsoleReplaced();
            }
        }
        else if (previous == false && eligibility.IsEligible)
        {
            supervisor.OnSessionUnlocked();
        }
    }

    private static SupervisorConfig CreateCaptureWorkerSupervisorConfig() => new()
    {
        WorkerExecutablePath = ResolveCaptureWorkerPath(),
        WorkerConnectTimeout = TimeSpan.FromSeconds(30),
        WorkerMaxLifetime = TimeSpan.FromMinutes(30),
        // Heartbeat timeout must exceed the interval so scheduling jitter
        // does not manufacture a liveness failure.
        HeartbeatInterval = TimeSpan.FromSeconds(10),
        HeartbeatTimeout = TimeSpan.FromSeconds(25),
        MaxConsecutiveFailures = 3,
        RestartDelay = TimeSpan.FromSeconds(5),
    };

    private static string ResolveCaptureWorkerPath()
    {
        string[] candidates =
        [
            Path.Combine(AppContext.BaseDirectory, "CaptureWorker", "Helicoid.CaptureWorker.exe"),
            Path.Combine(AppContext.BaseDirectory, "Helicoid.CaptureWorker.exe"),
            Path.GetFullPath(Path.Combine(
                AppContext.BaseDirectory,
                "..",
                "Helicoid.CaptureWorker",
                "Helicoid.CaptureWorker.exe")),
        ];
        return candidates.FirstOrDefault(File.Exists) ?? candidates[0];
    }

    private static async Task PollObservationGrantsAsync(
        EndpointFileDeliveryClient client,
        CancellationTokenSource cancellation)
    {
        var cancellationToken = cancellation.Token;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // The server holds this request until a grant is addressed to
                    // this endpoint session or the bounded wait expires.
                    await client.WaitAndServeObservationGrantsAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
                catch (EndpointFileDeliveryWaitingForUserException)
                {
                    await DelayUnlessCancelledAsync(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
                }
                catch (ServerClientException exception) when (
                    exception.Failure is ServerClientFailure.Unauthorized or ServerClientFailure.Forbidden)
                {
                    await DelayUnlessCancelledAsync(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
                }
                catch (ServerClientException exception) when (
                    exception.Failure is ServerClientFailure.NotFound or ServerClientFailure.NotAvailableInThisBuild)
                {
                    await DelayUnlessCancelledAsync(TimeSpan.FromMinutes(1), cancellationToken).ConfigureAwait(false);
                }
                catch (ServerClientException)
                {
                    await DelayUnlessCancelledAsync(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    await DelayUnlessCancelledAsync(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            cancellation.Dispose();
        }
    }

    private static async Task DelayUnlessCancelledAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private async void OnFileDeliveryTimerTick(object? sender, object e)
    {
        if (_isPollingFiles)
        {
            return;
        }
        var poll = PollEndpointFileJobsAsync();
        _endpointFilePollTask = poll;
        await poll;
    }

    private async Task PollEndpointFileJobsAsync()
    {
        if (_fileDeliveryClient is null || _isPollingFiles)
        {
            return;
        }

        _isPollingFiles = true;
        try
        {
            var files = await _fileDeliveryClient.PollAsync(CancellationToken.None);
            FileDeliveryText.Text = files.Count == 0
                ? "No file jobs are waiting. Checks run every two minutes."
                : $"Received {files.Count} file{(files.Count == 1 ? string.Empty : "s")} in Received Files.";
        }
        catch (EndpointFileDeliveryWaitingForUserException exception)
        {
            FileDeliveryText.Text = exception.Message;
        }
        catch (ServerClientException exception) when (
            exception.Failure is ServerClientFailure.Unauthorized or ServerClientFailure.Forbidden)
        {
            FileDeliveryText.Text = "Waiting for administrator approval or valid endpoint access.";
        }
        catch (ServerClientException exception) when (
            exception.Failure == ServerClientFailure.NotAvailableInThisBuild)
        {
            FileDeliveryText.Text = "File delivery is not enabled by this deployment.";
        }
        catch (ServerClientException)
        {
            FileDeliveryText.Text = "File delivery check failed. The endpoint will retry in two minutes.";
        }
        catch (Exception)
        {
            FileDeliveryText.Text = "File delivery is unavailable. The endpoint will retry in two minutes.";
        }
        finally
        {
            _isPollingFiles = false;
        }
    }

    private void OpenReceivedFilesButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var folder = EndpointFileDeliveryClient.GetReceivedFilesDirectory();
            Process.Start(new ProcessStartInfo(folder) { UseShellExecute = true });
        }
        catch (Exception)
        {
            FileDeliveryText.Text = "The Received Files folder could not be opened.";
        }
    }

    private async void ForgetEndpointIdentityButton_Click(object sender, RoutedEventArgs e)
    {
        var confirmation = new ContentDialog
        {
            Title = "Forget this computer's saved identity?",
            Content = new TextBlock
            {
                Text = "This stops endpoint polling and removes the local signing key and enrollment metadata. The old computer remains a separate server-side identity; ask the Manager to quarantine it after recovery. Queued work will not move to a new identity, and files already in Received Files stay on this computer.",
                TextWrapping = TextWrapping.Wrap,
            },
            PrimaryButtonText = "Forget saved identity",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = AppTitleBar.XamlRoot,
        };
        if (await confirmation.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        ForgetEndpointIdentityButton.IsEnabled = false;
        EnrollEndpointButton.IsEnabled = false;
        try
        {
            await StopEndpointFileDeliveryAndWaitAsync();
            EndpointEnrollmentClient.ForgetSavedIdentity();
            _viewModel.SetEnrollmentForgotten();
            FileDeliveryText.Text = "Saved endpoint identity forgotten. Received Files are still on this computer.";
            await ShowEnrollmentResultAsync(
                "Identity forgotten",
                "Ask the Manager for a fresh invitation to enroll this computer again. The new enrollment will have a separate computer identity.");
        }
        catch (ServerClientException exception)
        {
            _viewModel.SetEnrollmentIssue(exception.Message);
            FileDeliveryText.Text = "The identity reset did not finish. Endpoint polling is stopped; retry forgetting the saved identity.";
            await ShowEnrollmentResultAsync("Identity reset not completed", exception.Message);
        }
        catch (Exception)
        {
            const string message = "The identity reset did not finish. Endpoint polling is stopped; retry forgetting the saved identity.";
            _viewModel.SetEnrollmentIssue(message);
            FileDeliveryText.Text = message;
            await ShowEnrollmentResultAsync("Identity reset not completed", message);
        }
        finally
        {
            UpdateEndpointIdentityControls();
        }
    }

    private void UpdateEndpointIdentityControls()
    {
        try
        {
            var hasLocalIdentity = EndpointEnrollmentClient.HasSavedLocalIdentity();
            ForgetEndpointIdentityButton.Visibility = hasLocalIdentity ? Visibility.Visible : Visibility.Collapsed;
            ForgetEndpointIdentityButton.IsEnabled = hasLocalIdentity;
            EnrollEndpointButton.IsEnabled = !hasLocalIdentity;
        }
        catch (ServerClientException exception)
        {
            // Fail closed: preserve a recovery action and prevent key reuse
            // when protected local state cannot be inspected.
            _viewModel.SetEnrollmentIssue(exception.Message);
            ForgetEndpointIdentityButton.Visibility = Visibility.Visible;
            ForgetEndpointIdentityButton.IsEnabled = true;
            EnrollEndpointButton.IsEnabled = false;
        }
    }

    private async void ReviewFileRequestsButton_Click(object sender, RoutedEventArgs e)
    {
        var client = _fileDeliveryClient;
        if (client is null || _isReviewingFileRequests)
        {
            return;
        }

        _isReviewingFileRequests = true;
        ReviewFileRequestsButton.IsEnabled = false;
        try
        {
            var requests = await client.ListAvailableFileRequestsAsync(CancellationToken.None);
            if (requests.Count == 0)
            {
                FileDeliveryText.Text = "There are no open file requests for this computer.";
                return;
            }

            var requestPicker = new ComboBox
            {
                ItemsSource = requests,
                DisplayMemberPath = nameof(EndpointFileRequest.Title),
                SelectedIndex = 0,
                HorizontalAlignment = HorizontalAlignment.Stretch,
            };
            AutomationProperties.SetName(requestPicker, "Available file requests");
            var requestDetails = new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 360,
            };
            void UpdateRequestDetails()
            {
                if (requestPicker.SelectedItem is not EndpointFileRequest selected)
                {
                    requestDetails.Text = "Select a request to view its instructions and limits.";
                    return;
                }
                var extensions = selected.AllowedExtensions.Contains("*", StringComparer.Ordinal)
                    ? "Any file type"
                    : string.Join(", ", selected.AllowedExtensions.Select(extension => $".{extension}"));
                var closesAt = DateTimeOffset.FromUnixTimeSeconds(selected.ClosesAtUnix).ToLocalTime();
                requestDetails.Text =
                    $"{selected.Instructions}\n\nAllowed types: {extensions}\n" +
                    $"Files: up to {selected.MaxFileCount}; total size: {FormatFileSize(selected.MaxTotalSizeBytes)}\n" +
                    $"Closes: {closesAt:g}\n" +
                    $"Replacement: {(selected.ReplacementAllowed ? "allowed after confirmation" : "not allowed")}";
            }
            requestPicker.SelectionChanged += (_, _) => UpdateRequestDetails();
            UpdateRequestDetails();

            var requestContent = new StackPanel { Spacing = 12 };
            requestContent.Children.Add(new TextBlock
            {
                Text = "Choose a request from your administrator and review its instructions before selecting files.",
                TextWrapping = TextWrapping.Wrap,
            });
            requestContent.Children.Add(requestPicker);
            requestContent.Children.Add(requestDetails);
            var requestDialog = new ContentDialog
            {
                Title = "File requests",
                Content = new ScrollViewer
                {
                    Content = requestContent,
                    MaxHeight = 460,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                },
                PrimaryButtonText = "Choose files",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = AppTitleBar.XamlRoot,
            };
            if (await requestDialog.ShowAsync() != ContentDialogResult.Primary ||
                requestPicker.SelectedItem is not EndpointFileRequest request)
            {
                return;
            }

            var history = await client.ListMyFileRequestSubmissionsAsync(request.Id, CancellationToken.None);
            var recentHistory = history.Take(8).Select(submission =>
                $"{submission.State}: {string.Join(", ", submission.Files.Take(3).Select(file => file.FileName))}" +
                (submission.Files.Count > 3 ? "…" : string.Empty));
            var historyText = history.Count == 0
                ? "You have no previous submissions for this request."
                : $"Your previous submissions:\n{string.Join("\n", recentHistory)}";
            var historyDialog = new ContentDialog
            {
                Title = "Your submissions",
                Content = new TextBlock
                {
                    Text = $"{historyText}\n\nSelect the files you want to send to “{request.Title}”.",
                    TextWrapping = TextWrapping.Wrap,
                    MaxWidth = 360,
                },
                PrimaryButtonText = "Select files",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = AppTitleBar.XamlRoot,
            };
            if (await historyDialog.ShowAsync() != ContentDialogResult.Primary)
            {
                return;
            }

            var picker = new FileOpenPicker
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            };
            picker.FileTypeFilter.Add("*");
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));
            var selectedFiles = await picker.PickMultipleFilesAsync();
            if (selectedFiles is null || selectedFiles.Count == 0)
            {
                return;
            }

            string? replaceSubmissionId = null;
            var replaceableSubmissions = request.ReplacementAllowed
                ? history.Where(submission => submission.State == "received").ToList()
                : new List<EndpointFileRequestSubmission>();
            if (replaceableSubmissions.Count > 0)
            {
                var replacementPicker = new ComboBox
                {
                    HorizontalAlignment = HorizontalAlignment.Stretch,
                };
                AutomationProperties.SetName(replacementPicker, "Choose whether to replace a submission");
                replacementPicker.Items.Add(new ComboBoxItem
                {
                    Content = "Submit as a new response",
                });
                foreach (var submission in replaceableSubmissions)
                {
                    replacementPicker.Items.Add(new ComboBoxItem
                    {
                        Content = $"Replace submission {submission.Id}",
                        Tag = submission,
                    });
                }
                replacementPicker.SelectedIndex = 0;
                var replacementDialog = new ContentDialog
                {
                    Title = "Previous response found",
                    Content = new StackPanel
                    {
                        Spacing = 8,
                        Children =
                        {
                            new TextBlock
                            {
                                Text = "Choose a new response or select one of your received responses to replace.",
                                TextWrapping = TextWrapping.Wrap,
                            },
                            replacementPicker,
                        },
                    },
                    PrimaryButtonText = "Continue",
                    CloseButtonText = "Cancel",
                    DefaultButton = ContentDialogButton.Primary,
                    XamlRoot = AppTitleBar.XamlRoot,
                };
                if (await replacementDialog.ShowAsync() != ContentDialogResult.Primary)
                {
                    return;
                }
                if (replacementPicker.SelectedItem is ComboBoxItem { Tag: EndpointFileRequestSubmission selectedSubmission })
                {
                    var confirmDialog = new ContentDialog
                    {
                        Title = "Confirm replacement",
                        Content = new TextBlock
                        {
                            Text = $"Replace submission {selectedSubmission.Id} with the selected files? The previous response will be superseded after the replacement upload is verified.",
                            TextWrapping = TextWrapping.Wrap,
                            MaxWidth = 360,
                        },
                        PrimaryButtonText = "Replace submission",
                        CloseButtonText = "Cancel",
                        DefaultButton = ContentDialogButton.Close,
                        XamlRoot = AppTitleBar.XamlRoot,
                    };
                    if (await confirmDialog.ShowAsync() != ContentDialogResult.Primary)
                    {
                        return;
                    }
                    replaceSubmissionId = selectedSubmission.Id;
                }
            }

            FileDeliveryText.Text = "Uploading the selected files…";
            var result = await client.SubmitFilesToRequestAsync(
                request.Id,
                request.Revision,
                selectedFiles.Select(file => file.Path).ToArray(),
                replaceSubmissionId,
                confirmReplacement: replaceSubmissionId is not null,
                cancellationToken: CancellationToken.None);
            FileDeliveryText.Text =
                $"Submission received and verified ({result.Files.Count} file{(result.Files.Count == 1 ? string.Empty : "s")}).";
        }
        catch (EndpointFileDeliveryWaitingForUserException exception)
        {
            FileDeliveryText.Text = exception.Message;
        }
        catch (ServerClientException exception) when (
            exception.Failure == ServerClientFailure.NotAvailableInThisBuild)
        {
            FileDeliveryText.Text = "File requests are not enabled by this deployment.";
        }
        catch (ServerClientException exception) when (
            exception.Failure is ServerClientFailure.Unauthorized or ServerClientFailure.Forbidden)
        {
            FileDeliveryText.Text = "Waiting for administrator approval or valid endpoint access.";
        }
        catch (ArgumentException exception)
        {
            FileDeliveryText.Text = exception.Message;
        }
        catch (Exception)
        {
            FileDeliveryText.Text = "The file request could not be completed. Refresh the request list and try again.";
        }
        finally
        {
            _isReviewingFileRequests = false;
            ReviewFileRequestsButton.IsEnabled = true;
        }
    }

    private static string FormatFileSize(ulong bytes) =>
        bytes >= 1024 * 1024
            ? $"{bytes / (1024d * 1024d):0.#} MiB"
            : $"{bytes / 1024d:0.#} KiB";

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

    private async void EnrollEndpointButton_Click(object sender, RoutedEventArgs e)
    {
        static TextBox CreateField(string header, string placeholder = "", int maxLength = 128) => new()
        {
            Header = header,
            PlaceholderText = placeholder,
            MaxLength = maxLength,
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };

        var serverOrigin = CreateField("Server HTTPS origin", "https://helicoid.school.example:8920", 2048);
        var deploymentId = CreateField("Deployment ID shown by the Manager");
        var invitationId = CreateField("Invitation ID", maxLength: 36);
        var enrollmentCode = new PasswordBox
        {
            Header = "One-time enrollment code",
            MaxLength = 43,
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };
        var certificatePem = new TextBox
        {
            Header = "Deployment CA certificate (PEM)",
            PlaceholderText = "-----BEGIN CERTIFICATE-----",
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            MaxLength = 96 * 1024,
            MinHeight = 96,
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };
        var caFingerprint = CreateField("CA SHA-256 fingerprint", maxLength: 64);

        var form = new StackPanel { Spacing = 10 };
        form.Children.Add(new TextBlock
        {
            Text = "Get the deployment ID, CA certificate, and fingerprint through your organization's trusted setup channel. The fingerprint must match the CA certificate.",
            TextWrapping = TextWrapping.Wrap,
        });
        form.Children.Add(serverOrigin);
        form.Children.Add(deploymentId);
        form.Children.Add(invitationId);
        form.Children.Add(enrollmentCode);
        form.Children.Add(certificatePem);
        form.Children.Add(caFingerprint);

        var dialog = new ContentDialog
        {
            Title = "Enroll this computer",
            Content = new ScrollViewer
            {
                Content = form,
                MaxHeight = 500,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            },
            PrimaryButtonText = "Enroll",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = AppTitleBar.XamlRoot,
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            enrollmentCode.Password = string.Empty;
            certificatePem.Text = string.Empty;
            return;
        }

        var code = enrollmentCode.Password;
        enrollmentCode.Password = string.Empty;
        var caPem = certificatePem.Text;
        certificatePem.Text = string.Empty;
        byte[]? caDer = null;
        EnrollEndpointButton.IsEnabled = false;
        _viewModel.SetEnrollmentIssue(null);
        try
        {
            if (caPem.Length > 96 * 1024 ||
                !caPem.TrimStart().StartsWith("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal) ||
                caPem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase) ||
                caPem.Split("-----BEGIN CERTIFICATE-----", StringSplitOptions.None).Length != 2)
            {
                throw new ArgumentException("Paste exactly one deployment CA certificate in PEM format.");
            }

            using var caCertificate = X509Certificate2.CreateFromPem(caPem);
            caDer = caCertificate.Export(X509ContentType.Cert);
            if (serverOrigin.Text.Length > 2048 ||
                !Uri.TryCreate(serverOrigin.Text, UriKind.Absolute, out var origin))
            {
                throw new ArgumentException("Enter a complete HTTPS server origin.");
            }

            var trust = DeploymentTlsTrust.Create(
                deploymentId.Text,
                origin,
                caDer,
                caFingerprint.Text);
            using var client = new EndpointEnrollmentClient(trust);
            var result = await client.EnrollAsync(invitationId.Text, code, CancellationToken.None);
            _viewModel.SetEnrollmentAccepted(result);
            var configuration = EndpointEnrollmentClient.ReadSavedConfiguration()
                ?? throw new ServerClientException(
                    ServerClientFailure.SecurityStateUnavailable,
                    "Enrollment was accepted, but the protected endpoint trust record could not be loaded.");
            StartEndpointFileDelivery(configuration);
            await ShowEnrollmentResultAsync(
                "Enrollment submitted",
                $"Computer ID: {result.ComputerId}\nThe endpoint is awaiting server approval. This does not establish a live connection or permit screen access.");
        }
        catch (ServerClientException exception)
        {
            _viewModel.SetEnrollmentIssue(exception.Message);
            await ShowEnrollmentResultAsync("Enrollment not completed", exception.Message);
        }
        catch (DeploymentTlsTrustException exception)
        {
            _viewModel.SetEnrollmentIssue(exception.Message);
            await ShowEnrollmentResultAsync("Enrollment not completed", exception.Message);
        }
        catch (ArgumentException exception)
        {
            _viewModel.SetEnrollmentIssue(exception.Message);
            await ShowEnrollmentResultAsync("Enrollment not completed", exception.Message);
        }
        catch (CryptographicException)
        {
            const string message = "The deployment CA certificate could not be read.";
            _viewModel.SetEnrollmentIssue(message);
            await ShowEnrollmentResultAsync("Enrollment not completed", message);
        }
        finally
        {
            if (caDer is not null)
            {
                CryptographicOperations.ZeroMemory(caDer);
            }

            code = string.Empty;
            caPem = string.Empty;
            UpdateEndpointIdentityControls();
        }
    }

    private async Task ShowEnrollmentResultAsync(string title, string message)
    {
        var dialog = new ContentDialog
        {
            Title = title,
            Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap },
            CloseButtonText = "Close",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = AppTitleBar.XamlRoot,
        };
        await dialog.ShowAsync();
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
