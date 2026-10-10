using Helicoid.Domain.PhysicalConsole;
using Helicoid.WindowsPlatform.Native;

namespace Helicoid.WindowsPlatform;

/// <summary>
/// Periodic physical-console observer. Runs two-pass WTS observations on a
/// configurable interval and reports eligibility changes to a callback.
/// Used by the Computer app to detect lock/logout/user switch and fence
/// existing workers.
///
/// The observer does NOT manufacture trust from WTS facts. It reports
/// diagnostic eligibility only — never admission, capture authority, or enrollment.
///
/// Lifetime: the loop owns its CancellationTokenSource and Task. Stop() cancels,
/// awaits the task (not .Wait), and nulls references only after confirmed
/// termination. A new Start() while the previous loop is still draining is
/// rejected. Exceptions from the loop propagate to the caller of Stop() via
/// the error callback; they are not silently swallowed.
/// </summary>
public sealed class PhysicalConsoleObserverLoop : IDisposable
{
    private readonly TimeSpan _interval;
    private readonly Action<PhysicalConsoleEligibility> _onObservation;
    private readonly Action<Exception>? _onError;
    private readonly object _lock = new();
    private CancellationTokenSource? _cts;
    private Task? _loopTask;
    private PhysicalConsoleEligibility? _lastObservation;
    private bool _disposed;

    /// <summary>
    /// Create a new observer loop.
    /// </summary>
    /// <param name="interval">Interval between observations.</param>
    /// <param name="onObservation">Called on each observation with the eligibility result.</param>
    /// <param name="onError">Called on unhandled exceptions in the loop (optional).</param>
    public PhysicalConsoleObserverLoop(
        TimeSpan interval,
        Action<PhysicalConsoleEligibility> onObservation,
        Action<Exception>? onError = null)
    {
        _interval = interval;
        _onObservation = onObservation;
        _onError = onError;
    }

    /// <summary>
    /// The last observation result, or null if no observation has been made.
    /// </summary>
    public PhysicalConsoleEligibility? LastObservation
    {
        get { lock (_lock) return _lastObservation; }
    }

    /// <summary>
    /// Whether the observer loop is currently running.
    /// </summary>
    public bool IsRunning
    {
        get { lock (_lock) return _loopTask is not null && !_loopTask.IsCompleted; }
    }

    /// <summary>
    /// Start the observer loop. The first observation runs immediately.
    /// If the loop is already running, this is a no-op.
    /// </summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        lock (_lock)
        {
            // Reject if a previous loop is still draining.
            if (_loopTask is not null && !_loopTask.IsCompleted)
            {
                return;
            }

            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _loopTask = Task.Run(() => RunLoopAsync(token));
        }
    }

    /// <summary>
    /// Stop the observer loop. Awaits the task to confirm termination.
    /// Exceptions from the loop are propagated to the error callback; this
    /// method itself only throws ObjectDisposedException.
    /// </summary>
    public void Stop()
    {
        Task? task;
        CancellationTokenSource? cts;

        lock (_lock)
        {
            cts = _cts;
            task = _loopTask;
        }

        if (cts is null || task is null)
        {
            return;
        }

        cts.Cancel();

        try
        {
            // Await (not .Wait) to avoid blocking and AggregateException wrapping.
            task.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException) when (task.IsCanceled)
        {
            // Expected: task was canceled.
        }
        catch (AggregateException ex)
        {
            // Unwrap and report any non-cancellation exceptions from the loop.
            foreach (var inner in ex.Flatten().InnerExceptions)
            {
                if (inner is not OperationCanceledException)
                {
                    _onError?.Invoke(inner);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected.
        }

        lock (_lock)
        {
            // Only null references after confirmed termination.
            if (task.IsCompleted)
            {
                _loopTask = null;
                _cts?.Dispose();
                _cts = null;
            }
        }
    }

    /// <summary>
    /// Take a single observation now (synchronous).
    /// </summary>
    public PhysicalConsoleEligibility ObserveOnce()
    {
        var eligibility = PhysicalConsoleObserver.Observe();
        lock (_lock)
        {
            _lastObservation = eligibility;
        }
        return eligibility;
    }

    private async Task RunLoopAsync(CancellationToken ct)
    {
        // First observation immediately.
        try
        {
            var eligibility = ObserveOnce();
            _onObservation(eligibility);
        }
        catch (Exception ex)
        {
            _onError?.Invoke(ex);
        }

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_interval, ct).ConfigureAwait(false);

                var eligibility = ObserveOnce();
                _onObservation(eligibility);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _onError?.Invoke(ex);
            }
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            Stop();
        }
    }
}