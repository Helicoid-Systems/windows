namespace Helicoid.Domain.Tests;

/// <summary>
/// TEST-ONLY deterministic <see cref="TimeProvider"/> seam for session deadline
/// proofs. Preserves full UTC ticks and a separate monotonic tick stream so
/// fractional reception, wall rollback/jumps, and early timer fires can be
/// proven without polling. Production constructors select TimeProvider.System.
/// </summary>
internal sealed class FakeTimeProvider : TimeProvider
{
    private readonly object _gate = new();
    private DateTimeOffset _utcNow;
    private long _timestamp;
    private readonly List<FakeTimer> _timers = new();

    public FakeTimeProvider(DateTimeOffset utcNow)
    {
        _utcNow = utcNow;
        _timestamp = utcNow.UtcTicks / (TimeSpan.TicksPerSecond / TimestampFrequency);
    }

    public override long TimestampFrequency => 10_000_000;

    public override DateTimeOffset GetUtcNow()
    {
        lock (_gate)
        {
            return _utcNow;
        }
    }

    public override long GetTimestamp()
    {
        lock (_gate)
        {
            return _timestamp;
        }
    }

    public override ITimer CreateTimer(
        TimerCallback callback,
        object? state,
        TimeSpan dueTime,
        TimeSpan period)
    {
        lock (_gate)
        {
            var timer = new FakeTimer(this, callback, state, dueTime, period, _timestamp);
            _timers.Add(timer);
            return timer;
        }
    }

    /// <summary>Advance wall and monotonic clocks together and fire due timers.</summary>
    public void Advance(TimeSpan delta)
    {
        if (delta < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(delta));
        }

        List<(TimerCallback Callback, object? State)> due = new();
        lock (_gate)
        {
            var ticks = (long)(delta.Ticks * ((double)TimestampFrequency / TimeSpan.TicksPerSecond));
            _timestamp += ticks;
            _utcNow = _utcNow.AddTicks(delta.Ticks);

            for (var i = _timers.Count - 1; i >= 0; i--)
            {
                if (_timers[i].TryFire(_timestamp, out var callback, out var state))
                {
                    due.Add((callback, state));
                    if (_timers[i].IsOneShot)
                    {
                        _timers.RemoveAt(i);
                    }
                }
            }
        }

        foreach (var (callback, state) in due)
        {
            callback(state);
        }
    }

    /// <summary>
    /// Wall-clock jump only (rollback or forward). Monotonic timestamp is
    /// unchanged so rollback cannot extend a monotonic deadline.
    /// </summary>
    public void JumpWallClock(TimeSpan delta)
    {
        lock (_gate)
        {
            _utcNow = _utcNow.AddTicks(delta.Ticks);
        }
    }

    /// <summary>
    /// Move wall and monotonic clocks without dispatching timers. Proves that
    /// authorized response fencing does not depend on timer callback timing.
    /// </summary>
    public void AdvanceWithoutDispatch(TimeSpan delta)
    {
        if (delta < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(delta));
        }

        lock (_gate)
        {
            var ticks = (long)(delta.Ticks * ((double)TimestampFrequency / TimeSpan.TicksPerSecond));
            _timestamp += ticks;
            _utcNow = _utcNow.AddTicks(delta.Ticks);
        }
    }

    /// <summary>
    /// TEST-ONLY: invoke a live one-shot callback before its due time, with the
    /// timer disabled first (genuine early fire, not a due-advance).
    /// </summary>
    public void FireTimerEarly()
    {
        List<(TimerCallback Callback, object? State)> due = new();
        lock (_gate)
        {
            for (var i = _timers.Count - 1; i >= 0; i--)
            {
                if (_timers[i].TryFireEarly(out var callback, out var state))
                {
                    due.Add((callback, state));
                    if (_timers[i].IsOneShot)
                    {
                        _timers.RemoveAt(i);
                    }
                }
            }
        }

        foreach (var (callback, state) in due)
        {
            callback(state);
        }
    }

    /// <summary>Test seam: fire due timers without advancing clocks (early fire).</summary>
    public void FireDueTimers()
    {
        List<(TimerCallback Callback, object? State)> due = new();
        lock (_gate)
        {
            for (var i = _timers.Count - 1; i >= 0; i--)
            {
                if (_timers[i].TryFire(_timestamp, out var callback, out var state))
                {
                    due.Add((callback, state));
                    if (_timers[i].IsOneShot)
                    {
                        _timers.RemoveAt(i);
                    }
                }
            }
        }

        foreach (var (callback, state) in due)
        {
            callback(state);
        }
    }

    private sealed class FakeTimer : ITimer
    {
        private readonly FakeTimeProvider _owner;
        private readonly TimerCallback _callback;
        private readonly object? _state;
        private readonly TimeSpan _period;
        private long _dueTimestamp;
        private bool _disposed;

        public FakeTimer(
            FakeTimeProvider owner,
            TimerCallback callback,
            object? state,
            TimeSpan dueTime,
            TimeSpan period,
            long nowTimestamp)
        {
            _owner = owner;
            _callback = callback;
            _state = state;
            _period = period;
            _dueTimestamp = nowTimestamp + ToFrequencyTicks(owner, dueTime);
        }

        public bool IsOneShot => _period == Timeout.InfiniteTimeSpan || _period <= TimeSpan.Zero;

        private static long ToFrequencyTicks(FakeTimeProvider owner, TimeSpan value)
        {
            if (value <= TimeSpan.Zero)
            {
                return 0;
            }

            return (long)(value.Ticks * ((double)owner.TimestampFrequency / TimeSpan.TicksPerSecond));
        }

        /// <summary>Caller holds the owner gate.</summary>
        public bool TryFire(long nowTimestamp, out TimerCallback callback, out object? state)
        {
            callback = _callback;
            state = _state;
            if (_disposed || nowTimestamp < _dueTimestamp)
            {
                return false;
            }

            if (IsOneShot)
            {
                _disposed = true;
            }
            else
            {
                _dueTimestamp = nowTimestamp + ToFrequencyTicks(_owner, _period);
            }

            return true;
        }

        /// <summary>Caller holds the owner gate. Disable then fire before due.</summary>
        public bool TryFireEarly(out TimerCallback callback, out object? state)
        {
            callback = _callback;
            state = _state;
            if (_disposed)
            {
                return false;
            }

            // Mirror ReviewEarlyClock: the one-shot is disabled before the
            // callback runs so it cannot be double-fired as still-active.
            if (IsOneShot)
            {
                _disposed = true;
            }

            return true;
        }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (_owner._gate)
            {
                if (_disposed)
                {
                    return false;
                }

                _dueTimestamp = _owner._timestamp + ToFrequencyTicks(_owner, dueTime);
                return true;
            }
        }

        public void Dispose()
        {
            lock (_owner._gate)
            {
                _disposed = true;
                _owner._timers.Remove(this);
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
