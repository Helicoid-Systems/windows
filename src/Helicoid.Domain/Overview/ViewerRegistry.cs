using Helicoid.Domain.Model;

namespace Helicoid.Domain.Overview;

/// <summary>
/// App-owned registry of open remote view-only windows. Portable: no UI
/// types. Keys are the actual computer identity plus session context so a
/// stale close can never remove a replacement window.
/// </summary>
public sealed class ViewerRegistry
{
    private readonly Dictionary<(ComputerId Id, int Session), ViewerToken> _open = new();
    private int _nextHandle = 1;

    public event EventHandler? Changed;

    /// <summary>One open viewer. Handle is unique per open, not per computer.</summary>
    public sealed record ViewerToken(int Handle, ComputerId ComputerId, int SessionContext)
    {
        /// <summary>True after the owner closed this exact handle.</summary>
        public bool IsClosed { get; internal set; }
    }

    public IReadOnlyCollection<ViewerToken> OpenViewers => _open.Values.Where(v => !v.IsClosed).ToList();

    /// <summary>
    /// Register a viewer for this computer and session. Reopen of the same
    /// computer+session returns the existing token so the UI can focus it
    /// instead of creating a duplicate. Distinct sessions may both be open.
    /// </summary>
    public ViewerToken OpenOrFocus(ComputerId computerId, int sessionContext)
    {
        var key = (computerId, sessionContext);
        if (_open.TryGetValue(key, out var existing) && !existing.IsClosed)
        {
            return existing;
        }

        var token = new ViewerToken(_nextHandle++, computerId, sessionContext);
        _open[key] = token;
        Changed?.Invoke(this, EventArgs.Empty);
        return token;
    }

    /// <summary>
    /// Close one viewer by handle. A stale close for a handle that was already
    /// replaced never removes the replacement entry.
    /// </summary>
    public bool Close(int handle)
    {
        foreach (var (key, token) in _open)
        {
            if (token.Handle != handle)
            {
                continue;
            }

            token.IsClosed = true;
            if (ReferenceEquals(_open.GetValueOrDefault(key), token))
            {
                _open.Remove(key);
            }

            Changed?.Invoke(this, EventArgs.Empty);
            return true;
        }

        return false;
    }

    /// <summary>True when this exact handle is still the live viewer.</summary>
    public bool IsLive(int handle) =>
        _open.Values.Any(v => v.Handle == handle && !v.IsClosed);

    /// <summary>
    /// Close every viewer bound to a session context. Called on session loss
    /// and identity change so invalidated windows cannot outlive auth.
    /// </summary>
    public IReadOnlyList<ViewerToken> CloseSession(int sessionContext)
    {
        var closed = new List<ViewerToken>();
        foreach (var key in _open.Keys.ToList())
        {
            if (key.Session != sessionContext)
            {
                continue;
            }

            var token = _open[key];
            token.IsClosed = true;
            _open.Remove(key);
            closed.Add(token);
        }

        if (closed.Count > 0) Changed?.Invoke(this, EventArgs.Empty);
        return closed;
    }

    public void RetainAuthorized(IReadOnlySet<ComputerId> authorized)
    {
        foreach (var token in _open.Values.Where(v => !authorized.Contains(v.ComputerId)).ToList())
        {
            Close(token.Handle);
        }
    }

    /// <summary>Close every open viewer (app shutdown, not used by host close).</summary>
    public IReadOnlyList<ViewerToken> CloseAll()
    {
        var closed = _open.Values.ToList();
        foreach (var token in closed)
        {
            token.IsClosed = true;
        }

        _open.Clear();
        if (closed.Count > 0) Changed?.Invoke(this, EventArgs.Empty);
        return closed;
    }
}
