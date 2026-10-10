using Helicoid.Domain.Model;

namespace Helicoid.Domain.Overview;

/// <summary>
/// The five overview state objects kept deliberately separate:
/// panel inclusion, displayed IDs, tile selection, action snapshots, and
/// actual admitted streams. Do not collapse these into one boolean or one
/// selected-ID array.
/// </summary>
public sealed class OverviewState
{
    private readonly Dictionary<ComputerId, string> _names = new();
    private readonly List<AdmittedStream> _admittedStreams = new();
    private readonly List<ActionSnapshot> _openActionSnapshots = new();
    private IReadOnlyList<ComputerRecord> _inventory = Array.Empty<ComputerRecord>();
    private IReadOnlyList<ComputerId> _authorizedIds = Array.Empty<ComputerId>();
    private IReadOnlyList<ComputerId> _displayedIds = Array.Empty<ComputerId>();

    public MonitoringInclusion Inclusion { get; private set; } = MonitoringInclusion.All();

    public OverviewFilter Filter { get; } = new();

    public ActionSelection Selection { get; } = new();

    /// <summary>Displayed IDs after inclusion and current search/status filters.</summary>
    public IReadOnlyList<ComputerId> DisplayedIds => _displayedIds;

    /// <summary>Default target set for a new bulk action when nothing is selected.</summary>
    public IReadOnlyList<ComputerId> DefaultActionTargets =>
        Selection.Count > 0
            ? Selection.SelectedIds.Where(_displayedIds.Contains).ToList()
            : _displayedIds;

    /// <summary>Actual admitted observation streams, independent of inclusion.</summary>
    public IReadOnlyList<AdmittedStream> AdmittedStreams => _admittedStreams;

    /// <summary>Actions currently open with frozen IDs.</summary>
    public IReadOnlyList<ActionSnapshot> OpenActionSnapshots => _openActionSnapshots;

    public void SetInclusion(MonitoringInclusion inclusion)
    {
        ArgumentNullException.ThrowIfNull(inclusion);
        Inclusion = inclusion;
        Selection.Clear();
        RecomputeDisplayed();
    }

    public void UpdateInventory(
        IReadOnlyList<ComputerRecord> inventory,
        IReadOnlyList<ComputerId> authorizedIds)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        ArgumentNullException.ThrowIfNull(authorizedIds);

        _inventory = inventory;
        _authorizedIds = authorizedIds;

        _names.Clear();
        foreach (var computer in inventory)
        {
            _names[computer.Id] = computer.Name;
        }

        RecomputeDisplayed();
    }

    public void SetSearch(string? query)
    {
        Filter.SetSearch(query);
        Selection.Clear();
        RecomputeDisplayed();
    }

    public void SetStatusFilter(StatusFilter filter)
    {
        Filter.SetStatus(filter);
        Selection.Clear();
        RecomputeDisplayed();
    }

    private void RecomputeDisplayed()
    {
        var included = Inclusion.Resolve(_authorizedIds);
        var byId = _inventory.ToDictionary(c => c.Id);
        _displayedIds = included
            .Where(id => byId.TryGetValue(id, out var record) && Filter.Matches(record))
            .ToList();
    }

    public void SelectOnly(ComputerId id)
    {
        if (_displayedIds.Contains(id))
        {
            Selection.SelectOnly(id);
        }
    }

    public void ToggleSelection(ComputerId id)
    {
        if (_displayedIds.Contains(id))
        {
            Selection.Toggle(id);
        }
    }

    public void ClearSelection() => Selection.Clear();

    /// <summary>
    /// Freeze the current default action targets into an immutable snapshot.
    /// Zero displayed IDs cannot dispatch.
    /// </summary>
    public ActionSnapshot OpenAction(string actionName)
    {
        var targets = DefaultActionTargets
            .Select(id => (id, _names.TryGetValue(id, out var name) ? name : id.Value))
            .ToList();
        if (targets.Count == 0)
        {
            throw new InvalidOperationException("Cannot open an action with zero displayed computers.");
        }

        var snapshot = ActionSnapshot.Freeze(actionName, targets);
        _openActionSnapshots.Add(snapshot);
        return snapshot;
    }

    public void CloseAction(ActionSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        _openActionSnapshots.Remove(snapshot);
    }

    /// <summary>
    /// Record or replace one admitted stream. Inclusion changes stop overview
    /// demand; independent detail windows are not retargeted by this method.
    /// </summary>
    public void UpsertAdmittedStream(ComputerId id, string streamKind)
    {
        _admittedStreams.RemoveAll(s => s.ComputerId == id && s.StreamKind == streamKind);
        _admittedStreams.Add(new AdmittedStream(id, streamKind));
    }

    public void StopAdmittedStreams(ComputerId id) =>
        _admittedStreams.RemoveAll(s => s.ComputerId == id);

    public void StopAllAdmittedStreams() => _admittedStreams.Clear();

    /// <summary>Removing overview demand clears that computer's overview stream.</summary>
    public void OnInclusionRemoved(ComputerId id) => StopAdmittedStreams(id);
}

/// <summary>One actually admitted media stream, separate from inclusion demand.</summary>
public sealed record AdmittedStream(ComputerId ComputerId, string StreamKind);
