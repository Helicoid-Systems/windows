using Helicoid.Domain.Model;

namespace Helicoid.Domain.Overview;

/// <summary>
/// Stored monitoring inclusion demand. All mode includes every currently
/// authorized inventory ID; explicit mode never silently adds IDs.
/// Separate from authorization, temporary selection, and admitted streams.
/// </summary>
public sealed class MonitoringInclusion
{
    private readonly HashSet<ComputerId> _explicitIds = new();

    private MonitoringInclusion(bool isAllMode, IEnumerable<ComputerId>? explicitIds = null)
    {
        IsAllMode = isAllMode;
        if (explicitIds is not null)
        {
            foreach (var id in explicitIds)
            {
                _explicitIds.Add(id);
            }
        }
    }

    /// <summary>True when inclusion tracks all currently authorized inventory.</summary>
    public bool IsAllMode { get; private set; }

    /// <summary>Explicit included IDs. Empty when <see cref="IsAllMode"/> is true.</summary>
    public IReadOnlyCollection<ComputerId> ExplicitIds => _explicitIds;

    public static MonitoringInclusion All() => new(true);

    public static MonitoringInclusion Explicit(IEnumerable<ComputerId> ids)
    {
        ArgumentNullException.ThrowIfNull(ids);
        return new MonitoringInclusion(false, ids);
    }

    public static MonitoringInclusion EmptyExplicit() => new(false);

    /// <summary>
    /// Resolve the demanded ID set against current authorized inventory.
    /// All mode expands to current authorized IDs (D18). Explicit mode
    /// intersects and never expands.
    /// </summary>
    public IReadOnlyList<ComputerId> Resolve(IEnumerable<ComputerId> authorizedInventory)
    {
        ArgumentNullException.ThrowIfNull(authorizedInventory);
        var authorized = authorizedInventory as IReadOnlyCollection<ComputerId> ?? authorizedInventory.ToList();

        if (IsAllMode)
        {
            return authorized.Distinct().ToList();
        }

        return authorized.Where(_explicitIds.Contains).Distinct().ToList();
    }

    /// <summary>Check every current authorized inventory ID.</summary>
    public void CheckAll()
    {
        IsAllMode = true;
        _explicitIds.Clear();
    }

    /// <summary>Switch to an explicit set, replacing prior explicit membership.</summary>
    public void SetExplicit(IEnumerable<ComputerId> ids)
    {
        ArgumentNullException.ThrowIfNull(ids);
        IsAllMode = false;
        _explicitIds.Clear();
        foreach (var id in ids)
        {
            _explicitIds.Add(id);
        }
    }

    public void Add(ComputerId id)
    {
        if (IsAllMode)
        {
            return;
        }

        _explicitIds.Add(id);
    }

    public void Remove(ComputerId id)
    {
        if (IsAllMode)
        {
            // Leaving All mode requires an explicit set; dropping one ID
            // materializes the current explicit-minus-that-ID intent.
            IsAllMode = false;
        }

        _explicitIds.Remove(id);
    }

    /// <summary>Uncheck All without inventing IDs: empty explicit set.</summary>
    public void ClearToEmptyExplicit()
    {
        IsAllMode = false;
        _explicitIds.Clear();
    }

    /// <summary>
    /// True when this ID is demanded for the overview under All mode or
    /// explicit membership. Authorization is still resolved separately.
    /// </summary>
    public bool Contains(ComputerId id) => IsAllMode || _explicitIds.Contains(id);

    /// <summary>
    /// Tri-state for the All Computers checkbox against current authorized IDs.
    /// Empty authorized inventory is Unchecked, never a fake Checked.
    /// </summary>
    public InclusionCheckState GetAllCheckState(IReadOnlyCollection<ComputerId> authorized)
    {
        ArgumentNullException.ThrowIfNull(authorized);
        if (authorized.Count == 0)
        {
            return InclusionCheckState.Unchecked;
        }

        if (IsAllMode)
        {
            return InclusionCheckState.Checked;
        }

        var included = 0;
        foreach (var id in authorized)
        {
            if (_explicitIds.Contains(id))
            {
                included++;
            }
        }

        return included switch
        {
            0 => InclusionCheckState.Unchecked,
            _ when included == authorized.Count => InclusionCheckState.Checked,
            _ => InclusionCheckState.Indeterminate,
        };
    }

    /// <summary>
    /// Tri-state for one group of authorized member IDs.
    /// </summary>
    public InclusionCheckState GetGroupCheckState(IReadOnlyCollection<ComputerId> memberIds)
    {
        ArgumentNullException.ThrowIfNull(memberIds);
        if (memberIds.Count == 0)
        {
            return InclusionCheckState.Unchecked;
        }

        if (IsAllMode)
        {
            return InclusionCheckState.Checked;
        }

        var included = 0;
        foreach (var id in memberIds)
        {
            if (_explicitIds.Contains(id))
            {
                included++;
            }
        }

        return included switch
        {
            0 => InclusionCheckState.Unchecked,
            _ when included == memberIds.Count => InclusionCheckState.Checked,
            _ => InclusionCheckState.Indeterminate,
        };
    }

    /// <summary>
    /// Set one computer's inclusion without losing the rest of All mode.
    /// Unchecking while in All mode materializes authorized-minus-this-ID;
    /// checking while already in All mode is a no-op (no checkbox loop).
    /// </summary>
    public void SetIncluded(
        ComputerId id,
        bool included,
        IReadOnlyCollection<ComputerId> authorized)
    {
        ArgumentNullException.ThrowIfNull(authorized);

        if (included)
        {
            if (IsAllMode)
            {
                return;
            }

            _explicitIds.Add(id);
            return;
        }

        if (!IsAllMode)
        {
            _explicitIds.Remove(id);
            return;
        }

        IsAllMode = false;
        _explicitIds.Clear();
        foreach (var other in authorized)
        {
            if (other != id)
            {
                _explicitIds.Add(other);
            }
        }
    }

    /// <summary>Set every member of a group included or excluded.</summary>
    public void SetGroupIncluded(
        IEnumerable<ComputerId> memberIds,
        bool included,
        IReadOnlyCollection<ComputerId> authorized)
    {
        ArgumentNullException.ThrowIfNull(memberIds);
        ArgumentNullException.ThrowIfNull(authorized);
        var members = memberIds as IReadOnlyCollection<ComputerId> ?? memberIds.ToList();
        foreach (var id in members)
        {
            SetIncluded(id, included, authorized);
        }
    }

    /// <summary>
    /// Restore saved inclusion against current inventory. Explicit IDs that are
    /// no longer authorized are dropped rather than restored blindly.
    /// </summary>
    public static MonitoringInclusion Restore(
        bool savedAllMode,
        IEnumerable<ComputerId>? savedExplicitIds,
        IEnumerable<ComputerId> currentAuthorized)
    {
        ArgumentNullException.ThrowIfNull(currentAuthorized);
        var authorized = currentAuthorized as IReadOnlyCollection<ComputerId> ?? currentAuthorized.ToList();

        if (savedAllMode)
        {
            return All();
        }

        var restored = (savedExplicitIds ?? Enumerable.Empty<ComputerId>())
            .Where(authorized.Contains)
            .ToList();
        return Explicit(restored);
    }
}
