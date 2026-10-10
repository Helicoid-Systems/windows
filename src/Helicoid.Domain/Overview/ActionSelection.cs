using Helicoid.Domain.Model;

namespace Helicoid.Domain.Overview;

/// <summary>
/// Temporary tile selection for the next command. Cleared whenever inclusion,
/// search, or status filters change. Never reused as stored inclusion or as an
/// action snapshot.
/// </summary>
public sealed class ActionSelection
{
    private readonly HashSet<ComputerId> _selected = new();

    public IReadOnlyCollection<ComputerId> SelectedIds => _selected;

    public int Count => _selected.Count;

    public bool IsSelected(ComputerId id) => _selected.Contains(id);

    public void Select(ComputerId id) => _selected.Add(id);

    /// <summary>Replace selection with exactly this ID (right-click on unselected tile).</summary>
    public void SelectOnly(ComputerId id)
    {
        _selected.Clear();
        _selected.Add(id);
    }

    public void Toggle(ComputerId id)
    {
        if (!_selected.Remove(id))
        {
            _selected.Add(id);
        }
    }

    /// <summary>Shift-range select along the current displayed stable sort order.</summary>
    public void ExtendAlong(ComputerId anchor, ComputerId target, IReadOnlyList<ComputerId> displayedOrder)
    {
        ArgumentNullException.ThrowIfNull(displayedOrder);
        var start = IndexOf(displayedOrder, anchor);
        var end = IndexOf(displayedOrder, target);
        if (start < 0 || end < 0)
        {
            SelectOnly(target);
            return;
        }

        var (from, to) = start <= end ? (start, end) : (end, start);
        for (var i = from; i <= to; i++)
        {
            _selected.Add(displayedOrder[i]);
        }
    }

    public void SelectAll(IEnumerable<ComputerId> displayedIds)
    {
        ArgumentNullException.ThrowIfNull(displayedIds);
        foreach (var id in displayedIds)
        {
            _selected.Add(id);
        }
    }

    public void Clear() => _selected.Clear();

    private static int IndexOf(IReadOnlyList<ComputerId> order, ComputerId id)
    {
        for (var i = 0; i < order.Count; i++)
        {
            if (order[i] == id)
            {
                return i;
            }
        }

        return -1;
    }
}
