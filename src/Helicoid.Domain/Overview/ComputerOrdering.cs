using Helicoid.Domain.Model;

namespace Helicoid.Domain.Overview;

/// <summary>
/// Stable display order: natural computer name comparison with a
/// <see cref="ComputerId"/> ordinal tie break. Digit runs compare as numbers
/// so PC-2 sorts before PC-10.
/// </summary>
public static class ComputerOrdering
{
    public static IEnumerable<ComputerRecord> OrderForDisplay(IEnumerable<ComputerRecord> records)
    {
        ArgumentNullException.ThrowIfNull(records);
        return records
            .OrderBy(r => r.Name, NaturalNameComparer.Instance)
            .ThenBy(r => r.Id.Value, StringComparer.Ordinal);
    }

    public static IEnumerable<ComputerId> OrderIdsForDisplay(
        IEnumerable<ComputerId> ids,
        IReadOnlyDictionary<ComputerId, string> names)
    {
        ArgumentNullException.ThrowIfNull(ids);
        ArgumentNullException.ThrowIfNull(names);
        return ids
            .OrderBy(id => names.TryGetValue(id, out var name) ? name : id.Value, NaturalNameComparer.Instance)
            .ThenBy(id => id.Value, StringComparer.Ordinal);
    }

    /// <summary>Natural name comparison: case-insensitive, digit runs as numbers.</summary>
    public sealed class NaturalNameComparer : IComparer<string>
    {
        public static NaturalNameComparer Instance { get; } = new();

        public int Compare(string? x, string? y)
        {
            if (ReferenceEquals(x, y))
            {
                return 0;
            }

            if (x is null)
            {
                return -1;
            }

            if (y is null)
            {
                return 1;
            }

            var ix = 0;
            var iy = 0;
            while (ix < x.Length && iy < y.Length)
            {
                if (char.IsDigit(x[ix]) && char.IsDigit(y[iy]))
                {
                    var sx = ix;
                    var sy = iy;
                    while (ix < x.Length && char.IsDigit(x[ix]))
                    {
                        ix++;
                    }

                    while (iy < y.Length && char.IsDigit(y[iy]))
                    {
                        iy++;
                    }

                    // Compare digit runs as integers (leading zeros ignored).
                    var nx = x[sx..ix].TrimStart('0');
                    var ny = y[sy..iy].TrimStart('0');
                    if (nx.Length != ny.Length)
                    {
                        return nx.Length - ny.Length;
                    }

                    var numeric = string.CompareOrdinal(nx, ny);
                    if (numeric != 0)
                    {
                        return numeric;
                    }
                }
                else
                {
                    var cx = char.ToUpperInvariant(x[ix]);
                    var cy = char.ToUpperInvariant(y[iy]);
                    if (cx != cy)
                    {
                        return cx.CompareTo(cy);
                    }

                    ix++;
                    iy++;
                }
            }

            return (x.Length - ix).CompareTo(y.Length - iy);
        }
    }
}
