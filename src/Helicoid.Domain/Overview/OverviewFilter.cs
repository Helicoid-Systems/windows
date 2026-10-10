using Helicoid.Domain.Model;

namespace Helicoid.Domain.Overview;

public enum StatusFilter
{
    All = 0,
    Online = 1,
    NeedsAttention = 2,
}

/// <summary>
/// Search and status filters applied to included IDs. Filters never erase
/// enrollment or grant permissions.
/// </summary>
public sealed class OverviewFilter
{
    public string SearchQuery { get; private set; } = string.Empty;

    public StatusFilter StatusFilter { get; private set; } = StatusFilter.All;

    public void SetSearch(string? query) => SearchQuery = query?.Trim() ?? string.Empty;

    public void SetStatus(StatusFilter filter) => StatusFilter = filter;

    public void ClearSearch() => SearchQuery = string.Empty;

    /// <summary>
    /// Match computer name and trusted current user name (case-insensitive).
    /// </summary>
    public bool Matches(ComputerRecord computer)
    {
        ArgumentNullException.ThrowIfNull(computer);
        if (!StatusMatches(computer.Status))
        {
            return false;
        }

        if (SearchQuery.Length == 0)
        {
            return true;
        }

        return computer.Name.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase)
            || (computer.TrustedUserName?.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ?? false);
    }

    private bool StatusMatches(ComputerStatus status) => StatusFilter switch
    {
        StatusFilter.Online => status is ComputerStatus.Online or ComputerStatus.Connecting,
        StatusFilter.NeedsAttention => status is ComputerStatus.NeedsAttention
            or ComputerStatus.Failed
            or ComputerStatus.PendingApproval
            or ComputerStatus.Unavailable,
        _ => true,
    };
}
