namespace Helicoid.Domain.Model;

/// <summary>
/// Optional flat organization group. Membership filters the overview and never
/// grants access by itself.
/// </summary>
public sealed record ComputerGroup(string Id, string Name)
{
    public IReadOnlyList<ComputerId> MemberIds { get; init; } = Array.Empty<ComputerId>();
}
