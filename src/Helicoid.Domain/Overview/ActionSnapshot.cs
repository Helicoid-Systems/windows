using System.Collections.ObjectModel;
using Helicoid.Domain.Model;

namespace Helicoid.Domain.Overview;

/// <summary>
/// Immutable target set captured when an action composer opens. Search,
/// selection, and later connections cannot silently expand it. Revocation can
/// deny execution but cannot replace targets. Collections are read-only wrappers
/// so a cast cannot mutate frozen IDs or names.
/// </summary>
public sealed class ActionSnapshot
{
    private ActionSnapshot(
        string actionName,
        ReadOnlyCollection<ComputerId> computerIds,
        ReadOnlyCollection<string> displayNames,
        DateTimeOffset createdAtUtc)
    {
        ActionName = actionName;
        ComputerIds = computerIds;
        DisplayNames = displayNames;
        CreatedAtUtc = createdAtUtc;
    }

    public string ActionName { get; }

    public IReadOnlyList<ComputerId> ComputerIds { get; }

    public IReadOnlyList<string> DisplayNames { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public int Count => ComputerIds.Count;

    public static ActionSnapshot Freeze(
        string actionName,
        IEnumerable<(ComputerId Id, string Name)> targets,
        DateTimeOffset? createdAtUtc = null)
    {
        if (string.IsNullOrWhiteSpace(actionName))
        {
            throw new ArgumentException("Action name is required.", nameof(actionName));
        }

        ArgumentNullException.ThrowIfNull(targets);
        var list = targets.ToList();
        return new ActionSnapshot(
            actionName.Trim(),
            Array.AsReadOnly(list.Select(t => t.Id).ToArray()),
            Array.AsReadOnly(list.Select(t => t.Name).ToArray()),
            createdAtUtc ?? DateTimeOffset.UtcNow);
    }
}
