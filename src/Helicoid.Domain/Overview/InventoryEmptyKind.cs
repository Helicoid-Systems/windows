namespace Helicoid.Domain.Overview;

/// <summary>
/// Why the inventory area shows no computers. The three empty causes are
/// distinct so the UI can offer the action that actually helps.
/// </summary>
public enum InventoryEmptyKind
{
    /// <summary>At least one computer is displayed.</summary>
    None = 0,

    /// <summary>No authorized inventory exists for this session.</summary>
    NoInventory = 1,

    /// <summary>Inventory exists but nothing is included.</summary>
    NoInclusion = 2,

    /// <summary>Computers are included but search/status filters match none.</summary>
    NoMatches = 3,
}
