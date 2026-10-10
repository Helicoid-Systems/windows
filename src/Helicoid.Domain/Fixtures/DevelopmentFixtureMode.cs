using Helicoid.Domain.Model;

namespace Helicoid.Domain.Fixtures;

/// <summary>
/// Development fixtures are off by default and must be explicitly enabled.
/// They are labeled as non-production sample data and are never presented as
/// real computer pixels or measured platform results.
/// </summary>
public sealed class DevelopmentFixtureMode
{
    public bool IsEnabled { get; private set; }

    public string Label => IsEnabled
        ? "Development fixtures — sample data, not real computers"
        : "Production inventory (no fixtures)";

    public void Enable()
    {
        IsEnabled = true;
    }

    public void Disable()
    {
        IsEnabled = false;
    }

    public IReadOnlyList<ComputerRecord> BuildInventoryOrEmpty()
    {
        return IsEnabled
            ? DevelopmentFixtures.SampleInventory()
            : Array.Empty<ComputerRecord>();
    }
}

public static class DevelopmentFixtures
{
    public const string FixtureLabel = "Development fixture — sample data, not real computers";

    public static IReadOnlyList<ComputerRecord> SampleInventory() =>
        new[]
        {
            new ComputerRecord(ComputerId.Parse("fixture-pc-01"), "Lab PC-01", ComputerStatus.Online, "sample-user-a"),
            new ComputerRecord(ComputerId.Parse("fixture-pc-02"), "Lab PC-02", ComputerStatus.Online, "sample-user-b"),
            new ComputerRecord(ComputerId.Parse("fixture-pc-03"), "Lab PC-03", ComputerStatus.Offline),
            new ComputerRecord(ComputerId.Parse("fixture-pc-04"), "Lab PC-04", ComputerStatus.NeedsAttention, "sample-user-c"),
            new ComputerRecord(ComputerId.Parse("fixture-pc-05"), "Lab PC-05", ComputerStatus.PendingApproval),
            new ComputerRecord(ComputerId.Parse("fixture-pc-06"), "Lab PC-06", ComputerStatus.Failed),
        };

    public static IReadOnlyList<ComputerId> SampleAuthorizedIds() =>
        SampleInventory().Select(c => c.Id).ToList();
}
