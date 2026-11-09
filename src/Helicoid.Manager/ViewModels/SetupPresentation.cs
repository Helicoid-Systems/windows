using Helicoid.Domain.Setup;

namespace Helicoid.Manager.ViewModels;

/// <summary>
/// Native display projection for one host-check row. Unimplemented and
/// pending results read as "Not verified" rather than a passed row.
/// </summary>
public sealed class SetupHostCheckRow
{
    public SetupHostCheckRow(HostCheckRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        Name = row.Name;
        Detail = row.Detail ?? string.Empty;
        HasDetail = !string.IsNullOrWhiteSpace(Detail);
        StateText = row.Result switch
        {
            CheckResult.Passed => "Passed",
            CheckResult.NeedsAttention => "Needs attention",
            CheckResult.Checking => "Checking",
            CheckResult.Unimplemented => "Not verified",
            _ => "Not checked",
        };
    }

    public string Name { get; }

    public string StateText { get; }

    public string Detail { get; }

    public bool HasDetail { get; }
}
