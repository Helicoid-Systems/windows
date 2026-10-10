namespace Helicoid.Domain.Client;

/// <summary>
/// Launch-time switches for the manager. The development loopback client is
/// available only when the explicit --development-server option is present.
/// </summary>
public sealed class DevelopmentLaunchOptions
{
    public const string DevelopmentServerSwitch = "--development-server";
    public const string DevelopmentIdentitySwitch = "--development-manager-identity";

    public bool DevelopmentServerEnabled { get; private set; }

    public string? DevelopmentServerAddress { get; private set; }

    /// <summary>
    /// Operator-chosen development manager identity string. This is a loopback
    /// development fixture, not a cryptographic production identity.
    /// </summary>
    public string? DevelopmentManagerIdentity { get; private set; }

    public static DevelopmentLaunchOptions Parse(IEnumerable<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var options = new DevelopmentLaunchOptions();
        string? pendingValueFor = null;

        foreach (var raw in args)
        {
            var arg = raw ?? string.Empty;
            if (pendingValueFor is not null)
            {
                options.ApplyValue(pendingValueFor, arg);
                pendingValueFor = null;
                continue;
            }

            if (arg.Equals(DevelopmentServerSwitch, StringComparison.OrdinalIgnoreCase))
            {
                options.DevelopmentServerEnabled = true;
                continue;
            }

            if (arg.StartsWith(DevelopmentServerSwitch + "=", StringComparison.OrdinalIgnoreCase))
            {
                options.DevelopmentServerEnabled = true;
                options.ApplyValue(DevelopmentServerSwitch, arg[(DevelopmentServerSwitch.Length + 1)..]);
                continue;
            }

            if (arg.Equals(DevelopmentIdentitySwitch, StringComparison.OrdinalIgnoreCase))
            {
                pendingValueFor = DevelopmentIdentitySwitch;
                continue;
            }

            if (arg.StartsWith(DevelopmentIdentitySwitch + "=", StringComparison.OrdinalIgnoreCase))
            {
                options.ApplyValue(
                    DevelopmentIdentitySwitch,
                    arg[(DevelopmentIdentitySwitch.Length + 1)..]);
            }
        }

        return options;
    }

    private void ApplyValue(string name, string value)
    {
        if (name.Equals(DevelopmentServerSwitch, StringComparison.OrdinalIgnoreCase))
        {
            DevelopmentServerAddress = value.Trim();
            return;
        }

        if (name.Equals(DevelopmentIdentitySwitch, StringComparison.OrdinalIgnoreCase))
        {
            DevelopmentManagerIdentity = value.Trim();
        }
    }

    /// <summary>
    /// Build the client for this process. Development loopback requires the
    /// explicit switch; otherwise the closed production client is returned.
    /// </summary>
    public IHsServerClient CreateClient(HttpMessageHandler? handler = null)
    {
        if (!DevelopmentServerEnabled)
        {
            return new ClosedProductionClient();
        }

        var address = string.IsNullOrWhiteSpace(DevelopmentServerAddress)
            ? $"http://127.0.0.1:{DevelopmentServerClient.DefaultPort}"
            : DevelopmentServerAddress;

        return DevelopmentServerClient.CreateLoopback(address, handler);
    }
}
