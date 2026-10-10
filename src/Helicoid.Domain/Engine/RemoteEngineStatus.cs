namespace Helicoid.Domain.Engine;

/// <summary>
/// Honest remote-engine availability. Version 1 ships without a compiled
/// native bridge, so the engine reports Unavailable. No ABI export names or
/// entry points are guessed here.
/// </summary>
public enum RemoteEngineAvailability
{
    Unavailable = 0,
    Ready = 1,
}

public sealed record RemoteEngineStatus(
    RemoteEngineAvailability Availability,
    string Reason)
{
    public static RemoteEngineStatus UnavailableNoBridge() => new(
        RemoteEngineAvailability.Unavailable,
        "Live previews and remote control are not available in this build.");

    public static RemoteEngineStatus Ready(string engineDescription) =>
        new(RemoteEngineAvailability.Ready, engineDescription);

    public bool IsAvailable => Availability == RemoteEngineAvailability.Ready;
}
