namespace Helicoid.Domain.Overview;

/// <summary>
/// Logical preview width for overview tiles. Session-only presentation
/// preference: never persisted under a global key or invented account scope.
/// Height uses 16:9 aspect until real frame metadata exists.
/// </summary>
public enum PreviewSize
{
    Compact192 = 192,
    Standard256 = 256,
    Large320 = 320,
    ExtraLarge448 = 448,
}

public static class PreviewSizeExtensions
{
    public const double PreviewAspectRatio = 16.0 / 9.0;

    public static PreviewSize Default => PreviewSize.Large320;

    public static int LogicalPixels(this PreviewSize size) => (int)size;

    /// <summary>Preview well height at 16:9 for the current width.</summary>
    public static int LogicalHeight(this PreviewSize size) =>
        (int)Math.Round(size.LogicalPixels() / PreviewAspectRatio);

    /// <summary>Operator-facing size labels: Compact, Standard, Large, Extra Large.</summary>
    public static string Label(this PreviewSize size) => size switch
    {
        PreviewSize.Compact192 => "Compact",
        PreviewSize.Standard256 => "Standard",
        PreviewSize.Large320 => "Large",
        PreviewSize.ExtraLarge448 => "Extra Large",
        _ => size.ToString(),
    };
}
