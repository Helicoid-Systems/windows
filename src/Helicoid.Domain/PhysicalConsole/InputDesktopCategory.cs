namespace Helicoid.Domain.PhysicalConsole;

/// <summary>
/// Coarse classification of the input desktop name observed for the current
/// process. Only <see cref="Default"/> is an ordinary user desktop; every other
/// category denies physical-console eligibility. The raw desktop name is never
/// emitted because it can identify a user or protected surface.
/// </summary>
public enum InputDesktopCategory
{
    /// <summary>Name could not be classified into a known category.</summary>
    Unknown = 0,

    /// <summary>Desktop query failed or returned an empty name.</summary>
    Missing = 1,

    /// <summary>Ordinary interactive user desktop ("Default").</summary>
    Default = 2,

    /// <summary>Logon / Winlogon desktop; not an ordinary user desktop.</summary>
    Winlogon = 3,

    /// <summary>Secure desktop (UAC / secure attention).</summary>
    Secure = 4,

    /// <summary>Screen-saver desktop.</summary>
    ScreenSaver = 5,

    /// <summary>Any other named desktop; treated as unsupported.</summary>
    Other = 6,
}

public static class InputDesktopCategoryClassifier
{
    /// <summary>
    /// Classify a desktop name without retaining the name. Comparison is
    /// ordinal and case-insensitive for the fixed Windows names.
    /// </summary>
    public static InputDesktopCategory Classify(string? desktopName)
    {
        if (string.IsNullOrEmpty(desktopName))
        {
            return InputDesktopCategory.Missing;
        }

        if (string.Equals(desktopName, "Default", StringComparison.OrdinalIgnoreCase))
        {
            return InputDesktopCategory.Default;
        }

        if (string.Equals(desktopName, "Winlogon", StringComparison.OrdinalIgnoreCase))
        {
            return InputDesktopCategory.Winlogon;
        }

        if (string.Equals(desktopName, "Secure", StringComparison.OrdinalIgnoreCase))
        {
            return InputDesktopCategory.Secure;
        }

        if (desktopName.StartsWith("ScreenSaver", StringComparison.OrdinalIgnoreCase))
        {
            return InputDesktopCategory.ScreenSaver;
        }

        return InputDesktopCategory.Other;
    }
}
