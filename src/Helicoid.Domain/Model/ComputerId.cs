namespace Helicoid.Domain.Model;

/// <summary>
/// Stable identity of one enrolled computer. Names and discovery results never
/// substitute for this ID when granting access or freezing action targets.
/// </summary>
public readonly record struct ComputerId(string Value)
{
    public static ComputerId Parse(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Computer ID must be non-empty.", nameof(value));
        }

        return new ComputerId(value.Trim());
    }

    public override string ToString() => Value;
}
