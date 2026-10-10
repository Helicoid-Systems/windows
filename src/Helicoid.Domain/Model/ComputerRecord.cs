namespace Helicoid.Domain.Model;

/// <summary>
/// One inventory row for an enrolled computer. <see cref="TrustedUserName"/> is
/// optional secondary information and never replaces the computer name.
/// </summary>
public sealed record ComputerRecord(
    ComputerId Id,
    string Name,
    ComputerStatus Status,
    string? TrustedUserName = null,
    string? GroupId = null)
{
    public ComputerRecord WithStatus(ComputerStatus status) => this with { Status = status };

    public ComputerRecord WithGroup(string? groupId) => this with { GroupId = groupId };
}
