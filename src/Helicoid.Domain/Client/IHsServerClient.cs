using Helicoid.Domain.Model;

namespace Helicoid.Domain.Client;

/// <summary>
/// Narrow client surface for coordination-server calls. Concrete HTTP mapping
/// follows the copied contract in contracts/http-v1.md (server HTTP v1).
/// This interface invents no auth grants.
/// </summary>
public interface IHsServerClient
{
    /// <summary>True when a bearer session is held in memory.</summary>
    bool HasSession { get; }

    Task<HealthResponse> GetHealthAsync(CancellationToken cancellationToken);

    Task<LoginResponse> LoginAsync(
        string username,
        string password,
        string? managerPublicIdentity,
        CancellationToken cancellationToken);

    Task<SessionResponse> GetSessionAsync(CancellationToken cancellationToken);

    Task LogoutAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<Model.ComputerRecord>> GetInventoryAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<Model.ComputerId>> GetAuthorizedComputerIdsAsync(CancellationToken cancellationToken);

    /// <summary>Drop any in-memory session. Never persists tokens.</summary>
    void ClearSession();
}

/// <summary>
/// Default client while trusted production identity is pending. Fails closed
/// with a named reason and performs no network I/O.
/// </summary>
public sealed class ClosedProductionClient : IHsServerClient
{
    public const string ClosedReason =
        "Production server access is not enabled in this build. Trusted identity and authorization are pending.";

    public bool HasSession => false;

    public Task<HealthResponse> GetHealthAsync(CancellationToken cancellationToken) =>
        throw new ServerClientException(ServerClientFailure.NotAvailableInThisBuild, ClosedReason);

    public Task<LoginResponse> LoginAsync(
        string username,
        string password,
        string? managerPublicIdentity,
        CancellationToken cancellationToken) =>
        throw new ServerClientException(ServerClientFailure.NotAvailableInThisBuild, ClosedReason);

    public Task<SessionResponse> GetSessionAsync(CancellationToken cancellationToken) =>
        throw new ServerClientException(ServerClientFailure.NotAvailableInThisBuild, ClosedReason);

    public Task LogoutAsync(CancellationToken cancellationToken)
    {
        ClearSession();
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<Model.ComputerRecord>> GetInventoryAsync(CancellationToken cancellationToken) =>
        throw new ServerClientException(ServerClientFailure.NotAvailableInThisBuild, ClosedReason);

    public Task<IReadOnlyList<Model.ComputerId>> GetAuthorizedComputerIdsAsync(CancellationToken cancellationToken) =>
        throw new ServerClientException(ServerClientFailure.NotAvailableInThisBuild, ClosedReason);

    public void ClearSession()
    {
    }
}
