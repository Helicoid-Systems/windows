using System.Diagnostics;
using Helicoid.Domain.Client;

namespace Helicoid.WindowsPlatform;

/// <summary>
/// A server-redeemed, one-use observation admission. Instances can only be
/// created by <see cref="EndpointFileDeliveryClient"/> after endpoint proof
/// verification and server redemption.
/// </summary>
public sealed class EndpointObservationAdmission : IDisposable
{
    private readonly string _localUserId;
    private readonly long _startedAt;
    private readonly TimeSpan _lifetime;
    private readonly string _channelBindingHex;
    private readonly Func<byte[]> _currentChannelBinding;
    private int _active = 1;

    internal EndpointObservationAdmission(
        Guid challengeId,
        string grantId,
        string computerId,
        string endpointSessionId,
        long expiresAtUnix,
        string localUserId,
        TimeSpan lifetime,
        long startedAt,
        string channelBindingHex,
        Func<byte[]> currentChannelBinding)
    {
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromSeconds(10))
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        }
        ChallengeId = challengeId;
        GrantId = grantId;
        ComputerId = computerId;
        EndpointSessionId = endpointSessionId;
        ExpiresAtUnix = expiresAtUnix;
        _localUserId = localUserId;
        _lifetime = lifetime;
        _startedAt = startedAt;
        _channelBindingHex = channelBindingHex;
        _currentChannelBinding = currentChannelBinding;
    }

    internal Guid ChallengeId { get; }
    public string GrantId { get; }
    public string ComputerId { get; }
    public string EndpointSessionId { get; }
    public long ExpiresAtUnix { get; }

    /// <summary>Monotonic remaining lifetime, rounded down and capped at 10 seconds.</summary>
    internal uint RemainingMilliseconds
    {
        get
        {
            if (!IsOpen)
            {
                return 0;
            }

            double remaining = (_lifetime - Stopwatch.GetElapsedTime(_startedAt)).TotalMilliseconds;
            return remaining <= 0
                ? 0
                : (uint)Math.Min(10_000, Math.Floor(remaining));
        }
    }

    /// <summary>
/// Check the monotonic grant deadline, current unlocked physical-console
/// identity, and still-current native WebRTC channel binding. A failed check
/// permanently closes this lease.
    /// </summary>
    public bool IsCurrent
    {
        get
        {
            if (!IsOpen ||
                !EndpointFileDeliveryClient.IsObservationLeaseCurrent(_localUserId) ||
                !CurrentChannelBindingMatches())
            {
                Dispose();
                return false;
            }

            return IsOpen;
        }
    }

    private bool CurrentChannelBindingMatches()
    {
        byte[] binding = Array.Empty<byte>();
        try
        {
            binding = _currentChannelBinding();
            return ObservationAdmissionGrantVerifier.CanonicalChannelBindingHex(binding) is { } current &&
                   string.Equals(current, _channelBindingHex, StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(binding);
        }
    }

    internal bool IsOpen
    {
        get
        {
            if (Volatile.Read(ref _active) == 0)
            {
                return false;
            }

            if (Stopwatch.GetElapsedTime(_startedAt) < _lifetime)
            {
                return true;
            }

            Dispose();
            return false;
        }
    }

    public void Dispose() => Interlocked.Exchange(ref _active, 0);
}
