using System.Security.Cryptography;

namespace Helicoid.Domain.Client;

/// <summary>
/// In-memory pending v2 device-key challenge. Holds the opaque challenge
/// token until completion or clear. Never logs or stringifies secrets.
/// Cleared on success, cancel, expiry, identity change, or dispose.
/// </summary>
public sealed class PendingAuthChallenge : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _challengeToken;
    private bool _cleared;

    internal PendingAuthChallenge(
        string challengeId,
        byte[] challengeToken,
        string deploymentId,
        string operation,
        string managerPublicKeyHex,
        long expiresAtUnix,
        bool mfaRequired)
    {
        ChallengeId = challengeId;
        DeploymentId = deploymentId;
        Operation = operation;
        ManagerPublicKeyHex = managerPublicKeyHex;
        ExpiresAtUnix = expiresAtUnix;
        MfaRequired = mfaRequired;
        _challengeToken = challengeToken;
    }

    public string ChallengeId { get; }

    public string DeploymentId { get; }

    public string Operation { get; }

    public string ManagerPublicKeyHex { get; }

    public long ExpiresAtUnix { get; }

    /// <summary>
    /// True when a TOTP code must be supplied at completion. A missing
    /// mfa_required field on the begin response is treated as required.
    /// </summary>
    public bool MfaRequired { get; }

    public bool IsCleared
    {
        get
        {
            lock (_gate)
            {
                return _cleared;
            }
        }
    }

    public bool IsExpired(long nowUnixSeconds) =>
        nowUnixSeconds >= ExpiresAtUnix;

    /// <summary>
    /// Copy of the opaque challenge token for one completion attempt.
    /// Returns false when the challenge was already cleared.
    /// </summary>
    internal bool TryCopyChallengeToken(out byte[] token)
    {
        lock (_gate)
        {
            if (_cleared || _challengeToken is null)
            {
                token = Array.Empty<byte>();
                return false;
            }

            token = _challengeToken.ToArray();
            return true;
        }
    }

    /// <summary>
    /// UTF-8 challenge token for the completion request. The returned string
    /// is process-memory only; the caller must not log it. The token remains
    /// owned here until <see cref="Clear"/>.
    /// </summary>
    internal bool TryCopyChallengeTokenUtf8(out string token)
    {
        if (!TryCopyChallengeToken(out var bytes))
        {
            token = string.Empty;
            return false;
        }

        try
        {
            token = System.Text.Encoding.UTF8.GetString(bytes);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _cleared = true;
            if (_challengeToken is not null)
            {
                CryptographicOperations.ZeroMemory(_challengeToken);
                _challengeToken = null;
            }
        }
    }

    public void Dispose() => Clear();

    /// <summary>Never expose challenge material through diagnostics.</summary>
    public override string ToString() =>
        IsCleared ? "PendingAuthChallenge(cleared)" : "PendingAuthChallenge";
}
