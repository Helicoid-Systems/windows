using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Helicoid.Domain.Worker;
using Helicoid.WindowsPlatform.Native;

// This file contains Windows-only named pipe IPC code.
// PipeTransmissionMode.Message is only supported on Windows.
#pragma warning disable CA1416

namespace Helicoid.WindowsPlatform;
/// <summary>
/// Authentication result for IPC handshake verification.
/// </summary>
public enum IpcAuthenticationResult
{
    /// <summary>Peer identity fully verified.</summary>
    Authenticated = 0,

    /// <summary>Capability nonce mismatch.</summary>
    InvalidCapability = 1,

    /// <summary>Process ID does not match expected peer.</summary>
    ProcessMismatch = 2,

    /// <summary>WTS session ID does not match expected peer.</summary>
    SessionMismatch = 3,

    /// <summary>Token user SID does not match expected peer.</summary>
    TokenMismatch = 4,

    /// <summary>Pipe connection or read/write failure.</summary>
    TransportFailure = 5,

    /// <summary>Received an oversized or malformed frame.</summary>
    MalformedFrame = 6,

    /// <summary>Handshake timed out or canceled.</summary>
    Timeout = 7,

    /// <summary>Boot, launch, or desktop generation fence did not match.</summary>
    FenceMismatch = 8,

    /// <summary>A mandatory identity field was missing or malformed.</summary>
    MissingIdentity = 9,
}
/// <summary>
/// Outcome of a bounded frame read. Unknown/malformed frames fail closed:
/// callers must treat <see cref="Malformed"/> and <see cref="Disconnected"/>
/// as terminal, never as "keep going".
/// </summary>
public enum IpcReadResult
{
    /// <summary>A well-formed frame was read.</summary>
    Success = 0,

    /// <summary>No frame arrived within the timeout.</summary>
    Timeout = 1,

    /// <summary>The peer disconnected.</summary>
    Disconnected = 2,

    /// <summary>The frame was malformed, oversized, or an unknown type.</summary>
    Malformed = 3,
}
