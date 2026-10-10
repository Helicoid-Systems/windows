using Helicoid.Domain.PhysicalConsole;
using Helicoid.WindowsPlatform;

namespace Helicoid.ConsoleProbe;

/// <summary>
/// Delegates to the reusable <see cref="Helicoid.WindowsPlatform.PhysicalConsoleObserver"/>
/// in the shared Windows platform module. No duplicate native code.
/// </summary>
internal static class PhysicalConsoleObserver
{
    /// <summary>
    /// Observe the physical console via the shared platform module.
    /// </summary>
    public static PhysicalConsoleEligibility Observe()
        => WindowsPlatform.PhysicalConsoleObserver.Observe();
}