using System.ComponentModel;
using System.Runtime.InteropServices;
using Helicoid.WindowsPlatform.Native;

namespace Helicoid.WindowsPlatform;

/// <summary>
/// Manages a Windows Job Object with KILL_ON_JOB_CLOSE semantics. When the
/// owning process exits (or this object is disposed), the OS terminates all
/// processes assigned to the job. Used by the supervisor to guarantee child
/// worker cleanup even on abnormal parent termination.
/// </summary>
public sealed class KillOnCloseJob : IDisposable
{
    private readonly SafeJobHandle _handle;
    private bool _disposed;

    /// <summary>
    /// Create a new job object with KILL_ON_JOB_CLOSE. Throws on failure.
    /// </summary>
    public KillOnCloseJob()
    {
        _handle = JobObjectNative.CreateJobObjectW(IntPtr.Zero, lpName: null);
        if (_handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                LimitFlags = JobObjectNative.JobObjectLimitKillOnJobClose,
            },
        };

        if (!JobObjectNative.SetInformationJobObject(
            _handle,
            JobObjectNative.JobObjectExtendedLimitInformation,
            ref limits,
            (uint)Marshal.SizeOf(limits)))
        {
            int error = Marshal.GetLastWin32Error();
            _handle.Dispose();
            throw new Win32Exception(error);
        }
    }

    /// <summary>
    /// Get the raw job handle for use with PROC_THREAD_ATTRIBUTE_JOB_LIST.
    /// Used by the supervisor to assign the child to the job at creation time.
    /// </summary>
    public IntPtr DangerousGetHandle()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _handle.DangerousGetHandle();
    }

    /// <summary>
    /// Assign a process to this job. The process will be terminated when the
    /// job handle closes (parent exit or dispose). Returns false if the process
    /// is already in a job or the assignment fails.
    /// </summary>
    public bool TryAssignProcess(IntPtr processHandle)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (processHandle == IntPtr.Zero)
        {
            return false;
        }

        return JobObjectNative.AssignProcessToJobObject(_handle, processHandle);
    }

    /// <summary>
    /// Check if a process is assigned to this job.
    /// </summary>
    public bool IsProcessInJob(IntPtr processHandle)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (processHandle == IntPtr.Zero)
        {
            return false;
        }

        if (JobObjectNative.IsProcessInJob(processHandle, _handle, out bool result))
        {
            return result;
        }

        return false;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            _handle.Dispose();
        }
    }
}