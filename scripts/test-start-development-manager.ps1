# Tests start-development-manager.cmd argument forwarding on native Windows.
# Uses a controlled fake console Helicoid.Manager.exe that records sanitized
# argv to a temp file. Also checks the missing-executable controlled exit.
# Never launches the real WinUI GUI.
#
# Run: powershell -File scripts/test-start-development-manager.ps1
# Exits 0 on success, 1 on failure.

$ErrorActionPreference = 'Stop'
$failed = 0
$previousArgvOut = $env:HS_ARGV_OUT

function Assert-True([bool]$cond, [string]$msg) {
    if (-not $cond) {
        Write-Error "FAIL: $msg"
        $script:failed = 1
    } else {
        Write-Host "OK: $msg"
    }
}

# Fixture: tiny console recorder compiled in-process (no external packages).
$recorderSrc = @'
using System;
using System.IO;
class Recorder {
    static void Main(string[] args) {
        var outFile = Environment.GetEnvironmentVariable("HS_ARGV_OUT");
        if (string.IsNullOrEmpty(outFile)) {
            outFile = Path.Combine(Path.GetTempPath(), "hs-argv.txt");
        }
        File.WriteAllLines(outFile, args);
        Environment.Exit(0);
    }
}
'@

function New-FakeManager([string]$destDir) {
    $src = Join-Path $destDir 'Recorder.cs'
    Set-Content -Path $src -Value $recorderSrc -Encoding UTF8
    $exe = Join-Path $destDir 'Helicoid.Manager.exe'
    if (Test-Path $exe) { Remove-Item $exe -Force }
    # Add-Type produces a real .exe named Helicoid.Manager.exe.
    Add-Type -TypeDefinition $recorderSrc -OutputAssembly $exe -OutputType ConsoleApplication -Language CSharp
    return $exe
}

$root = Split-Path -Parent $PSScriptRoot
$cmdPath = Join-Path $root 'scripts\start-development-manager.cmd'
Assert-True (Test-Path $cmdPath) "launcher script exists at $cmdPath"

# --- Case 1: argv forwarding, path with spaces ---
$spaceDir = Join-Path ([System.IO.Path]::GetTempPath()) ("hs launcher test " + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $spaceDir -Force | Out-Null
try {
    Copy-Item $cmdPath (Join-Path $spaceDir 'start-development-manager.cmd')
    New-FakeManager $spaceDir | Out-Null

    $argvOut = Join-Path $spaceDir 'recorded-argv.txt'
    if (Test-Path $argvOut) { Remove-Item $argvOut -Force }
    $env:HS_ARGV_OUT = $argvOut

    # Run from a different cwd to prove %~dp0 works regardless of cwd.
    $otherCwd = [System.IO.Path]::GetTempPath()
    Push-Location $otherCwd
    try {
        $p = Start-Process -FilePath (Join-Path $spaceDir 'start-development-manager.cmd') `
            -PassThru -WindowStyle Hidden -Wait
        Assert-True ($p.ExitCode -eq 0) "launcher exits 0 when sibling exe exists (got $($p.ExitCode))"
    } finally {
        Pop-Location
    }

    # start is async; poll briefly for the recorder output.
    $deadline = (Get-Date).AddSeconds(10)
    while (-not (Test-Path $argvOut) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 200
    }
    Assert-True (Test-Path $argvOut) "fake manager wrote argv file"

    if (Test-Path $argvOut) {
        $argv = Get-Content $argvOut
        $joined = ($argv -join ' ')
        Write-Host "recorded argv: $joined"
        Assert-True ($argv.Count -ge 2) "at least two args forwarded"
        Assert-True ($argv -contains '--development-server=http://127.0.0.1:8787') `
            "forwards exact --development-server=http://127.0.0.1:8787"
        Assert-True ($argv -contains 'dev-manager-key') "forwards identity value dev-manager-key"
        # Identity switch is present immediately before the value.
        $idx = [array]::IndexOf($argv, 'dev-manager-key')
        Assert-True ($idx -gt 0 -and $argv[$idx - 1] -eq '--development-manager-identity') `
            "forwards --development-manager-identity before dev-manager-key"
    }
} finally {
    $env:HS_ARGV_OUT = $previousArgvOut
    Remove-Item $spaceDir -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Case 2: missing sibling executable, controlled exit ---
$missingDir = Join-Path ([System.IO.Path]::GetTempPath()) ("hs launcher missing " + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $missingDir -Force | Out-Null
try {
    Copy-Item $cmdPath (Join-Path $missingDir 'start-development-manager.cmd')
    # No Helicoid.Manager.exe in this folder.
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $env:ComSpec
    $info.Arguments = '/d /c ""' + (Join-Path $missingDir 'start-development-manager.cmd') + '""'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $p = [System.Diagnostics.Process]::Start($info)
    $p.StandardInput.WriteLine('x')
    $p.StandardInput.Close()
    if (-not $p.WaitForExit(10000)) {
        $p.Kill()
        throw 'Missing-executable launcher did not finish within 10 seconds.'
    }
    $diagnostics = $p.StandardOutput.ReadToEnd()
    Assert-True ($p.ExitCode -eq 1) "missing sibling exe exits 1 (got $($p.ExitCode))"
    Assert-True ($diagnostics -match 'Helicoid.Manager.exe not found') 'missing executable diagnostic is retained'
    Assert-True ($diagnostics -match 'Press any key to close') 'missing executable waits for dismissal'
    $p.Dispose()
} finally {
    Remove-Item $missingDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failed -ne 0) {
    Write-Error "launcher tests failed"
    exit 1
}
Write-Host "all launcher tests passed"
exit 0
