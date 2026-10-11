# Verify the numeric WTSINFOEXW decoder contract against the installed Windows SDK.
# No session is queried and no identity strings are read.
$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vs)) { throw 'C++ Windows SDK toolchain unavailable' }
$work = Join-Path $env:RUNNER_TEMP ('helicoid-wts-layout-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
@'
#include <windows.h>
#include <wtsapi32.h>
#include <cstddef>
#include <cstdio>
static_assert(sizeof(WTSINFOEXW) == 232);
static_assert(offsetof(WTSINFOEXW, Level) == 0);
static_assert(offsetof(WTSINFOEXW, Data) == 8);
static_assert(offsetof(WTSINFOEX_LEVEL1_W, SessionId) == 0);
static_assert(offsetof(WTSINFOEX_LEVEL1_W, SessionState) == 4);
static_assert(offsetof(WTSINFOEX_LEVEL1_W, SessionFlags) == 8);
static_assert(WTSSessionInfoEx == 25);
static_assert(WTS_SESSIONSTATE_LOCK == 0);
static_assert(WTS_SESSIONSTATE_UNLOCK == 1);
static_assert(WTS_SESSIONSTATE_UNKNOWN == 0xffffffff);
int main() { std::puts("WTSINFOEXW SDK layout verified: 232 bytes, data offset 8, flags offset 16"); }
'@ | Set-Content -Encoding ascii (Join-Path $work 'layout.cpp')
$setup = Join-Path $vs 'Common7/Tools/VsDevCmd.bat'
$command = "call `"$setup`" -arch=x64 -host_arch=x64 && cd /d `"$work`" && cl /nologo /std:c++17 /EHsc layout.cpp /Fe:layout.exe && layout.exe"
& $env:ComSpec /d /c $command
if ($LASTEXITCODE -ne 0) { throw 'WTS SDK layout verification failed' }
