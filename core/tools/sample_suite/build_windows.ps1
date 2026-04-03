param(
    [Parameter(Mandatory = $true)][string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptRoot "..\..\..")).Path
$SourceRoot = Join-Path $RepoRoot "core\tests\sample_suite\sources\windows"

$WindowsExeDir = Join-Path $OutputRoot "windows_exe"
$WindowsDllDir = Join-Path $OutputRoot "windows_dll"
$WindowsSysDir = Join-Path $OutputRoot "windows_sys"

New-Item -ItemType Directory -Force -Path $WindowsExeDir | Out-Null
New-Item -ItemType Directory -Force -Path $WindowsDllDir | Out-Null
New-Item -ItemType Directory -Force -Path $WindowsSysDir | Out-Null

$ExeSource = Join-Path $SourceRoot "windows_exe_main.c"
$DllSource = Join-Path $SourceRoot "windows_dll.c"
$SysSource = Join-Path $SourceRoot "windows_sys_driver.c"

$ExeOut = Join-Path $WindowsExeDir "sample_windows.exe"
$DllOut = Join-Path $WindowsDllDir "sample_windows.dll"
$SysObj = Join-Path $WindowsSysDir "sample_windows_sys.obj"
$SysOut = Join-Path $WindowsSysDir "sample_windows.sys"

$HasClangCl = $null -ne (Get-Command "clang-cl" -ErrorAction SilentlyContinue)
$HasLldLink = $null -ne (Get-Command "lld-link" -ErrorAction SilentlyContinue)

if ($HasClangCl) {
    & clang-cl /nologo /O2 /W4 /GS- $ExeSource /link /OUT:$ExeOut
    & clang-cl /nologo /LD /O2 /W4 /GS- $DllSource /link /OUT:$DllOut

    if ($HasLldLink) {
        & clang-cl /nologo /c /O2 /W4 /GS- /GR- /EHs-c- /Zl $SysSource /Fo:$SysObj
        & lld-link /NOLOGO /MACHINE:X64 /DRIVER /SUBSYSTEM:NATIVE /NODEFAULTLIB /ENTRY:DriverEntry /OUT:$SysOut $SysObj
    } else {
        & clang-cl /nologo /c /O2 /W4 /GS- /GR- /EHs-c- /Zl $SysSource /Fo:$SysObj
        & link /NOLOGO /MACHINE:X64 /DRIVER /SUBSYSTEM:NATIVE /NODEFAULTLIB /ENTRY:DriverEntry /OUT:$SysOut $SysObj
    }
} else {
    & cl /nologo /O2 /W4 /GS- $ExeSource /link /OUT:$ExeOut
    & cl /nologo /LD /O2 /W4 /GS- $DllSource /link /OUT:$DllOut
    & cl /nologo /c /O2 /W4 /GS- /GR- /EHsc- /Zl $SysSource /Fo:$SysObj
    & link /NOLOGO /MACHINE:X64 /DRIVER /SUBSYSTEM:NATIVE /NODEFAULTLIB /ENTRY:DriverEntry /OUT:$SysOut $SysObj
}
