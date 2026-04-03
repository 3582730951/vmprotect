param(
    [Parameter(Mandatory = $true)][string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptRoot "..\..\..")).Path
$SourceRoot = Join-Path $RepoRoot "core\tests\sample_suite\sources\windows"
$WrapperPath = Join-Path $RepoRoot "core\wrapper\eippf_cc.py"

if (-not (Test-Path $WrapperPath)) {
    throw "[FAIL] wrapper script is missing: $WrapperPath"
}

$ClangCl = Get-Command "clang-cl" -ErrorAction SilentlyContinue
if ($null -eq $ClangCl) {
    throw "[FAIL] clang-cl is required; refusing fallback to cl.exe"
}
$ClangClPath = $ClangCl.Source

$Python = Get-Command "python" -ErrorAction SilentlyContinue
$PythonExe = ""
$PythonPrefix = @()
if ($null -ne $Python) {
    $PythonExe = $Python.Source
} else {
    $PyLauncher = Get-Command "py" -ErrorAction SilentlyContinue
    if ($null -eq $PyLauncher) {
        throw "[FAIL] python interpreter is required"
    }
    $PythonExe = $PyLauncher.Source
    $PythonPrefix = @("-3")
}

$CMake = Get-Command "cmake" -ErrorAction SilentlyContinue
if ($null -eq $CMake) {
    throw "[FAIL] cmake is required"
}

$WindowsExeDir = Join-Path $OutputRoot "windows_exe"
$WindowsDllDir = Join-Path $OutputRoot "windows_dll"
$WindowsSysDir = Join-Path $OutputRoot "windows_sys"
$PassPluginDir = Join-Path $OutputRoot "pass_plugins"
$PassBuildDir = Join-Path $OutputRoot "_pass_plugin_build_windows"
$PassPluginPath = Join-Path $PassPluginDir "eippf_protection_suite_pass.dll"

New-Item -ItemType Directory -Force -Path $WindowsExeDir | Out-Null
New-Item -ItemType Directory -Force -Path $WindowsDllDir | Out-Null
New-Item -ItemType Directory -Force -Path $WindowsSysDir | Out-Null
New-Item -ItemType Directory -Force -Path $PassPluginDir | Out-Null
New-Item -ItemType Directory -Force -Path $PassBuildDir | Out-Null

$ExeSource = Join-Path $SourceRoot "windows_exe_main.c"
$DllSource = Join-Path $SourceRoot "windows_dll.c"
$SysSource = Join-Path $SourceRoot "windows_sys_driver.c"

$ExeOut = Join-Path $WindowsExeDir "sample_windows.exe"
$DllOut = Join-Path $WindowsDllDir "sample_windows.dll"
$SysObj = Join-Path $WindowsSysDir "sample_windows_sys.obj"
$SysOut = Join-Path $WindowsSysDir "sample_windows.sys"

$LLVMDir = $env:LLVM_DIR
if ([string]::IsNullOrWhiteSpace($LLVMDir)) {
    $ClangBinDir = Split-Path -Parent $ClangClPath
    $CandidateLLVMDir = Join-Path (Split-Path -Parent $ClangBinDir) "lib\cmake\llvm"
    if (Test-Path $CandidateLLVMDir) {
        $LLVMDir = (Resolve-Path $CandidateLLVMDir).Path
    }
}
if ([string]::IsNullOrWhiteSpace($LLVMDir) -or -not (Test-Path $LLVMDir)) {
    throw "[FAIL] LLVM_DIR is required to build eippf_protection_suite_pass"
}

$Ninja = Get-Command "ninja" -ErrorAction SilentlyContinue
$ConfigureArgs = @(
    "-S", (Join-Path $RepoRoot "core"),
    "-B", $PassBuildDir,
    "-DLLVM_DIR=$LLVMDir",
    "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$PassPluginDir",
    "-DEIPPF_BUILD_TESTS=OFF",
    "-DEIPPF_BUILD_POST_LINK_MUTATOR=OFF",
    "-DEIPPF_BUILD_DEX_TOOLCHAIN=OFF",
    "-DEIPPF_BUILD_SCRIPT_GUARD=OFF",
    "-DEIPPF_BUILD_IP_WEAVER=OFF",
    "-DEIPPF_BUILD_IP_WEAVER_IR=OFF",
    "-DEIPPF_BUILD_TOOLING=OFF"
)
if ($null -ne $Ninja) {
    $ConfigureArgs += @("-G", "Ninja")
}
& $CMake.Source @ConfigureArgs
if ($LASTEXITCODE -ne 0) {
    throw "[FAIL] cmake configure for pass plugin failed with code $LASTEXITCODE"
}
& $CMake.Source "--build" $PassBuildDir "--target" "eippf_protection_suite_pass" "--config" "Release"
if ($LASTEXITCODE -ne 0) {
    throw "[FAIL] cmake build for pass plugin failed with code $LASTEXITCODE"
}
if (-not (Test-Path $PassPluginPath)) {
    throw "[FAIL] pass plugin build output missing: $PassPluginPath"
}

function Invoke-WrappedCompile {
    param(
        [Parameter(Mandatory = $true)][string[]]$CompileArgs
    )

    $env:EIPPF_CLANG_CL = $script:ClangClPath
    & $script:PythonExe @script:PythonPrefix $script:WrapperPath "--pass-plugin" $script:PassPluginPath "--" @CompileArgs
    if ($LASTEXITCODE -ne 0) {
        throw "[FAIL] wrapper compile failed with code $LASTEXITCODE"
    }
}

$HasLldLink = $null -ne (Get-Command "lld-link" -ErrorAction SilentlyContinue)

Invoke-WrappedCompile @("/nologo", "/O2", "/W4", "/GS-", $ExeSource, "/link", "/OUT:$ExeOut")
Invoke-WrappedCompile @("/nologo", "/LD", "/O2", "/W4", "/GS-", $DllSource, "/link", "/OUT:$DllOut")
Invoke-WrappedCompile @("/nologo", "/c", "/O2", "/W4", "/GS-", "/GR-", "/EHs-c-", "/Zl", $SysSource, "/Fo:$SysObj")

if ($HasLldLink) {
    & lld-link /NOLOGO /MACHINE:X64 /DRIVER /SUBSYSTEM:NATIVE /NODEFAULTLIB /ENTRY:DriverEntry /OUT:$SysOut $SysObj
    if ($LASTEXITCODE -ne 0) {
        throw "[FAIL] lld-link failed with code $LASTEXITCODE"
    }
} else {
    & link /NOLOGO /MACHINE:X64 /DRIVER /SUBSYSTEM:NATIVE /NODEFAULTLIB /ENTRY:DriverEntry /OUT:$SysOut $SysObj
    if ($LASTEXITCODE -ne 0) {
        throw "[FAIL] link.exe failed with code $LASTEXITCODE"
    }
}
