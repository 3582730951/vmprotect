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

function Resolve-LLVMDirCandidate {
    param(
        [Parameter(Mandatory = $false)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$SourceLabel
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        $script:LLVMResolutionAttempts += "${SourceLabel}: empty"
        return $null
    }

    $Normalized = $Candidate.Trim().Trim('"')
    try {
        $Resolved = (Resolve-Path -LiteralPath $Normalized -ErrorAction Stop).Path
    } catch {
        $script:LLVMResolutionAttempts += "${SourceLabel}: '$Normalized' not found"
        return $null
    }

    $LLVMConfigPath = Join-Path $Resolved "LLVMConfig.cmake"
    if (-not (Test-Path -LiteralPath $LLVMConfigPath)) {
        $script:LLVMResolutionAttempts += "${SourceLabel}: '$Resolved' missing LLVMConfig.cmake"
        return $null
    }

    $script:LLVMResolutionAttempts += "${SourceLabel}: '$Resolved' accepted"
    return $Resolved
}

$WindowsExeDir = Join-Path $OutputRoot "windows_exe"
$WindowsDllDir = Join-Path $OutputRoot "windows_dll"
$WindowsSysDir = Join-Path $OutputRoot "windows_sys"
$PassPluginDir = Join-Path $OutputRoot "pass_plugins"
$RuntimeLibDir = Join-Path $OutputRoot "runtime_libs"
$PassBuildDir = Join-Path $OutputRoot "_pass_plugin_build_windows"
$PassPluginPath = Join-Path $PassPluginDir "eippf_protection_suite_pass.dll"
$RuntimeLibPath = Join-Path $RuntimeLibDir "eippf_string_token_runtime.lib"

New-Item -ItemType Directory -Force -Path $WindowsExeDir | Out-Null
New-Item -ItemType Directory -Force -Path $WindowsDllDir | Out-Null
New-Item -ItemType Directory -Force -Path $WindowsSysDir | Out-Null
New-Item -ItemType Directory -Force -Path $PassPluginDir | Out-Null
New-Item -ItemType Directory -Force -Path $RuntimeLibDir | Out-Null
New-Item -ItemType Directory -Force -Path $PassBuildDir | Out-Null

$ExeSource = Join-Path $SourceRoot "windows_exe_main.c"
$DllSource = Join-Path $SourceRoot "windows_dll.c"
$SysSource = Join-Path $SourceRoot "windows_sys_driver.c"

$ExeOut = Join-Path $WindowsExeDir "sample_windows.exe"
$DllOut = Join-Path $WindowsDllDir "sample_windows.dll"
$SysObj = Join-Path $WindowsSysDir "sample_windows_sys.obj"
$SysOut = Join-Path $WindowsSysDir "sample_windows.sys"

$script:LLVMResolutionAttempts = @()
$LLVMDir = Resolve-LLVMDirCandidate -Candidate $env:LLVM_DIR -SourceLabel "env:LLVM_DIR"

if ([string]::IsNullOrWhiteSpace($LLVMDir)) {
    $LLVMConfig = Get-Command "llvm-config.exe" -ErrorAction SilentlyContinue
    if ($null -eq $LLVMConfig) {
        $LLVMConfig = Get-Command "llvm-config" -ErrorAction SilentlyContinue
    }
    if ($null -ne $LLVMConfig) {
        $LLVMDirCandidate = (& $LLVMConfig.Source --cmakedir 2>$null | Select-Object -First 1)
        if ($LASTEXITCODE -eq 0) {
            $LLVMDir = Resolve-LLVMDirCandidate -Candidate "$LLVMDirCandidate" -SourceLabel "llvm-config --cmakedir"
        } else {
            $script:LLVMResolutionAttempts += "llvm-config --cmakedir: failed with code $LASTEXITCODE"
        }
    } else {
        $script:LLVMResolutionAttempts += "llvm-config --cmakedir: llvm-config not found"
    }
}

if ([string]::IsNullOrWhiteSpace($LLVMDir)) {
    $ClangBinDir = Split-Path -Parent $ClangClPath
    $DerivedLLVMDir = Join-Path (Split-Path -Parent $ClangBinDir) "lib\cmake\llvm"
    $LLVMDir = Resolve-LLVMDirCandidate -Candidate $DerivedLLVMDir -SourceLabel "derived-from-clang-cl"
}

if ([string]::IsNullOrWhiteSpace($LLVMDir)) {
    Write-Host "[FAIL] Unable to resolve a valid LLVM CMake directory."
    Write-Host "[INFO] LLVM resolution attempts:"
    foreach ($Attempt in $script:LLVMResolutionAttempts) {
        Write-Host "[INFO]   $Attempt"
    }
    throw "[FAIL] LLVM_DIR resolution failed"
}

$LLVMConfigPath = Join-Path $LLVMDir "LLVMConfig.cmake"
if (-not (Test-Path -LiteralPath $LLVMConfigPath)) {
    throw "[FAIL] LLVM_DIR does not contain LLVMConfig.cmake: $LLVMDir"
}

$Ninja = Get-Command "ninja" -ErrorAction SilentlyContinue
$ConfigureArgs = @(
    "-S", (Join-Path $RepoRoot "core"),
    "-B", $PassBuildDir,
    "-DLLVM_DIR=$LLVMDir",
    "-DCMAKE_C_COMPILER=$ClangClPath",
    "-DCMAKE_CXX_COMPILER=$ClangClPath",
    "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$PassPluginDir",
    "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE=$PassPluginDir",
    "-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$RuntimeLibDir",
    "-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE=$RuntimeLibDir",
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
& $CMake.Source "--build" $PassBuildDir "--target" "eippf_protection_suite_pass" "eippf_string_token_runtime" "--config" "Release"
if ($LASTEXITCODE -ne 0) {
    throw "[FAIL] cmake build for pass plugin failed with code $LASTEXITCODE"
}
if (-not (Test-Path $PassPluginPath)) {
    throw "[FAIL] pass plugin build output missing: $PassPluginPath"
}
if (-not (Test-Path $RuntimeLibPath)) {
    throw "[FAIL] runtime library output missing: $RuntimeLibPath"
}

Write-Host "[INFO] clang-cl path: $ClangClPath"
Write-Host "[INFO] LLVM_DIR: $LLVMDir"
Write-Host "[INFO] runtime lib path: $RuntimeLibPath"

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

Invoke-WrappedCompile @("/nologo", "/O2", "/W4", "/GS-", $ExeSource, "/link", "/OUT:$ExeOut", $RuntimeLibPath)
Invoke-WrappedCompile @("/nologo", "/LD", "/O2", "/W4", "/GS-", $DllSource, "/link", "/OUT:$DllOut", $RuntimeLibPath)
Invoke-WrappedCompile @("/nologo", "/c", "/O2", "/W4", "/GS-", "/GR-", "/EHs-c-", "/Zl", $SysSource, "/Fo:$SysObj")

if ($HasLldLink) {
    & lld-link /NOLOGO /MACHINE:X64 /DRIVER /SUBSYSTEM:NATIVE /NODEFAULTLIB /ENTRY:DriverEntry /OUT:$SysOut $SysObj $RuntimeLibPath
    if ($LASTEXITCODE -ne 0) {
        throw "[FAIL] lld-link failed with code $LASTEXITCODE"
    }
} else {
    & link /NOLOGO /MACHINE:X64 /DRIVER /SUBSYSTEM:NATIVE /NODEFAULTLIB /ENTRY:DriverEntry /OUT:$SysOut $SysObj $RuntimeLibPath
    if ($LASTEXITCODE -ne 0) {
        throw "[FAIL] link.exe failed with code $LASTEXITCODE"
    }
}
