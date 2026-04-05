param(
    [Parameter(Mandatory = $true)][string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptRoot "..\..\..")).Path
$SourceRoot = Join-Path $RepoRoot "core\tests\sample_suite\sources\windows"
$WrapperPath = Join-Path $RepoRoot "core\wrapper\eippf_cc.py"
$CoreRoot = Join-Path $RepoRoot "core"
$SharedIncludeRoot = Join-Path $CoreRoot "include"
$RuntimeIncludeRoot = Join-Path $CoreRoot "runtime\include"
$HelperSource = Join-Path $CoreRoot "runtime\src\string_token_runtime.cpp"
$PinnedLlvmTarballUrl = "https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/clang%2Bllvm-18.1.8-x86_64-pc-windows-msvc.tar.xz"
$PinnedLlvmTarballSha256 = "22c5907db053026cc2a8ff96d21c0f642a90d24d66c23c6d28ee7b1d572b82e8"
$PinnedLlvmRoot = "C:\eippf\llvm18"

function Resolve-RequiredPath {
    param(
        [Parameter(Mandatory = $true)][string]$InputPath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        throw "[FAIL] missing required path for $Label"
    }
    $Trimmed = $InputPath.Trim().Trim('"')
    if (-not (Test-Path -LiteralPath $Trimmed)) {
        throw "[FAIL] missing required path for ${Label}: $Trimmed"
    }
    return (Resolve-Path -LiteralPath $Trimmed).Path
}

function Format-CommandToken {
    param([Parameter(Mandatory = $true)][string]$Token)

    if ($Token -match '[\s"]') {
        return '"' + ($Token.Replace('"', '\"')) + '"'
    }
    return $Token
}

function Format-CommandLine {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $tokens = @($Executable) + $Arguments
    return (($tokens | ForEach-Object { Format-CommandToken -Token $_ }) -join " ")
}

function Write-AsciiTextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.Encoding]::ASCII)
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureLabel
    )

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "[FAIL] $FailureLabel failed with code $LASTEXITCODE"
    }
}

function Invoke-WrappedCompileAndLink {
    param(
        [Parameter(Mandatory = $true)][string[]]$CompileArgs,
        [Parameter(Mandatory = $true)][string]$SidecarPath,
        [Parameter(Mandatory = $true)][string]$FailureLabel
    )

    $wrapperArgs = @()
    if ($script:PythonPrefix.Count -gt 0) {
        $wrapperArgs += $script:PythonPrefix
    }
    $wrapperArgs += @($script:WrapperPath, "--pass-plugin", $script:PassPluginPath, "--compiler", $script:ClangClPath, "--")
    $wrapperArgs += $CompileArgs

    Write-AsciiTextFile -Path $SidecarPath -Content (Format-CommandLine -Executable $script:PythonExe -Arguments $wrapperArgs)
    $env:EIPPF_CLANG_CL = $script:ClangClPath
    Invoke-NativeCommand -Executable $script:PythonExe -Arguments $wrapperArgs -FailureLabel $FailureLabel
}

function Ensure-PinnedLlvm18Toolchain {
    param(
        [Parameter(Mandatory = $true)][string]$PinnedLlvmTarballUrl,
        [Parameter(Mandatory = $true)][string]$PinnedLlvmTarballSha256,
        [Parameter(Mandatory = $true)][string]$PinnedLlvmRoot,
        [Parameter(Mandatory = $true)][string]$PinnedLlvmArchive,
        [Parameter(Mandatory = $true)][string]$PinnedLlvmStage
    )

    $ResolvedRoot = [System.IO.Path]::GetFullPath($PinnedLlvmRoot.Trim().Trim('"'))
    $ClangClPath = Join-Path $ResolvedRoot "bin\clang-cl.exe"
    $LlvmDir = Join-Path $ResolvedRoot "lib\cmake\llvm"
    $LlvmConfigPath = Join-Path $LlvmDir "LLVMConfig.cmake"
    $PassPluginHeaderPath = Join-Path $ResolvedRoot "include\llvm\Passes\PassPlugin.h"

    if (Test-Path -LiteralPath $PinnedLlvmArchive -PathType Leaf) {
        $ExistingSha256 = (Get-FileHash -LiteralPath $PinnedLlvmArchive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($ExistingSha256 -ne $PinnedLlvmTarballSha256.ToLowerInvariant()) {
            throw "[FAIL] pinned LLVM tarball SHA256 mismatch"
        }
    } else {
        $ArchiveParent = Split-Path -Parent $PinnedLlvmArchive
        if (-not [string]::IsNullOrWhiteSpace($ArchiveParent)) {
            New-Item -ItemType Directory -Path $ArchiveParent -Force | Out-Null
        }
        Invoke-WebRequest -Uri $PinnedLlvmTarballUrl -OutFile $PinnedLlvmArchive
        $DownloadedSha256 = (Get-FileHash -LiteralPath $PinnedLlvmArchive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($DownloadedSha256 -ne $PinnedLlvmTarballSha256.ToLowerInvariant()) {
            throw "[FAIL] pinned LLVM tarball SHA256 mismatch"
        }
    }

    $TarExe = Get-Command "tar.exe" -ErrorAction SilentlyContinue
    if ($null -eq $TarExe) {
        throw "[FAIL] tar.exe is required for pinned LLVM extraction"
    }

    if (Test-Path -LiteralPath $PinnedLlvmStage) {
        Remove-Item -LiteralPath $PinnedLlvmStage -Recurse -Force
    }
    if (Test-Path -LiteralPath $ResolvedRoot) {
        Remove-Item -LiteralPath $ResolvedRoot -Recurse -Force
    }

    New-Item -ItemType Directory -Path $PinnedLlvmStage -Force | Out-Null

    & $TarExe.Source -xf $PinnedLlvmArchive -C $PinnedLlvmStage
    if ($LASTEXITCODE -ne 0) {
        throw "[FAIL] pinned LLVM extraction failed with code $LASTEXITCODE"
    }

    $ExtractedRoots = @(Get-ChildItem -LiteralPath $PinnedLlvmStage -Directory -Force | Where-Object { $_.Name -like "clang+llvm-*" })
    if ($ExtractedRoots.Count -ne 1) {
        throw "[FAIL] pinned LLVM extraction must yield exactly one clang+llvm-* root"
    }

    New-Item -ItemType Directory -Path $ResolvedRoot -Force | Out-Null
    $ExtractedRoot = $ExtractedRoots[0].FullName
    Get-ChildItem -LiteralPath $ExtractedRoot -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $ResolvedRoot -Recurse -Force
    }

    if (-not (Test-Path -LiteralPath $ClangClPath -PathType Leaf)) {
        throw "[FAIL] pinned clang-cl.exe missing after extraction: $ClangClPath"
    }
    if (-not (Test-Path -LiteralPath $LlvmConfigPath -PathType Leaf)) {
        throw "[FAIL] pinned LLVMConfig.cmake missing after extraction: $LlvmConfigPath"
    }
    if (-not (Test-Path -LiteralPath $PassPluginHeaderPath -PathType Leaf)) {
        throw "[FAIL] pinned PassPlugin.h missing after extraction: $PassPluginHeaderPath"
    }

    return [pscustomobject]@{
        Root = $ResolvedRoot
        LlvmDir = $LlvmDir
        ClangClPath = $ClangClPath
    }
}

if (-not (Test-Path -LiteralPath $WrapperPath)) {
    throw "[FAIL] wrapper script is missing: $WrapperPath"
}

$RunnerTempRaw = $env:RUNNER_TEMP
if ([string]::IsNullOrWhiteSpace($RunnerTempRaw)) {
    throw "[FAIL] RUNNER_TEMP is required"
}
$RunnerTemp = [System.IO.Path]::GetFullPath($RunnerTempRaw.Trim().Trim('"'))
$PinnedLlvmArchive = Join-Path $RunnerTemp "clang+llvm-18.1.8-x86_64-pc-windows-msvc.tar.xz"
$PinnedLlvmStage = Join-Path $RunnerTemp "llvm18_unpack"

$RawPinnedLlvmSource = $env:EIPPF_WINDOWS_LLVM_SOURCE
if ([string]::IsNullOrWhiteSpace($RawPinnedLlvmSource)) {
    throw "[FAIL] EIPPF_WINDOWS_LLVM_SOURCE is required"
}
$LLVMSource = $RawPinnedLlvmSource.Trim()
if ($LLVMSource -ne "pinned_llvm18_tarball") {
    throw "[FAIL] unsupported EIPPF_WINDOWS_LLVM_SOURCE: $LLVMSource"
}

$PinnedLlvm = Ensure-PinnedLlvm18Toolchain `
    -PinnedLlvmTarballUrl $PinnedLlvmTarballUrl `
    -PinnedLlvmTarballSha256 $PinnedLlvmTarballSha256 `
    -PinnedLlvmRoot $PinnedLlvmRoot `
    -PinnedLlvmArchive $PinnedLlvmArchive `
    -PinnedLlvmStage $PinnedLlvmStage
$AllowedLlvmRoot = $PinnedLlvm.Root
$LLVMDir = $PinnedLlvm.LlvmDir
$ClangClPath = $PinnedLlvm.ClangClPath

$env:EIPPF_ALLOWED_LLVM_ROOT = $AllowedLlvmRoot
$env:LLVM_DIR = $LLVMDir

$SharedIncludeRoot = Resolve-RequiredPath -InputPath $SharedIncludeRoot -Label "core/include"
$RuntimeIncludeRoot = Resolve-RequiredPath -InputPath $RuntimeIncludeRoot -Label "core/runtime/include"
$HelperSource = Resolve-RequiredPath -InputPath $HelperSource -Label "string_token_runtime.cpp"

$HelperIncludeArgs = @("/I$SharedIncludeRoot", "/I$RuntimeIncludeRoot")
if ($HelperIncludeArgs.Count -ne 2 -or ($HelperIncludeArgs | Select-Object -Unique).Count -ne 2) {
    throw "[FAIL] helper include roots must be exactly core/include and core/runtime/include"
}

$Python = Get-Command "python" -ErrorAction SilentlyContinue
$PythonExe = ""
$PythonPrefix = @()
if ($null -ne $Python) {
    $PythonExe = Resolve-RequiredPath -InputPath $Python.Source -Label "python"
} else {
    $PyLauncher = Get-Command "py" -ErrorAction SilentlyContinue
    if ($null -eq $PyLauncher) {
        throw "[FAIL] python interpreter is required"
    }
    $PythonExe = Resolve-RequiredPath -InputPath $PyLauncher.Source -Label "py launcher"
    $PythonPrefix = @("-3")
}

$CMake = Get-Command "cmake" -ErrorAction SilentlyContinue
if ($null -eq $CMake) {
    throw "[FAIL] cmake is required"
}
$CMakePath = Resolve-RequiredPath -InputPath $CMake.Source -Label "cmake"

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$OutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
$WindowsExeDir = Join-Path $OutputRoot "windows_exe"
$WindowsDllDir = Join-Path $OutputRoot "windows_dll"
$WindowsSysDir = Join-Path $OutputRoot "windows_sys"
$PassPluginDir = Join-Path $OutputRoot "pass_plugins"
$RuntimeLibDir = Join-Path $OutputRoot "runtime_libs"
$PassBuildDir = Join-Path $OutputRoot "_pass_plugin_build_windows"
$ReportDir = Join-Path $OutputRoot "toolchain_reports"
$CommandsDir = Join-Path $ReportDir "commands"

New-Item -ItemType Directory -Force -Path $WindowsExeDir | Out-Null
New-Item -ItemType Directory -Force -Path $WindowsDllDir | Out-Null
New-Item -ItemType Directory -Force -Path $WindowsSysDir | Out-Null
New-Item -ItemType Directory -Force -Path $PassPluginDir | Out-Null
New-Item -ItemType Directory -Force -Path $RuntimeLibDir | Out-Null
New-Item -ItemType Directory -Force -Path $PassBuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $CommandsDir | Out-Null

$PassPluginPath = Join-Path $PassPluginDir "eippf_protection_suite_pass.dll"
$HelperUserObj = Join-Path $RuntimeLibDir "string_token_runtime.windows.user.obj"
$HelperKernelObj = Join-Path $RuntimeLibDir "string_token_runtime.windows.sys.obj"

$ExeSource = Resolve-RequiredPath -InputPath (Join-Path $SourceRoot "windows_exe_main.c") -Label "windows_exe_main.c"
$DllSource = Resolve-RequiredPath -InputPath (Join-Path $SourceRoot "windows_dll.c") -Label "windows_dll.c"
$SysSource = Resolve-RequiredPath -InputPath (Join-Path $SourceRoot "windows_sys_driver.c") -Label "windows_sys_driver.c"

$ExeOut = Join-Path $WindowsExeDir "sample_windows.exe"
$DllOut = Join-Path $WindowsDllDir "sample_windows.dll"
$SysOut = Join-Path $WindowsSysDir "sample_windows.sys"

$ReportPath = Join-Path $ReportDir "windows.txt"
$PluginBuildSidecar = Join-Path $CommandsDir "windows.plugin_build.txt"
$HelperUserSidecar = Join-Path $CommandsDir "windows.helper_user_compile.txt"
$HelperKernelSidecar = Join-Path $CommandsDir "windows.helper_kernel_compile.txt"
$ExeLinkSidecar = Join-Path $CommandsDir "windows.exe_link.txt"
$DllLinkSidecar = Join-Path $CommandsDir "windows.dll_link.txt"
$SysLinkSidecar = Join-Path $CommandsDir "windows.sys_link.txt"

$Ninja = Get-Command "ninja" -ErrorAction SilentlyContinue
$ConfigureArgs = @(
    "-S", $CoreRoot,
    "-B", $PassBuildDir,
    "-DLLVM_DIR=$LLVMDir",
    "-DCMAKE_C_COMPILER=$ClangClPath",
    "-DCMAKE_CXX_COMPILER=$ClangClPath",
    "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$PassPluginDir",
    "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE=$PassPluginDir",
    "-DEIPPF_EXPECTED_PLUGIN_PATH=$PassPluginPath",
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
$PluginBuildArgs = @("--build", $PassBuildDir, "--target", "eippf_protection_suite_pass", "--config", "Release")
$PluginSidecarContent = (Format-CommandLine -Executable $CMakePath -Arguments $ConfigureArgs) + "`n" + (Format-CommandLine -Executable $CMakePath -Arguments $PluginBuildArgs)
Write-AsciiTextFile -Path $PluginBuildSidecar -Content $PluginSidecarContent
Invoke-NativeCommand -Executable $CMakePath -Arguments $ConfigureArgs -FailureLabel "cmake configure for pass plugin"
Invoke-NativeCommand -Executable $CMakePath -Arguments $PluginBuildArgs -FailureLabel "cmake build for pass plugin"
if (-not (Test-Path -LiteralPath $PassPluginPath)) {
    throw "[FAIL] pass plugin build output missing: $PassPluginPath"
}

$HelperUserArgs = @(
    "/nologo",
    "/c",
    "/O2",
    "/W4",
    "/GR-",
    "/EHs-c-",
    "/Fo:$HelperUserObj",
    $HelperSource
) + $HelperIncludeArgs
$HelperKernelArgs = @(
    "/nologo",
    "/c",
    "/O2",
    "/W4",
    "/GS-",
    "/GR-",
    "/EHs-c-",
    "/Zl",
    "/Fo:$HelperKernelObj",
    $HelperSource
) + $HelperIncludeArgs

Write-AsciiTextFile -Path $HelperUserSidecar -Content (Format-CommandLine -Executable $ClangClPath -Arguments $HelperUserArgs)
Write-AsciiTextFile -Path $HelperKernelSidecar -Content (Format-CommandLine -Executable $ClangClPath -Arguments $HelperKernelArgs)
Invoke-NativeCommand -Executable $ClangClPath -Arguments $HelperUserArgs -FailureLabel "helper user compile"
Invoke-NativeCommand -Executable $ClangClPath -Arguments $HelperKernelArgs -FailureLabel "helper kernel compile"

if (-not (Test-Path -LiteralPath $HelperUserObj)) {
    throw "[FAIL] helper user object missing: $HelperUserObj"
}
if (-not (Test-Path -LiteralPath $HelperKernelObj)) {
    throw "[FAIL] helper kernel object missing: $HelperKernelObj"
}

Invoke-WrappedCompileAndLink -CompileArgs @(
    "/nologo",
    "/O2",
    "/W4",
    "/GS-",
    $ExeSource,
    "/link",
    "/OUT:$ExeOut",
    $HelperUserObj
) -SidecarPath $ExeLinkSidecar -FailureLabel "windows exe link"
Invoke-WrappedCompileAndLink -CompileArgs @(
    "/nologo",
    "/LD",
    "/O2",
    "/W4",
    "/GS-",
    $DllSource,
    "/link",
    "/OUT:$DllOut",
    $HelperUserObj
) -SidecarPath $DllLinkSidecar -FailureLabel "windows dll link"
Invoke-WrappedCompileAndLink -CompileArgs @(
    "/nologo",
    "/O2",
    "/W4",
    "/GS-",
    "/GR-",
    "/EHs-c-",
    "/Zl",
    $SysSource,
    "/link",
    "/OUT:$SysOut",
    "/NOLOGO",
    "/MACHINE:X64",
    "/DRIVER",
    "/SUBSYSTEM:NATIVE",
    "/NODEFAULTLIB",
    "/ENTRY:DriverEntry",
    $HelperKernelObj
) -SidecarPath $SysLinkSidecar -FailureLabel "windows sys link"

if (-not (Test-Path -LiteralPath $ExeOut)) {
    throw "[FAIL] windows exe output missing: $ExeOut"
}
if (-not (Test-Path -LiteralPath $DllOut)) {
    throw "[FAIL] windows dll output missing: $DllOut"
}
if (-not (Test-Path -LiteralPath $SysOut)) {
    throw "[FAIL] windows sys output missing: $SysOut"
}

$CompilerVersionFirstLine = (& $ClangClPath "--version" | Select-Object -First 1)
if ([string]::IsNullOrWhiteSpace($CompilerVersionFirstLine)) {
    throw "[FAIL] unable to resolve compiler version first line"
}

$ReportLines = @(
    "platform=windows",
    "llvm_source=$LLVMSource",
    "compiler_path=$ClangClPath",
    "compiler_version_first_line=$CompilerVersionFirstLine",
    "llvm_dir=$LLVMDir",
    "plugin_path=$PassPluginPath",
    "helper_user_o=$HelperUserObj",
    "helper_kernel_o=$HelperKernelObj",
    "plugin_build_command=$PluginBuildSidecar",
    "helper_user_compile_command=$HelperUserSidecar",
    "helper_kernel_compile_command=$HelperKernelSidecar",
    "windows_exe_link_inputs=$HelperUserObj",
    "windows_dll_link_inputs=$HelperUserObj",
    "windows_sys_link_inputs=$HelperKernelObj",
    "windows_exe_link_command=$ExeLinkSidecar",
    "windows_dll_link_command=$DllLinkSidecar",
    "windows_sys_link_command=$SysLinkSidecar"
)
Write-AsciiTextFile -Path $ReportPath -Content ($ReportLines -join "`n")
