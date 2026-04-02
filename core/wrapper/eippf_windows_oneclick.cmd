@echo off
setlocal ENABLEEXTENSIONS

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%\..\..") do set "REPO_ROOT=%%~fI"

set "PROXY=%REPO_ROOT%\core\wrapper\weaver_proxy.py"
if defined EIPPF_IR_WEAVER_BIN (
  set "IR_WEAVER=%EIPPF_IR_WEAVER_BIN%"
) else (
  set "IR_WEAVER=%REPO_ROOT%\build\ip_weaver_ir\ip_weaver_ir.exe"
)
if defined EIPPF_VM_RUNTIME_LIB (
  set "VM_RUNTIME=%EIPPF_VM_RUNTIME_LIB%"
) else (
  set "VM_RUNTIME=%REPO_ROOT%\build\runtime\eippf_vm_rt.lib"
)

if not exist "%PROXY%" (
  echo [EIPPF] Missing proxy script: %PROXY%
  exit /b 2
)
if not exist "%IR_WEAVER%" (
  echo [EIPPF] Missing IR weaver: %IR_WEAVER%
  echo [EIPPF] Set EIPPF_IR_WEAVER_BIN or build target ip_weaver_ir first.
  exit /b 2
)
if not exist "%VM_RUNTIME%" (
  echo [EIPPF] Missing VM runtime library: %VM_RUNTIME%
  echo [EIPPF] Set EIPPF_VM_RUNTIME_LIB or build target eippf_vm_rt first.
  exit /b 2
)

if "%~1"=="" goto :usage
set "MODE=%~1"
shift /1

if /I "%MODE%"=="cmake-config" goto :cmake_config
if /I "%MODE%"=="cmake-build" goto :cmake_build
if /I "%MODE%"=="clang" goto :clang_mode
if /I "%MODE%"=="ndk-build" goto :ndk_mode
if /I "%MODE%"=="msbuild" goto :msbuild_mode
if /I "%MODE%"=="vcxproj-attach" goto :vcxproj_attach_mode
if /I "%MODE%"=="help" goto :usage

echo [EIPPF] Unknown mode: %MODE%
goto :usage

:cmake_config
if "%~1"=="" (
  echo [EIPPF] cmake-config requires: ^<source_dir^> ^<build_dir^> [extra cmake args...]
  exit /b 2
)
set "SRC_DIR=%~1"
shift /1
if "%~1"=="" (
  echo [EIPPF] cmake-config requires: ^<source_dir^> ^<build_dir^> [extra cmake args...]
  exit /b 2
)
set "BUILD_DIR=%~1"
shift /1

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

call :to_cmake_path "%PROXY%" PROXY_CMAKE
call :to_cmake_path "%IR_WEAVER%" IR_WEAVER_CMAKE
call :to_cmake_path "%VM_RUNTIME%" VM_RUNTIME_CMAKE

set "CACHE_FILE=%BUILD_DIR%\eippf_launcher_cache.cmake"
(
  echo set(CMAKE_C_COMPILER_LAUNCHER "py;-3;%PROXY_CMAKE%;--ir-weaver-bin;%IR_WEAVER_CMAKE%;--vm-runtime-lib;%VM_RUNTIME_CMAKE%" CACHE STRING "" FORCE^)
  echo set(CMAKE_CXX_COMPILER_LAUNCHER "py;-3;%PROXY_CMAKE%;--ir-weaver-bin;%IR_WEAVER_CMAKE%;--vm-runtime-lib;%VM_RUNTIME_CMAKE%" CACHE STRING "" FORCE^)
  echo set(CMAKE_C_LINKER_LAUNCHER "py;-3;%PROXY_CMAKE%;--ir-weaver-bin;%IR_WEAVER_CMAKE%;--vm-runtime-lib;%VM_RUNTIME_CMAKE%" CACHE STRING "" FORCE^)
  echo set(CMAKE_CXX_LINKER_LAUNCHER "py;-3;%PROXY_CMAKE%;--ir-weaver-bin;%IR_WEAVER_CMAKE%;--vm-runtime-lib;%VM_RUNTIME_CMAKE%" CACHE STRING "" FORCE^)
) > "%CACHE_FILE%"

cmake -S "%SRC_DIR%" -B "%BUILD_DIR%" -G Ninja -C "%CACHE_FILE%" %*
exit /b %ERRORLEVEL%

:cmake_build
if "%~1"=="" (
  echo [EIPPF] cmake-build requires: ^<build_dir^> [extra build args...]
  exit /b 2
)
set "BUILD_DIR=%~1"
shift /1
cmake --build "%BUILD_DIR%" %*
exit /b %ERRORLEVEL%

:clang_mode
if "%~1"=="" (
  echo [EIPPF] clang mode requires: ^<real_compiler^> [compiler args...]
  echo [EIPPF] Example: eippf_windows_oneclick.cmd clang clang++ -O2 app.cpp -o app.exe
  exit /b 2
)
set "REAL_COMPILER=%~1"
shift /1
py -3 "%PROXY%" --ir-weaver-bin "%IR_WEAVER%" --vm-runtime-lib "%VM_RUNTIME%" "%REAL_COMPILER%" %*
exit /b %ERRORLEVEL%

:ndk_mode
set "NDK_BUILD_EXE=ndk-build.cmd"
if not "%~1"=="" (
  set "NDK_BUILD_EXE=%~1"
  shift /1
)
set "CCACHE_WRAPPER=%TEMP%\eippf_ndk_weaver_ccache.cmd"
(
  echo @echo off
  echo py -3 "%PROXY%" --ir-weaver-bin "%IR_WEAVER%" --vm-runtime-lib "%VM_RUNTIME%" %%%%*
  echo exit /b %%%%ERRORLEVEL%%%%
) > "%CCACHE_WRAPPER%"

"%NDK_BUILD_EXE%" NDK_CCACHE="%CCACHE_WRAPPER%" %*
exit /b %ERRORLEVEL%

:msbuild_mode
if "%~1"=="" (
  echo [EIPPF] msbuild mode requires: ^<solution_or_vcxproj^> [extra msbuild args...]
  exit /b 2
)
set "MSBUILD_TARGET=%~1"
shift /1
set "WRAPPER_DIR=%REPO_ROOT%\core\wrapper\"
set "EIPPF_IR_WEAVER_BIN=%IR_WEAVER%"
set "EIPPF_VM_RUNTIME_LIB=%VM_RUNTIME%"
msbuild "%MSBUILD_TARGET%" /m "/p:CLToolPath=%WRAPPER_DIR%" "/p:CLToolExe=eippf_cl_wrapper.cmd" "/p:LinkToolPath=%WRAPPER_DIR%" "/p:LinkToolExe=eippf_link_wrapper.cmd" %*
exit /b %ERRORLEVEL%

:vcxproj_attach_mode
set "ATTACH_ROOT=."
if not "%~1"=="" (
  set "ATTACH_ROOT=%~1"
  shift /1
)
set "ATTACH_CMD=%REPO_ROOT%\core\wrapper\eippf_vcxproj_batch_attach.cmd"
if not exist "%ATTACH_CMD%" (
  echo [EIPPF] Missing attach command: %ATTACH_CMD%
  exit /b 2
)
"%ATTACH_CMD%" "%ATTACH_ROOT%" %*
exit /b %ERRORLEVEL%

:to_cmake_path
set "TMP_PATH=%~1"
set "TMP_PATH=%TMP_PATH:\=/%"
set "%~2=%TMP_PATH%"
exit /b 0

:usage
echo.
echo EIPPF Windows One-Click Wrapper
echo Usage:
echo   %~nx0 cmake-config ^<source_dir^> ^<build_dir^> [extra cmake args...]
echo   %~nx0 cmake-build  ^<build_dir^> [extra build args...]
echo   %~nx0 clang        ^<real_compiler^> [compiler args...]
echo   %~nx0 ndk-build    [ndk-build.cmd path] [ndk-build args...]
echo   %~nx0 msbuild      ^<solution_or_vcxproj^> [extra msbuild args...]
echo   %~nx0 vcxproj-attach [root_dir] [-DryRun]
echo.
echo Env overrides:
echo   EIPPF_IR_WEAVER_BIN
echo   EIPPF_VM_RUNTIME_LIB
exit /b 1
