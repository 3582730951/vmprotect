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
if defined EIPPF_REAL_CL (
  set "REAL_CL=%EIPPF_REAL_CL%"
) else (
  set "REAL_CL=cl.exe"
)

if not exist "%PROXY%" (
  echo [EIPPF] Missing proxy script: %PROXY%
  exit /b 2
)

py -3 "%PROXY%" --ir-weaver-bin "%IR_WEAVER%" --vm-runtime-lib "%VM_RUNTIME%" "%REAL_CL%" %*
exit /b %ERRORLEVEL%
