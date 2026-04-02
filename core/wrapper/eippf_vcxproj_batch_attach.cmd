@echo off
setlocal ENABLEEXTENSIONS

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%eippf_vcxproj_batch_attach.ps1"

if not exist "%PS1%" (
  echo [EIPPF] Missing script: %PS1%
  exit /b 2
)

set "ROOT=%~1"
if "%ROOT%"=="" set "ROOT=."
shift /1

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Root "%ROOT%" %*
exit /b %ERRORLEVEL%
