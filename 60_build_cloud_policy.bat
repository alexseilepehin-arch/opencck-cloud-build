@echo off
setlocal EnableExtensions
call "%~dp0_settings.bat"

where powershell >nul 2>nul || (echo ERROR: powershell.exe not found in PATH.& exit /b 2)

set "KIND=%~1"
if "%KIND%"=="" set "KIND=all"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\build-cloud-policy.ps1" -Kind "%KIND%" -SettingsPath "%~dp0_settings.bat" -OutDir "%~dp0cloud-artifacts" -CacheDir "%~dp0opencck-generated"
exit /b %ERRORLEVEL%
