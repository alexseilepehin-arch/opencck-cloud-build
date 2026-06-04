@echo off
setlocal EnableExtensions
call "%~dp0_settings.bat"

where ssh >nul 2>nul || (echo ERROR: ssh.exe not found in PATH.& exit /b 2)
where scp >nul 2>nul || (echo ERROR: scp.exe not found in PATH.& exit /b 2)
where powershell >nul 2>nul || (echo ERROR: powershell.exe not found in PATH.& exit /b 2)

if "%CLOUD_ARTIFACT_BASE_URL%"=="https://CHANGE-ME.example.invalid/awg-policy" (
    echo ERROR: set CLOUD_ARTIFACT_BASE_URL in _settings.bat before installing cloud policy updater.
    exit /b 2
)

set "LOCAL_RSC=%TEMP%\awg-cloud-policy-installer-%RANDOM%.rsc"
set "REMOTE_RSC=%USB_MOUNT%/awg-cloud-policy-installer.rsc"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$tpl=Get-Content -LiteralPath '%~dp0awg-cloud-policy-installer.rsc' -Raw; " ^
  "$map=@{ " ^
  "'__CLOUD_ARTIFACT_BASE_URL__'='%CLOUD_ARTIFACT_BASE_URL%'; " ^
  "'__CLOUD_FORCE_MANIFEST__'='%CLOUD_FORCE_MANIFEST%'; " ^
  "'__CLOUD_FULL_MANIFEST__'='%CLOUD_FULL_MANIFEST%'; " ^
  "'__CLOUD_POLICY_STATE_FILE__'='%CLOUD_POLICY_STATE_FILE%'; " ^
  "'__CLOUD_WORK_DIR__'='%CLOUD_WORK_DIR%'; " ^
  "'__CLOUD_FORCE_MIN_COUNT__'='%CLOUD_FORCE_MIN_COUNT%'; " ^
  "'__CLOUD_OPENCCK_MIN_COUNT__'='%CLOUD_OPENCCK_MIN_COUNT%'; " ^
  "'__CLOUD_WATCHDOG_STALE_HOURS__'='%CLOUD_WATCHDOG_STALE_HOURS%' }; " ^
  "foreach($k in $map.Keys){$tpl=$tpl.Replace($k,$map[$k])}; " ^
  "[IO.File]::WriteAllText('%LOCAL_RSC%',$tpl,[Text.UTF8Encoding]::new($false))"
if errorlevel 1 exit /b %ERRORLEVEL%

scp -i "%SSH_KEY_PATH%" %SSH_COMMON_OPTS% "%LOCAL_RSC%" "%ROUTER%:%REMOTE_RSC%"
if errorlevel 1 exit /b %ERRORLEVEL%

ssh -i "%SSH_KEY_PATH%" %SSH_COMMON_OPTS% "%ROUTER%" "/import file-name=%REMOTE_RSC%"
set "RC=%ERRORLEVEL%"
del "%LOCAL_RSC%" >nul 2>nul
exit /b %RC%
