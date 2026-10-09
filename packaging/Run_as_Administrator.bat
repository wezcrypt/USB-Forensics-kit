@echo off
rem Starts the kit elevated (UAC prompt). Elevation is requested from Windows, never bypassed.
cd /d "%~dp0"
powershell -NoProfile -Command "Start-Process -FilePath '%~dp0WezCryptUFK.exe' -WorkingDirectory '%~dp0' -Verb RunAs"
