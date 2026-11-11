@echo off
if exist "%~dp0JOOMLA-OMNIRECOVERY-AI.exe" (
  start "" "%~dp0JOOMLA-OMNIRECOVERY-AI.exe" --demo
) else if exist "%~dp0release\JOOMLA-OMNIRECOVERY-AI.exe" (
  start "" "%~dp0release\JOOMLA-OMNIRECOVERY-AI.exe" --demo
) else (
  echo Build the release first using Build.ps1 or use Start-Development.ps1 -Demo.
  pause
)
