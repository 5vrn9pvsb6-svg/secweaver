@echo off
rem Run with cmd /d /c from CMD/SSH; PowerShell already creates a child CMD.
rem EXIT /B rereads the removed batch file. EXIT preserves the child exit code.
(
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall-service.ps1" %*
  exit
)
