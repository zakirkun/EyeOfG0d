@echo off
rem Switch the console to UTF-8; otherwise the text in this file is garbled in a GBK terminal.
chcp 65001 >nul 2>&1
rem EyeOfG0d supervisor start script (Windows)
rem
rem Usage:
rem   start.bat                  run in the foreground (Ctrl-C to stop)
rem   start.bat -addr :9000      extra arguments are passed through to eyeofg0d as-is
rem
rem It does exactly one thing: run eyeofg0d.exe and, once the process exits, decide by exit code whether to relaunch it.
rem
rem   0      user stopped normally -> exit the loop
rem   other  crash             -> rerun after backoff (1->2->4... up to 60 seconds)

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "BIN=eyeofg0d.exe"
if not exist "%BIN%" (
	echo [eyeofg0d] executable %BIN% not found 1>&2
	exit /b 1
)

set "MAX_DELAY=60"
set /a delay=1

:loop
"%BIN%" %*
set "code=!ERRORLEVEL!"

if "!code!"=="0" (
	echo [eyeofg0d] exited normally
	exit /b 0
)

echo [eyeofg0d] abnormal exit ^(code=!code!^), restarting in !delay!s 1>&2
rem timeout fails in a redirected console, so fall back to ping (delaying N seconds needs N+1 pings).
set /a pings=!delay!+1
ping -n !pings! 127.0.0.1 >nul 2>&1
set /a delay=!delay!*2
if !delay! gtr %MAX_DELAY% set /a delay=%MAX_DELAY%
goto loop
