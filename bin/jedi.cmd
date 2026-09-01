@echo off
rem APEX JediSyslogger — Windows launcher.
rem UTF-8 first: the dashboard draws box characters, and the default OEM code
rem page renders them as mojibake. Use --ascii if this still looks wrong.
chcp 65001 >nul 2>&1
setlocal
set "APP=%~dp0.."
if not exist "%APP%\jedi-cli.js" set "APP=%~dp0"
if defined JEDI_HOME set "APP=%JEDI_HOME%"
if not exist "%APP%\jedi-cli.js" (
  echo jedi: cannot find jedi-cli.js - set JEDI_HOME to the install directory 1>&2
  exit /b 1
)
where node >nul 2>&1
if errorlevel 1 (
  echo jedi: Node.js 18 or newer is required and 'node' is not on PATH 1>&2
  echo        install it from https://nodejs.org 1>&2
  exit /b 1
)
node "%APP%\jedi-cli.js" %*
