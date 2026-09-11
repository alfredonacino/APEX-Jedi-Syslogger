@echo off
rem Windows shim for the uniform launcher: cmd.exe does not read a shebang,
rem so `apexmod run ...` needs this to mean the same thing it does elsewhere.
setlocal
set "HERE=%~dp0"
where py >nul 2>nul && (py -3 "%HERE%apexmod" %* & exit /b %ERRORLEVEL%)
python "%HERE%apexmod" %*
