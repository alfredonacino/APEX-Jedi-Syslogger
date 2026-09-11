# Launch APEX JediSyslogger on Windows. See run.sh; the flags are identical.
Set-Location -Path $PSScriptRoot
$py = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }
& $py (Join-Path $PSScriptRoot "apexmod") run --port 8099 @args
exit $LASTEXITCODE
