<#
.SYNOPSIS
  Install (or remove) APEX JediSyslogger on Windows 10/11.

.DESCRIPTION
  Copies the app into %LOCALAPPDATA%\Programs\apex-jedisyslogger and puts a
  `jedi` shim on the user's PATH. No administrator rights are needed and
  nothing is written to Program Files, the registry beyond the user PATH
  variable, or the service manager.

  Node.js 18 or newer must already be installed; this checks and stops with a
  link rather than installing a runtime behind your back.

.EXAMPLE
  # from the unpacked archive
  powershell -ExecutionPolicy Bypass -File .\packaging\install.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\packaging\install.ps1 -Uninstall
#>
[CmdletBinding()]
param(
  [switch]$Uninstall,
  [string]$Destination = (Join-Path $env:LOCALAPPDATA 'Programs\apex-jedisyslogger')
)

$ErrorActionPreference = 'Stop'
$AppName = 'APEX JediSyslogger'

function Write-Step($msg) { Write-Host "  $msg" }

# ---- uninstall ------------------------------------------------------------
if ($Uninstall) {
  if (Test-Path $Destination) {
    Remove-Item -Recurse -Force $Destination
    Write-Step "removed $Destination"
  } else {
    Write-Step "nothing installed at $Destination"
  }
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  $binDir = Join-Path $Destination 'bin'
  if ($userPath -and $userPath.Split(';') -contains $binDir) {
    $kept = ($userPath.Split(';') | Where-Object { $_ -ne $binDir }) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $kept, 'User')
    Write-Step 'removed it from your PATH'
  }
  Write-Host "`n$AppName uninstalled. Open a new terminal for PATH to update.`n"
  exit 0
}

# ---- prerequisites --------------------------------------------------------
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
  Write-Error @"
Node.js 18 or newer is required and 'node' is not on PATH.

  Install it from https://nodejs.org (LTS), or:
      winget install OpenJS.NodeJS.LTS

Then run this script again.
"@
}
$nodeVersion = (& node -v) -replace '^v', ''
$major = [int]($nodeVersion.Split('.')[0])
if ($major -lt 18) {
  Write-Error "Node.js $nodeVersion is too old — 18 or newer is required. Update from https://nodejs.org"
}
Write-Step "found Node.js $nodeVersion"

# ---- copy -----------------------------------------------------------------
$source = Split-Path -Parent $PSScriptRoot     # the unpacked archive root
if (-not (Test-Path (Join-Path $source 'jedi-cli.js'))) {
  Write-Error "cannot find jedi-cli.js next to this script — run it from inside the unpacked archive"
}

if (Test-Path $Destination) {
  # An upgrade must not carry a previous release's files forward, but it must
  # not take auth.json or certs with it either: those are this machine's.
  Get-ChildItem $Destination -Exclude 'auth.json', 'certs' | Remove-Item -Recurse -Force
} else {
  New-Item -ItemType Directory -Path $Destination -Force | Out-Null
}

$items = @('jedi-cli.js','forward.js','updater.js','server.js','auth.js','ecosystem.config.js',
           'index.html','login.html','account.html','about.html',
           'js','css','bin','samples','types','packaging',
           'README.md','DOCUMENTATION.md','CONNECTORS.md')
foreach ($item in $items) {
  $src = Join-Path $source $item
  if (Test-Path $src) { Copy-Item $src -Destination $Destination -Recurse -Force }
}
Write-Step "installed to $Destination"

# ---- PATH -----------------------------------------------------------------
$binDir = Join-Path $Destination 'bin'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if ($userPath.Split(';') -notcontains $binDir) {
  [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $binDir).TrimStart(';'), 'User')
  Write-Step 'added bin\ to your user PATH'
} else {
  Write-Step 'already on your PATH'
}

$version = & node -p "require('$($Destination -replace '\\','/')/js/version.js').VERSION"
Write-Host @"

$AppName $version installed.

  jedi                     live dashboard  (open a NEW terminal first)
  jedi --help              every command and flag
  jedi update              check for a newer version

  If box characters look wrong, use:  jedi --ascii
  To remove:  powershell -ExecutionPolicy Bypass -File "$Destination\packaging\install.ps1" -Uninstall

"@
