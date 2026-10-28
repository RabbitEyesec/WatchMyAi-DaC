<#
.SYNOPSIS
  Install or update Sysmon with the WatchMyAI configuration on a Windows lab host.

.DESCRIPTION
  Downloads Sysmon from the official Sysinternals location, refuses to run it unless the
  binary carries a valid Microsoft Authenticode signature, then installs or reconfigures
  it with deployment\windows\sysmon\watchmyai-sysmon.xml. Elastic Agent collection is
  configured separately in Fleet (see docs\SYSMON_INTEGRATION.md).

  Run from an elevated PowerShell on a DISPOSABLE or approved host only.

.PARAMETER Config
  Path to the Sysmon XML. Defaults to the repository copy.
.PARAMETER SysmonPath
  Use an already-downloaded Sysmon64.exe instead of downloading one.
.PARAMETER DryRun
  Print what would happen and change nothing.
#>
[CmdletBinding()]
param(
  [string]$Config = (Join-Path $PSScriptRoot '..\..\deployment\windows\sysmon\watchmyai-sysmon.xml'),
  [string]$SysmonPath = '',
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Test-Administrator {
  $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) { throw 'Run this script from an elevated PowerShell session.' }
if (-not (Test-Path -LiteralPath $Config)) { throw "Sysmon configuration not found: $Config" }
$null = [xml](Get-Content -LiteralPath $Config -Raw)   # fails on malformed XML

if (-not $SysmonPath) {
  $work = Join-Path $env:TEMP ('watchmyai-sysmon-' + [guid]::NewGuid().ToString('N'))
  $zip = Join-Path $work 'Sysmon.zip'
  if ($DryRun) {
    Write-Host "DRY RUN: would download https://download.sysinternals.com/files/Sysmon.zip to $zip"
    Write-Host "DRY RUN: would verify the Microsoft signature and install with $Config"
    return
  }
  New-Item -ItemType Directory -Path $work | Out-Null
  Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing
  Expand-Archive -LiteralPath $zip -DestinationPath $work
  $SysmonPath = Join-Path $work 'Sysmon64.exe'
}
if (-not (Test-Path -LiteralPath $SysmonPath)) { throw "Sysmon binary not found: $SysmonPath" }

$signature = Get-AuthenticodeSignature -LiteralPath $SysmonPath
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
  throw "Refusing to run $SysmonPath : Authenticode status $($signature.Status), signer $($signature.SignerCertificate.Subject)"
}
Write-Host "Verified Microsoft signature on $SysmonPath"

$installed = $null -ne (Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue)
if ($DryRun) {
  $action = if ($installed) { 'update configuration' } else { 'install' }
  Write-Host "DRY RUN: would $action Sysmon with $Config"
  return
}
if ($installed) {
  & $SysmonPath -accepteula -c $Config
} else {
  & $SysmonPath -accepteula -i $Config
}
if ($LASTEXITCODE -ne 0) { throw "Sysmon exited with code $LASTEXITCODE" }

$log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
Write-Host "Sysmon is running. Operational log records: $($log.RecordCount)"
Write-Host 'Next: enrol this host in a dedicated Fleet policy with the Windows integration (sysmon_operational).'
