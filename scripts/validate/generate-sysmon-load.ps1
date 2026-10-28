<#
.SYNOPSIS
  Generate benign, uniquely-tagged file activity for the WMAI-023 / WMAI-024 live tests.

.DESCRIPTION
  Creates -Creates files and then deletes -Deletes of them inside one temporary workspace
  from a SINGLE process (this PowerShell process), so the Sysmon events share one
  process.entity_id. The workspace path embeds a run ID; pass that run ID to
  scripts/validate/verify_sysmon_ingest.py --run-id to correlate source events and alerts.

  Defaults exceed the rule thresholds (50 creations, 20 deletions). Use -Creates 10 -Deletes 5
  for a below-threshold negative run. Run on a disposable lab host only.
#>
[CmdletBinding()]
param(
  [int]$Creates = 60,
  [int]$Deletes = 25,
  [string]$RunId = ('wmai-' + [guid]::NewGuid().ToString('N').Substring(0, 12)),
  [string]$Root = (Join-Path $env:TEMP 'watchmyai-sysmon-lab')
)

$ErrorActionPreference = 'Stop'
if ($Deletes -gt $Creates) { throw '-Deletes cannot exceed -Creates.' }

$workspace = Join-Path $Root $RunId
New-Item -ItemType Directory -Path $workspace -Force | Out-Null
$started = (Get-Date).ToUniversalTime().ToString('o')
1..$Creates | ForEach-Object {
  Set-Content -LiteralPath (Join-Path $workspace ("f{0:D4}.tmp" -f $_)) -Value 'watchmyai benign test data'
}
1..$Deletes | ForEach-Object {
  Remove-Item -LiteralPath (Join-Path $workspace ("f{0:D4}.tmp" -f $_)) -Force
}
[pscustomobject]@{
  run_id       = $RunId
  workspace    = $workspace
  creates      = $Creates
  deletes      = $Deletes
  started_utc  = $started
  finished_utc = (Get-Date).ToUniversalTime().ToString('o')
  host         = $env:COMPUTERNAME
  pid          = $PID
} | ConvertTo-Json
Write-Host "Done. Verify with: python scripts/validate/verify_sysmon_ingest.py --run-id $RunId"
Write-Host "Clean up with: Remove-Item -Recurse -Force '$workspace'"
