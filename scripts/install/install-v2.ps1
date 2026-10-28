<#
.SYNOPSIS
  One-command setup for the WatchMyAI Version 2 toolchain (Sigma, Sysmon, D3FEND) on Windows.
.DESCRIPTION
  Creates .venv, installs WatchMyAI and the Version 2 tools from the hash-pinned lock file, and
  runs the toolchain. Use -InstallSysmon on a lab Windows host to also install Sysmon.
#>
param(
    [switch]$InstallSysmon
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepositoryRoot = (Resolve-Path (Join-Path $ScriptDir "../..")).Path

$PythonExe = $null
$PythonPrefix = @()
$Candidates = @(
    @{ Name = "py"; Prefix = @("-3.12") },
    @{ Name = "py"; Prefix = @("-3.11") },
    @{ Name = "python"; Prefix = @() }
)
foreach ($Candidate in $Candidates) {
    $Command = Get-Command $Candidate.Name -ErrorAction SilentlyContinue
    if (-not $Command) { continue }
    $CandidatePrefix = @($Candidate.Prefix)
    & $Command.Source @CandidatePrefix -c "import sys; raise SystemExit(not ((3, 11) <= sys.version_info[:2] < (3, 13)))" 2>$null
    if ($LASTEXITCODE -eq 0) {
        $PythonExe = $Command.Source
        $PythonPrefix = @($Candidate.Prefix)
        break
    }
}
if (-not $PythonExe) {
    Write-Error "Python 3.11 or 3.12 is required. Install it, then run this script again."
    exit 2
}

$VenvPython = Join-Path $RepositoryRoot ".venv\Scripts\python.exe"
Write-Host "==> Creating the virtual environment (.venv)"
if (-not (Test-Path $VenvPython)) {
    & $PythonExe @PythonPrefix -m venv (Join-Path $RepositoryRoot ".venv")
    if ($LASTEXITCODE -ne 0) { throw "Could not create .venv" }
}

Write-Host "==> Installing WatchMyAI and the Version 2 tools (hash-pinned)"
& $VenvPython -m pip install --quiet --require-hashes --requirement (Join-Path $RepositoryRoot "requirements-dev.lock")
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed" }
& $VenvPython -m pip install --quiet --no-build-isolation --no-deps $RepositoryRoot
if ($LASTEXITCODE -ne 0) { throw "WatchMyAI installation failed" }

Write-Host "==> Running the Version 2 toolchain"
Push-Location $RepositoryRoot
try {
    & $VenvPython scripts/run_v2_integrations.py
    if ($LASTEXITCODE -ne 0) { throw "Version 2 toolchain reported a failure" }
} finally {
    Pop-Location
}

if ($InstallSysmon) {
    Write-Host "==> Installing Sysmon with the WatchMyAI configuration"
    & (Join-Path $ScriptDir "install-sysmon.ps1")
}

Write-Host ""
Write-Host "WatchMyAI Version 2 is ready."
Write-Host "  Run everything again:    .venv\Scripts\python.exe scripts\run_v2_integrations.py"
Write-Host "  Install Sysmon (lab):    .\scripts\install\install-v2.ps1 -InstallSysmon"
Write-Host "  Check Sysmon in Elastic: .venv\Scripts\python.exe scripts\validate\verify_sysmon_ingest.py"
