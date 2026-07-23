param(
    [switch]$BootstrapOnly,
    [switch]$Dev
)

$ErrorActionPreference = "Stop"
$ExitMissingPrerequisite = 2
$ExitInvalidConfiguration = 3
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepositoryRoot = (Resolve-Path (Join-Path $ScriptDir "../..")).Path

if (-not $BootstrapOnly -and $env:OS -ne "Windows_NT") {
    Write-Error "Windows installation must run on Windows; use -BootstrapOnly for repository checks"
    exit $ExitMissingPrerequisite
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "Missing prerequisite: Git"
    exit $ExitMissingPrerequisite
}
if (-not $BootstrapOnly -and -not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    Write-Error "Missing prerequisite: curl.exe"
    exit $ExitMissingPrerequisite
}

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
    Write-Error "Python 3.11 or 3.12 is required"
    exit $ExitMissingPrerequisite
}

& $PythonExe @PythonPrefix (Join-Path $RepositoryRoot "scripts/validate/validate_config.py") `
    --config (Join-Path $RepositoryRoot ".env.example") --template
if ($LASTEXITCODE -ne 0) { exit $ExitInvalidConfiguration }

$VenvRoot = Join-Path $RepositoryRoot ".venv"
$VenvPython = Join-Path $VenvRoot "Scripts/python.exe"
if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    & $PythonExe @PythonPrefix -m venv $VenvRoot
    if ($LASTEXITCODE -ne 0) { exit $ExitMissingPrerequisite }
}
& $VenvPython -c "import sys; raise SystemExit(not ((3, 11) <= sys.version_info[:2] < (3, 13)))"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Existing .venv uses unsupported Python; recreate it with Python 3.11 or 3.12"
    exit $ExitMissingPrerequisite
}

$LockFile = Join-Path $RepositoryRoot $(if ($Dev) { "requirements-dev.lock" } else { "requirements-release.lock" })
& $VenvPython -m pip install --require-hashes --requirement $LockFile
if ($LASTEXITCODE -ne 0) { exit 1 }
& $VenvPython -m pip install --no-build-isolation --no-deps $RepositoryRoot
if ($LASTEXITCODE -ne 0) { exit 1 }
& $VenvPython -m pip check
if ($LASTEXITCODE -ne 0) { exit 1 }

$WatchMyAI = Join-Path $VenvRoot "Scripts/watchmyai.exe"
& $WatchMyAI --version
$SmokeHome = Join-Path ([System.IO.Path]::GetTempPath()) ("watchmyai-install-smoke-" + [guid]::NewGuid())
$PriorUnsignedPolicy = $env:WATCHMYAI_ALLOW_UNSIGNED_POLICY
try {
    & $WatchMyAI --home $SmokeHome init | Out-Null
    if ($LASTEXITCODE -ne 0) { exit 1 }
    $env:WATCHMYAI_ALLOW_UNSIGNED_POLICY = "1"
    & $WatchMyAI --home $SmokeHome self-check | Out-Null
    if ($LASTEXITCODE -ne 0) { exit 1 }
}
finally {
    $env:WATCHMYAI_ALLOW_UNSIGNED_POLICY = $PriorUnsignedPolicy
    if (Test-Path -LiteralPath $SmokeHome) { Remove-Item -LiteralPath $SmokeHome -Recurse -Force }
}

Write-Host "PASS: WatchMyAI installed non-editably in $VenvRoot"
Write-Host "Next: & '$WatchMyAI' setup --repository-only --non-interactive --config '$(Join-Path $RepositoryRoot '.env')'"
exit 0
