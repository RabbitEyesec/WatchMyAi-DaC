param(
    [switch]$RepositoryOnly,
    [string]$Config = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepositoryRoot = (Resolve-Path (Join-Path $ScriptDir "../..")).Path
$Python = Join-Path $RepositoryRoot ".venv/Scripts/python.exe"
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    Write-Error "Missing repository environment: run scripts/install/install.ps1 -BootstrapOnly"
    exit 2
}
$Arguments = @((Join-Path $RepositoryRoot "scripts/preflight.py"))
if ($RepositoryOnly) { $Arguments += "--repository-only" }
if ($Config) { $Arguments += @("--config", $Config) }
& $Python @Arguments
exit $LASTEXITCODE
