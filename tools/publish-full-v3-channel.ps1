[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArtifactRoot,
    [Parameter(Mandatory)][string]$HistoryOutputRoot,
    [Parameter(Mandatory)][string]$ScratchRoot,
    [Parameter(Mandatory)][string]$SeedZip,
    [string]$PriorHistoryRoot,
    [switch]$RequireV3
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'CloudPolicyV3Publisher.Common.psm1') -Force

function Read-PriorHistory {
    if ($PriorHistoryRoot) { return $PriorHistoryRoot }
    if (!$env:GITHUB_ACTIONS) { return }
    $query = "repos/$env:GITHUB_REPOSITORY/actions/artifacts?name=full-v3-history&per_page=100"
    $result = & gh api $query
    if ($LASTEXITCODE) { throw 'FULL_V3_HISTORY_API' }
    $artifacts = (($result -join "`n") | ConvertFrom-Json).artifacts
    $runsQuery = "repos/$env:GITHUB_REPOSITORY/actions/workflows/awg-policy-cloud.yml/runs?branch=main&status=success&per_page=100"
    $runsResult = & gh api $runsQuery
    if ($LASTEXITCODE) { throw 'FULL_V3_HISTORY_RUNS_API' }
    $completed = @(($runsResult -join "`n" | ConvertFrom-Json).workflow_runs | ForEach-Object id)
    $candidate = $artifacts | Where-Object {
        !$_.expired -and $_.workflow_run.head_branch -ceq 'main' -and
        [string]$_.workflow_run.id -cne $env:GITHUB_RUN_ID -and $_.workflow_run.id -in $completed
    } | Sort-Object created_at -Descending | Select-Object -First 1
    if (!$candidate) {
        # Distinguish a first rollout from loss of a previously published history.
        try {
            $head = Invoke-WebRequest -Uri 'https://alexseilepehin-arch.github.io/opencck-cloud-build/v3/full/latest.json' -TimeoutSec 20
        } catch {
            if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { return }
            throw
        }
        if ($head.StatusCode -eq 200) { throw 'FULL_V3_HISTORY_MISSING_AFTER_PUBLICATION' }
        throw 'FULL_V3_HISTORY_DISCOVERY_UNCERTAIN'
    }
    $target = Join-Path $ScratchRoot 'prior'
    & gh run download $candidate.workflow_run.id --repo $env:GITHUB_REPOSITORY --name full-v3-history --dir $target | Out-Host
    if ($LASTEXITCODE -or !(Test-Path -LiteralPath (Join-Path $target 'catalog.json'))) { throw 'FULL_V3_HISTORY_DOWNLOAD' }
    return $target
}

$prior = $null
try {
    [void](New-Item -ItemType Directory -Path $ScratchRoot)
    $prior = Read-PriorHistory
    $seedDir = Join-Path $ScratchRoot 'seed'
    Expand-Archive -LiteralPath $SeedZip -DestinationPath $seedDir
    $seed = Join-Path $seedDir 'full-policy-manifest.txt'
    if (!(Test-Path -LiteralPath $seed)) { throw 'FULL_V3_SEED_MISSING' }
    $arguments = @{ArtifactRoot=$ArtifactRoot;HistoryOutputRoot=$HistoryOutputRoot;SeedV2ManifestPath=$seed}
    if ($prior) { $arguments.PriorHistoryRoot = $prior }
    Publish-CloudPolicyV3Full @arguments
    if ($env:GITHUB_OUTPUT) { Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value 'history_ready=true' }
} catch {
    if ($RequireV3) { throw }
    Write-Warning ("Full v3 build deferred. " + $_.Exception.Message)
    if ($prior) {
        try {
            Copy-VerifiedCloudPolicyV3Channel -HistoryRoot $prior -ArtifactRoot $ArtifactRoot
        } catch {
            Write-Warning ("Verified Full v3 fallback unavailable. " + $_.Exception.Message)
        }
    }
    if ($env:GITHUB_OUTPUT) { Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value 'history_ready=false' }
}
