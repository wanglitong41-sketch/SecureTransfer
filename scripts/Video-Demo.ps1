[CmdletBinding()]
param(
  [Parameter(Mandatory, Position = 0)]
  [ValidateSet('Samples', 'Prepare', 'Start', 'Hash', 'Probe', 'Bandwidth', 'Browser', 'Long', 'Acl')]
  [string]$Action,

  [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}$')]
  [string]$Run = 'take-1',

  [ValidateSet('transfer.txt', 'resume-8MiB.bin', 'parallel-a.bin', 'parallel-b.bin', 'parallel-c.bin')]
  [string]$Sample = 'transfer.txt',

  [string]$Downloaded,

  [switch]$Headed
)

$ErrorActionPreference = 'Stop'
$project = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$runRoot = Join-Path $project "runtime/video-$Run"
$deployment = Join-Path $runRoot 'deployment'
$samples = Join-Path $runRoot 'samples'
$downloads = Join-Path $runRoot 'downloads'
$evidence = Join-Path $runRoot 'evidence'

function Invoke-Npm {
  Write-Host ('> npm ' + ($args -join ' '))
  & npm.cmd @args
  if ($LASTEXITCODE -ne 0) { throw "npm exited with code $LASTEXITCODE." }
}

function Confirm-PortAvailable {
  $network = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
  if ($network.GetActiveTcpListeners() | Where-Object Port -eq 8443) {
    throw 'Port 8443 is in use. Stop the previous project server in its terminal.'
  }
}

function New-Samples {
  New-Item -ItemType Directory -Path $samples, $downloads -Force | Out-Null
  $description = Join-Path $samples 'transfer.txt'
  if (-not (Test-Path -LiteralPath $description)) {
    'SecureTransfer EX1B file transfer demo' | Set-Content -LiteralPath $description -Encoding utf8
  }
  $sizes = [ordered]@{
    'resume-8MiB.bin' = 8MB
    'parallel-a.bin' = 2MB
    'parallel-b.bin' = 2MB
    'parallel-c.bin' = 2MB
  }
  foreach ($name in $sizes.Keys) {
    $file = Join-Path $samples $name
    if (Test-Path -LiteralPath $file) {
      if ((Get-Item -LiteralPath $file).Length -eq $sizes[$name]) { continue }
      throw "Unexpected file size: $file. Use a new -Run value."
    }
    $bytes = [byte[]]::new($sizes[$name])
    $random = [Random]::new([int][char]$name[$name.Length - 5])
    $random.NextBytes($bytes)
    [IO.File]::WriteAllBytes($file, $bytes)
  }
  Write-Host "Samples:   $samples"
  Write-Host "Downloads: $downloads"
  Get-ChildItem -LiteralPath $samples -File | Select-Object Name, Length | Format-Table -AutoSize
}

$environment = @{}
$envNames = 'Path', 'ST_DATA_DIR', 'ST_PORT', 'ST_MODE', 'ST_BANDWIDTH_POLICY', 'ST_EVIDENCE_DIR', 'ST_E2E_DATA_DIR'
foreach ($name in $envNames) {
  $environment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Push-Location -LiteralPath $project
try {
  switch ($Action) {
    'Samples' { New-Samples }
    'Prepare' {
      if (Test-Path -LiteralPath $deployment) {
        throw "Deployment directory already exists: $deployment. Use a new -Run value."
      }
      Confirm-PortAvailable
      Write-Host '> Setup-Node.ps1'
      & (Join-Path $PSScriptRoot 'Setup-Node.ps1')
      . (Join-Path $PSScriptRoot 'Use-Node.ps1')
      Invoke-Npm ci
      Write-Host '> Setup-Certificates.ps1 -Trust'
      & (Join-Path $PSScriptRoot 'Setup-Certificates.ps1') -Trust
      Invoke-Npm run build
      Write-Host '> Prepare-Deployment.ps1'
      & (Join-Path $PSScriptRoot 'Prepare-Deployment.ps1') -DeploymentRoot $deployment
      New-Samples
      Write-Host "Deployment: $deployment"
    }
    'Start' {
      Confirm-PortAvailable
      $node = Join-Path $deployment 'tools/node/node.exe'
      if (-not (Test-Path -LiteralPath $node)) { throw 'Run Prepare for this take first.' }
      $env:ST_DATA_DIR = Join-Path $deployment 'runtime'
      $env:ST_PORT = '8443'
      $env:ST_MODE = 'production'
      $env:ST_BANDWIDTH_POLICY = $null
      Set-Location -LiteralPath $deployment
      Write-Host '> node apps/server/dist/index.js'
      Write-Host "Deployment: $deployment"
      & $node (Join-Path $deployment 'apps/server/dist/index.js')
      if ($LASTEXITCODE -ne 0) { throw "Server exited with code $LASTEXITCODE." }
    }
    'Hash' {
      if (-not $Downloaded) { $Downloaded = Join-Path $downloads $Sample }
      $expected = Get-FileHash -LiteralPath (Join-Path $samples $Sample) -Algorithm SHA256
      $actual = Get-FileHash -LiteralPath $Downloaded -Algorithm SHA256
      Write-Host "Source   SHA-256: $($expected.Hash)"
      Write-Host "Download SHA-256: $($actual.Hash)"
      if ($expected.Hash -ne $actual.Hash) { throw 'SHA-256 mismatch.' }
      Write-Host 'PASS: SHA-256 matches.'
    }
    'Probe' {
      $node = Join-Path $deployment 'tools/node/node.exe'
      if (-not (Test-Path -LiteralPath $node)) { throw 'Run Prepare for this take first.' }
      & $node (Join-Path $PSScriptRoot 'Verify-DeployedService.mjs') $deployment
      if ($LASTEXITCODE -ne 0) { throw 'Deployment transfer probe failed. See the diagnostic above.' }
    }
    { $_ -in 'Bandwidth', 'Browser', 'Long' } {
      Confirm-PortAvailable
      . (Join-Path $PSScriptRoot 'Use-Node.ps1')
      New-Item -ItemType Directory -Path $evidence -Force | Out-Null
      $env:ST_EVIDENCE_DIR = $evidence
      if ($Action -eq 'Bandwidth') {
        Invoke-Npm test '--' tests/integration/stage-six.test.ts -t 'enforces per-user upload and download rates'
        $report = Get-Content -LiteralPath (Join-Path $evidence 'bandwidth.json') -Raw | ConvertFrom-Json
        $report.samples | Select-Object tier, direction, connections, @{Name = 'KiB/s'; Expression = {
          [Math]::Round($_.bytes / ($_.elapsedMs / 1000) / 1024, 1)
        }} | Format-Table -AutoSize
      } elseif ($Action -eq 'Browser') {
        $env:ST_E2E_DATA_DIR = Join-Path $runRoot ('edge-' + [guid]::NewGuid().ToString('N'))
        $env:ST_PORT = '8443'
        $env:ST_MODE = 'production'
        $browserArgs = @('run', 'test:e2e', '--', '--output', (Join-Path $evidence 'edge-artifacts'))
        if ($Headed) { $browserArgs += '--headed' }
        Invoke-Npm @browserArgs
      } else {
        Invoke-Npm run test:long
        Get-Content -LiteralPath (Join-Path $evidence 'keepalive.json') -Raw | Write-Host
        Get-Content -LiteralPath (Join-Path $evidence 'stability.json') -Raw |
          ConvertFrom-Json | Select-Object result, users, elapsedMs, requests | Format-List
      }
      Write-Host "Evidence: $evidence"
    }
    'Acl' {
      Confirm-PortAvailable
      $env:ST_BANDWIDTH_POLICY = $null
      & (Join-Path $PSScriptRoot 'Configure-RuntimeAcl.ps1') -DeploymentRoot $deployment
      & (Join-Path $PSScriptRoot 'Verify-Deployment.ps1') -DeploymentRoot $deployment -EvidenceDirectory $evidence
      Get-Content -LiteralPath (Join-Path $evidence 'restricted-deployment.json') -Raw |
        ConvertFrom-Json | Select-Object result, processOwner | Format-List
      Get-Content -LiteralPath (Join-Path $evidence 'acl-probe.json') -Raw |
        ConvertFrom-Json | Select-Object -ExpandProperty checks | Format-List
    }
  }
} finally {
  Pop-Location
  foreach ($name in $envNames) {
    if ($null -eq $environment[$name]) {
      Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    } else {
      Set-Item -LiteralPath "Env:$name" -Value $environment[$name]
    }
  }
}

