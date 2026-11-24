[CmdletBinding(SupportsShouldProcess)]
param([string]$DeploymentRoot)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
$runtimeRoot = Join-Path $projectRoot 'runtime'
if (-not $DeploymentRoot) { $DeploymentRoot = Join-Path $projectRoot 'runtime/deploy-stage5-final' }
$targetRoot = [IO.Path]::GetFullPath($DeploymentRoot).TrimEnd('\')
if (-not $targetRoot.StartsWith($runtimeRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
  throw 'DeploymentRoot must be a dedicated directory below this project runtime.'
}
if (Test-Path -LiteralPath $targetRoot) { throw 'Deployment directory already exists; choose a new path. Existing files will not be overwritten.' }
foreach ($path in @('apps/server/dist/index.js','apps/web/dist/index.html','packages/protocol/dist/index.js','runtime/certs/server-cert.pem','runtime/certs/server-key.pem')) {
  if (-not (Test-Path -LiteralPath (Join-Path $projectRoot $path))) { throw "Missing prerequisite: $path. Build and prepare certificates first." }
}
$nodeRoot = Join-Path $projectRoot 'runtime/tools/node-v26.13.1-win-x64'
if (-not $PSCmdlet.ShouldProcess($targetRoot, 'Copy a separate production deployment and install locked production dependencies')) { return }
New-Item -ItemType Directory -Path $targetRoot -Force | Out-Null
$stagingAcl = New-Object Security.AccessControl.DirectorySecurity
$stagingAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
  $stagingAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -LiteralPath $targetRoot -AclObject $stagingAcl
foreach ($path in @('package.json','package-lock.json','.npmrc')) {
  Copy-Item -LiteralPath (Join-Path $projectRoot $path) -Destination (Join-Path $targetRoot $path)
}
foreach ($workspace in @('apps/server','apps/web','packages/protocol')) {
  $destination = Join-Path $targetRoot $workspace
  New-Item -ItemType Directory -Path $destination -Force | Out-Null
  Copy-Item -LiteralPath (Join-Path $projectRoot "$workspace/package.json") -Destination (Join-Path $destination 'package.json')
  Copy-Item -LiteralPath (Join-Path $projectRoot "$workspace/dist") -Destination (Join-Path $destination 'dist') -Recurse
}
$nodeDestination = Join-Path $targetRoot 'tools/node'
New-Item -ItemType Directory -Path $nodeDestination -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $nodeRoot 'node.exe') -Destination (Join-Path $nodeDestination 'node.exe')
if (Test-Path -LiteralPath (Join-Path $nodeRoot 'LICENSE')) {
  Copy-Item -LiteralPath (Join-Path $nodeRoot 'LICENSE') -Destination (Join-Path $nodeDestination 'LICENSE')
}
$certDestination = Join-Path $targetRoot 'runtime/certs'
New-Item -ItemType Directory -Path $certDestination -Force | Out-Null
foreach ($name in @('server-cert.pem','server-key.pem','ca-cert.pem')) {
  Copy-Item -LiteralPath (Join-Path $projectRoot "runtime/certs/$name") -Destination (Join-Path $certDestination $name)
}
foreach ($name in @('database','storage','temp','logs')) {
  New-Item -ItemType Directory -Path (Join-Path $targetRoot "runtime/$name") -Force | Out-Null
}
foreach ($name in @('Probe-ServiceAccess.ps1','Verify-DeployedService.mjs')) {
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $targetRoot "tools/$name")
}
$oldPath = $env:Path
try {
  $env:Path = $nodeRoot + ';' + $env:Path
  Push-Location -LiteralPath $targetRoot
  try {
    & (Join-Path $nodeRoot 'npm.cmd') ci --omit=dev --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw 'Production dependency installation failed.' }
  } finally { Pop-Location }
} finally { $env:Path = $oldPath }
[ordered]@{ managedDeployment = $true; sourceRoot = $projectRoot; createdAt = [DateTime]::UtcNow.ToString('o'); nodeVersion = '26.13.1'; operatorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } |
  ConvertTo-Json | Set-Content -LiteralPath (Join-Path $targetRoot 'deployment.json') -Encoding utf8
Write-Output "Prepared deployment: $targetRoot"
