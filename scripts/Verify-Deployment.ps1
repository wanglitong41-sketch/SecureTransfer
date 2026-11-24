[CmdletBinding()]
param(
  [string]$DeploymentRoot,
  [PSCredential]$Credential,
  [string]$EvidenceDirectory
)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
$runtimeRoot = Join-Path $projectRoot 'runtime'
if (-not $DeploymentRoot) { $DeploymentRoot = Join-Path $projectRoot 'runtime/deploy-stage5-final' }
$targetRoot = [IO.Path]::GetFullPath($DeploymentRoot).TrimEnd('\')
if (-not $targetRoot.StartsWith($runtimeRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid deployment root.' }
$manifest = Get-Content -LiteralPath (Join-Path $targetRoot 'deployment.json') -Raw | ConvertFrom-Json
if (-not $manifest.managedDeployment -or $manifest.sourceRoot -ne $projectRoot) { throw 'Invalid deployment manifest.' }
if (-not $Credential) { $Credential = Get-Credential -UserName "$env:COMPUTERNAME\SecureTransferSvc" -Message 'Run the isolated deployment under its standard account' }
if ($Credential.UserName -notmatch '(?i)(^|\\)SecureTransferSvc$') { throw 'Use the designated runtime account.' }
if (Get-NetTCPConnection -State Listen -LocalPort 8443 -ErrorAction SilentlyContinue) { throw 'Port 8443 is already in use.' }
function Assert-AclProbePassed([string]$ReportPath, [string]$ErrorPath, [Nullable[int]]$ExitCode) {
  $logHint = "See $ReportPath and $ErrorPath."
  if ($null -ne $ExitCode -and $ExitCode -ne 0) {
    throw "Runtime-account ACL probe exited with code $ExitCode. $logHint"
  }

  try {
    $report = Get-Content -LiteralPath $ReportPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "Runtime-account ACL probe did not produce a readable JSON report. $logHint"
  }
  if (-not $report -or $report.result -cne 'PASS' -or $report.identity -ine "$env:COMPUTERNAME\SecureTransferSvc" -or -not $report.checks) {
    throw "Runtime-account ACL probe did not confirm a pass under SecureTransferSvc. $logHint"
  }
  foreach ($check in @(
    'database writable', 'storage writable', 'temp writable', 'logs writable',
    'server key readable', 'server key write denied', 'code write denied',
    'protected outside read denied', 'non-administrator', 'expected identity'
  )) {
    $property = $report.checks.PSObject.Properties[$check]
    if (-not $property -or $property.Value -isnot [bool] -or -not $property.Value) {
      throw "Runtime-account ACL probe check failed or missing: $check. $logHint"
    }
  }
}

$evidenceRoot = Join-Path $targetRoot 'runtime/logs'
$protectedDirectory = Join-Path $targetRoot ('../acl-probe-' + [guid]::NewGuid().ToString('N'))
$protectedFile = Join-Path $protectedDirectory 'fixture.txt'
$oldDataRoot=$env:ST_DATA_DIR; $oldMode=$env:ST_MODE; $oldPort=$env:ST_PORT
$service = $null
try {
  New-Item -ItemType Directory -Path $protectedDirectory -Force | Out-Null
  $protectedAcl = New-Object Security.AccessControl.DirectorySecurity
  $protectedAcl.SetAccessRuleProtection($true,$false)
  foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
    $protectedAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  }
  Set-Acl -LiteralPath $protectedDirectory -AclObject $protectedAcl
  [IO.File]::WriteAllText($protectedFile,'protected-acl-fixture')
  $probeOutput = Join-Path $evidenceRoot 'acl-probe.json'
  $probeError = Join-Path $evidenceRoot 'acl-probe-error.log'
  $probeArguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $targetRoot 'tools/Probe-ServiceAccess.ps1') + '" -DeploymentRoot "' + $targetRoot + '" -ProtectedFile "' + $protectedFile + '"'
  $probe = Start-Process -FilePath "$env:SystemRoot/System32/WindowsPowerShell/v1.0/powershell.exe" -ArgumentList $probeArguments -Credential $Credential -WindowStyle Hidden -RedirectStandardOutput $probeOutput -RedirectStandardError $probeError -PassThru
  if (-not $probe.WaitForExit(30000)) {
    Stop-Process -Id $probe.Id -ErrorAction SilentlyContinue
    throw "Runtime-account ACL probe timed out. See $probeOutput and $probeError."
  }
  # The exit code may be unavailable for a process started with alternate credentials.
  Assert-AclProbePassed -ReportPath $probeOutput -ErrorPath $probeError -ExitCode $probe.ExitCode
  $nodePath = Join-Path $targetRoot 'tools/node/node.exe'
  $env:ST_DATA_DIR=Join-Path $targetRoot 'runtime'; $env:ST_MODE='production'; $env:ST_PORT='8443'
  $service = Start-Process -FilePath $nodePath -ArgumentList ('"' + (Join-Path $targetRoot 'apps/server/dist/index.js') + '"') -WorkingDirectory $targetRoot -Credential $Credential -WindowStyle Hidden -RedirectStandardOutput (Join-Path $evidenceRoot 'service-console.log') -RedirectStandardError (Join-Path $evidenceRoot 'service-error.log') -PassThru
  Start-Sleep -Seconds 2
  if ($service.HasExited) { throw 'Runtime service failed to start.' }
  $owner = Invoke-CimMethod -InputObject (Get-CimInstance Win32_Process -Filter "ProcessId=$($service.Id)") -MethodName GetOwner
  if ($owner.ReturnValue -ne 0 -or $owner.User -ne 'SecureTransferSvc') { throw 'Could not verify the actual Node process owner.' }
  & $nodePath (Join-Path $targetRoot 'tools/Verify-DeployedService.mjs') $targetRoot |
    Tee-Object -FilePath (Join-Path $evidenceRoot 'service-transfer.json')
  if ($LASTEXITCODE -ne 0) { throw 'Real restricted-account service transfer failed.' }
  & icacls.exe $targetRoot /T /L | Set-Content -LiteralPath (Join-Path $evidenceRoot 'acl-listing.txt') -Encoding utf8
  $publishedEvidence = $EvidenceDirectory
  if (-not $publishedEvidence) { $publishedEvidence = Join-Path $projectRoot 'docs/evidence/stage-5' }
  New-Item -ItemType Directory -Path $publishedEvidence -Force | Out-Null
  foreach ($name in @('acl-probe.json','acl-probe-error.log','service-transfer.json','acl-listing.txt','service-error.log')) {
    Copy-Item -LiteralPath (Join-Path $evidenceRoot $name) -Destination (Join-Path $publishedEvidence $name) -Force
  }
  [ordered]@{ result='PASS'; processOwner=$owner.User; processId=$service.Id; deploymentRoot=$targetRoot; recordedAt=[DateTime]::UtcNow.ToString('o') } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $publishedEvidence 'restricted-deployment.json') -Encoding utf8
  Write-Output "Restricted-account ACL and file transfer verified. Evidence: $evidenceRoot"
} finally {
  if ($service -and -not $service.HasExited) { Stop-Process -Id $service.Id }
  $env:ST_DATA_DIR=$oldDataRoot; $env:ST_MODE=$oldMode; $env:ST_PORT=$oldPort
  Remove-Item -LiteralPath $protectedFile -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $protectedDirectory -ErrorAction SilentlyContinue
}
