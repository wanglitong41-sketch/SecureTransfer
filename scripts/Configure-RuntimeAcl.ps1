[CmdletBinding(SupportsShouldProcess)]
param([string]$DeploymentRoot)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
$runtimeRoot = Join-Path $projectRoot 'runtime'
if (-not $DeploymentRoot) { $DeploymentRoot = Join-Path $projectRoot 'runtime/deploy-stage5-final' }
$targetRoot = [IO.Path]::GetFullPath($DeploymentRoot).TrimEnd('\')
if (-not $targetRoot.StartsWith($runtimeRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Only a prepared deployment below project runtime can be configured.' }
$manifestPath = Join-Path $targetRoot 'deployment.json'
if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'Prepare-Deployment.ps1 must complete first.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if (-not $manifest.managedDeployment -or $manifest.sourceRoot -ne $projectRoot) { throw 'Deployment manifest does not match this repository.' }
if ($WhatIfPreference) {
  $null = $PSCmdlet.ShouldProcess($targetRoot, 'Set code/runtime/certificate ACLs for SecureTransferSvc while preserving the operator, SYSTEM and Administrators')
  return
}
$user = Get-LocalUser -Name 'SecureTransferSvc' -ErrorAction Stop
$administrators = Get-LocalGroup -SID 'S-1-5-32-544'
if (Get-LocalGroupMember -Group $administrators.Name | Where-Object { $_.SID -eq $user.SID }) { throw 'SecureTransferSvc must not be an administrator.' }
if (-not $manifest.operatorSid) { throw 'Re-prepare this deployment with an operator SID in its manifest.' }
$operatorSid = [Security.Principal.SecurityIdentifier]::new([string]$manifest.operatorSid)
function Set-DirectoryPermissions([string]$Path, [Security.AccessControl.FileSystemRights]$ServiceRights) {
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($operatorSid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
  }
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user.SID, $ServiceRights, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
  Set-Acl -LiteralPath $Path -AclObject $acl
}
if ($PSCmdlet.ShouldProcess($targetRoot, 'Apply runtime account permissions to this dedicated deployment')) {
  Set-DirectoryPermissions $targetRoot 'ReadAndExecute'
  foreach ($name in @('database','storage','temp','logs')) {
    Set-DirectoryPermissions (Join-Path $targetRoot "runtime/$name") 'Modify'
  }
  Set-DirectoryPermissions (Join-Path $targetRoot 'runtime/certs') 'ReadAndExecute'
  & icacls.exe $targetRoot /verify /T /L /Q
  if ($LASTEXITCODE -ne 0) { throw 'ACL verification failed.' }
  Write-Output 'Configured code/certificates read-only and runtime data writable for SecureTransferSvc.'
}
