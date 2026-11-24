[CmdletBinding(SupportsShouldProcess)]
param([Security.SecureString]$Password)
$ErrorActionPreference = 'Stop'
$accountName = 'SecureTransferSvc'
if ($WhatIfPreference) { $null = $PSCmdlet.ShouldProcess($accountName, 'Create a standard local runtime account with a supplied secure password'); return }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Administrator PowerShell is required to create SecureTransferSvc.'
}
if (Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue) { throw 'Account already exists; its password and groups will not be changed.' }
if (-not $Password) { $Password = Read-Host 'Set a password for SecureTransferSvc (never put it in command text)' -AsSecureString }
if ($PSCmdlet.ShouldProcess($accountName, 'Create a non-administrator local runtime account')) {
  $user = New-LocalUser -Name $accountName -Password $Password -Description 'SecureTransfer coursework runtime identity' -UserMayNotChangePassword
  $users = Get-LocalGroup -SID 'S-1-5-32-545'
  if (-not (Get-LocalGroupMember -Group $users.Name | Where-Object { $_.SID -eq $user.SID })) {
    Add-LocalGroupMember -Group $users.Name -Member $user
  }
  Write-Output "Created standard account: $accountName"
}
