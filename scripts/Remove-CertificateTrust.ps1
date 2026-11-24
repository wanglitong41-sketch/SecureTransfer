$ErrorActionPreference = 'Stop'
$thumbprintPath = Join-Path $PSScriptRoot '../runtime/certs/trusted-thumbprint.txt'
if (-not (Test-Path -LiteralPath $thumbprintPath)) { throw 'No project CA thumbprint found.' }
$thumbprint = (Get-Content -LiteralPath $thumbprintPath -Raw).Trim()
if ($thumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'Invalid project CA thumbprint.' }
$store = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
try {
  $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  $matches = $store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $thumbprint, $false)
  foreach ($certificate in $matches) { $store.Remove($certificate) }
  Write-Host 'Removed project CA trust, if present, from the current user store.'
} finally { $store.Close() }
