param([Parameter(Mandatory)][string]$DeploymentRoot, [Parameter(Mandatory)][string]$ProtectedFile)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$checks = [ordered]@{}
foreach ($name in @('database','storage','temp','logs')) {
  $path = Join-Path $DeploymentRoot ("runtime/$name/access-" + [guid]::NewGuid().ToString('N') + '.tmp')
  try {
    [IO.File]::WriteAllText($path, 'acl-fixture')
    $checks["$name writable"] = ([IO.File]::ReadAllText($path) -eq 'acl-fixture')
  } catch { $checks["$name writable"] = $false }
  finally { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path } }
}
$keyPath = Join-Path $DeploymentRoot 'runtime/certs/server-key.pem'
try { $stream = [IO.File]::OpenRead($keyPath); $stream.Dispose(); $checks['server key readable'] = $true }
catch { $checks['server key readable'] = $false }
try {
  $stream = [IO.File]::Open($keyPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
  $stream.Dispose(); $checks['server key write denied'] = $false
} catch [UnauthorizedAccessException] { $checks['server key write denied'] = $true }
$sourceProbe = Join-Path $DeploymentRoot ('apps/server/dist/write-probe-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllText($sourceProbe, 'probe'); $checks['code write denied'] = $false }
catch [UnauthorizedAccessException] { $checks['code write denied'] = $true }
finally { if (Test-Path -LiteralPath $sourceProbe) { Remove-Item -LiteralPath $sourceProbe } }
try { $stream = [IO.File]::OpenRead($ProtectedFile); $stream.Dispose(); $checks['protected outside read denied'] = $false }
catch [UnauthorizedAccessException] { $checks['protected outside read denied'] = $true }
$checks['non-administrator'] = -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$checks['expected identity'] = $identity.Name.EndsWith('\SecureTransferSvc', [StringComparison]::OrdinalIgnoreCase)
$passed = -not ($checks.Values | Where-Object { -not $_ })
[ordered]@{ result = $(if ($passed) { 'PASS' } else { 'FAIL' }); identity = $identity.Name; checks = $checks } | ConvertTo-Json -Depth 4
if (-not $passed) { exit 1 }
exit 0
