$ErrorActionPreference = 'Stop'
$toolsRoot = Join-Path $PSScriptRoot '../runtime/tools'
$nodeDirectory = Join-Path $toolsRoot 'node-v26.13.1-win-x64'
if (Test-Path -LiteralPath (Join-Path $nodeDirectory 'node.exe')) {
  & (Join-Path $nodeDirectory 'node.exe') --version
  if ($LASTEXITCODE -ne 0) { throw 'Local Node.js cannot start.' }
  return
}
New-Item -ItemType Directory -Path $toolsRoot -Force | Out-Null
$archivePath = Join-Path $toolsRoot 'node-v26.13.1-win-x64.zip'
Invoke-WebRequest -UseBasicParsing -Uri 'https://nodejs.org/dist/v26.13.1/node-v26.13.1-win-x64.zip' -OutFile $archivePath
$expectedHash = 'e2edda75bfb089654705cf65a13b58933bfd5f57148e8ebda916f58a2474f1f7'
if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
  throw 'Node.js archive checksum mismatch.'
}
Expand-Archive -LiteralPath $archivePath -DestinationPath $toolsRoot -Force
Write-Host 'Node.js prepared. Run: . ./scripts/Use-Node.ps1'
