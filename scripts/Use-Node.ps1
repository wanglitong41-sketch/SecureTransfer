$nodeDirectory = Join-Path $PSScriptRoot '../runtime/tools/node-v26.13.1-win-x64'
if (-not (Test-Path -LiteralPath (Join-Path $nodeDirectory 'node.exe'))) {
  throw 'Run scripts/Setup-Node.ps1 first.'
}
$env:Path = (Resolve-Path -LiteralPath $nodeDirectory).Path + ';' + $env:Path
