param([switch]$Trust)
$ErrorActionPreference = 'Stop'
$certRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../runtime/certs'))
New-Item -ItemType Directory -Path $certRoot -Force | Out-Null

$opensslCommand = Get-Command openssl.exe -ErrorAction SilentlyContinue
if ($opensslCommand) {
  $opensslPath = $opensslCommand.Source
} else {
  $gitCommand = Get-Command git.exe -ErrorAction Stop
  $opensslPath = [IO.Path]::GetFullPath((Join-Path (Split-Path $gitCommand.Source) '../usr/bin/openssl.exe'))
}
if (-not (Test-Path -LiteralPath $opensslPath)) { throw 'OpenSSL is required; install Git for Windows with its bundled OpenSSL.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $certRoot /inheritance:r /grant:r "*$($identity):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict certificate directory permissions.' }

function Invoke-OpenSSL([string[]]$Arguments) {
  $ErrorActionPreference = 'Continue'
  $output = & $opensslPath @Arguments 2>&1
  if ($LASTEXITCODE -ne 0) { throw "OpenSSL failed: $output" }
}

$caPem = Join-Path $certRoot 'ca-cert.pem'
$caKey = Join-Path $certRoot 'ca-key.pem'
$caDer = Join-Path $certRoot 'ca-cert.cer'
$serverPem = Join-Path $certRoot 'server-cert.pem'
$serverKey = Join-Path $certRoot 'server-key.pem'
$serverRequest = Join-Path $certRoot 'server.csr'
$extensionPath = Join-Path $certRoot 'server.ext'
$paths = @($caPem, $caKey, $caDer, $serverPem, $serverKey)
$existing = @($paths | Where-Object { Test-Path -LiteralPath $_ })
if ($existing.Count -gt 0 -and $existing.Count -ne $paths.Count) {
  throw 'Partial certificate files exist. Inspect runtime/certs before retrying; existing keys will not be overwritten.'
}
if ($existing.Count -eq 0) {
  Invoke-OpenSSL -Arguments @('req','-x509','-newkey','rsa:3072','-nodes','-sha256','-days','30',
    '-subj','/CN=SecureTransfer Local Test CA','-addext','basicConstraints=critical,CA:TRUE',
    '-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',$caKey,'-out',$caPem)
  Invoke-OpenSSL -Arguments @('req','-new','-newkey','rsa:3072','-nodes','-sha256','-subj','/CN=localhost',
    '-keyout',$serverKey,'-out',$serverRequest)
  @(
    'basicConstraints=critical,CA:FALSE'
    'keyUsage=critical,digitalSignature,keyEncipherment'
    'extendedKeyUsage=serverAuth'
    'subjectAltName=DNS:localhost,IP:127.0.0.1'
  ) | Set-Content -LiteralPath $extensionPath -Encoding ascii
  Invoke-OpenSSL -Arguments @('x509','-req','-in',$serverRequest,'-CA',$caPem,'-CAkey',$caKey,
    '-CAcreateserial','-days','30','-sha256','-extfile',$extensionPath,'-out',$serverPem)
  Invoke-OpenSSL -Arguments @('x509','-in',$caPem,'-outform','DER','-out',$caDer)
}
Invoke-OpenSSL -Arguments @('verify','-CAfile',$caPem,'-verify_hostname','localhost',$serverPem)
Invoke-OpenSSL -Arguments @('x509','-in',$serverPem,'-checkend','0','-noout')

$certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($caDer)
$certificate.Thumbprint | Set-Content -LiteralPath (Join-Path $certRoot 'trusted-thumbprint.txt') -Encoding ascii
if ($Trust) {
  $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
  try {
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($certificate)
  } finally { $store.Close() }
  Write-Host 'Trusted this project CA in the current user certificate store.'
} else {
  Write-Host 'Certificates prepared. For browser trust run: npm run setup:certs -- -Trust'
}
$certificate.Dispose()
