# Rewrites `sig` in passport_dump.json to an RSA PKCS#1 v1.5 + SHA-256 signature over the raw
# `econtent` bytes (must match zk-creds bench verification / PassportDump::econtent_hash).
#
# Default private key: issuer_demo_priv.pem (test only). Use your own key:
#   .\sign_econtent_for_issuer.ps1 -PrivateKeyPath .\issuer_priv.pem
#
# Requires: OpenSSL on PATH, PowerShell 5+

param(
    [string]$DumpPath = (Join-Path $PSScriptRoot "passport_dump.json"),
    [string]$PrivateKeyPath = (Join-Path $PSScriptRoot "issuer_demo_priv.pem")
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $DumpPath)) {
    Write-Error "Missing $DumpPath — add a passport JSON dump (see README)."
}
if (-not (Test-Path $PrivateKeyPath)) {
    Write-Error "Missing private key: $PrivateKeyPath"
}

$jsonText = Get-Content -LiteralPath $DumpPath -Raw -Encoding UTF8
$json = $jsonText | ConvertFrom-Json
if (-not $json.econtent) {
    Write-Error "JSON has no econtent field"
}

$econtent = [Convert]::FromBase64String($json.econtent)
$tmpIn = [System.IO.Path]::GetTempFileName()
$tmpOut = [System.IO.Path]::GetTempFileName()
try {
    [System.IO.File]::WriteAllBytes($tmpIn, $econtent)
    & openssl dgst -sha256 -sign $PrivateKeyPath -out $tmpOut $tmpIn
    if ($LASTEXITCODE -ne 0) {
        Write-Error "openssl sign failed with exit code $LASTEXITCODE"
    }
    $sigBytes = [System.IO.File]::ReadAllBytes($tmpOut)
    $json.sig = [Convert]::ToBase64String($sigBytes)
    $json | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $DumpPath -Encoding UTF8
    Write-Host "Updated sig in $DumpPath ($( $sigBytes.Length ) bytes, base64 in JSON)."
}
finally {
    Remove-Item -LiteralPath $tmpIn -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpOut -ErrorAction SilentlyContinue
}
