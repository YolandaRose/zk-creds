# Builds the canonical passport RECORD_BLOB (same layout as `PassportDump::write_blob` / `PersonalInfo::record_blob`),
# signs SHA256(blob) with RSA PKCS#1 v1.5 + SHA-256, and writes base64 sig into `passport_dump.json`.
#
#   .\sign_passport_record.ps1 -PrivateKeyPath .\issuer_demo_priv.pem
#
param(
    [string]$JsonPath = (Join-Path $PSScriptRoot "passport_dump.json"),
    [string]$PrivateKeyPath = (Join-Path $PSScriptRoot "issuer_demo_priv.pem")
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $JsonPath)) { Write-Error "Missing $JsonPath" }
if (-not (Test-Path $PrivateKeyPath)) { Write-Error "Missing private key: $PrivateKeyPath" }

$stateLen = 3
$nameLen = 39
$bioMax = 128

$j = (Get-Content -LiteralPath $JsonPath -Raw -Encoding UTF8) | ConvertFrom-Json

function Pad-Utf8([string]$s, [int]$max) {
    $raw = [System.Text.Encoding]::UTF8.GetBytes($s)
    $buf = New-Object byte[] $max
    [Array]::Clear($buf, 0, $max)
    $n = [Math]::Min($raw.Length, $max)
    if ($n -gt 0) { [Array]::Copy($raw, $buf, $n) }
    return $buf
}

function To-BE4([uint32]$v) {
    $b = New-Object byte[] 4
    $b[0] = [byte](($v -shr 24) -band 255)
    $b[1] = [byte](($v -shr 16) -band 255)
    $b[2] = [byte](($v -shr 8) -band 255)
    $b[3] = [byte]($v -band 255)
    return $b
}

$bioRaw = [Convert]::FromBase64String($j.biometrics)
if ($bioRaw.Length -gt $bioMax) {
    Write-Warning "biometrics decodes to $($bioRaw.Length) bytes; truncating to $bioMax"
    $tmp = New-Object byte[] $bioMax
    [Array]::Copy($bioRaw, $tmp, $bioMax)
    $bioRaw = $tmp
}

$blob = New-Object byte[] ($stateLen + $nameLen + 4 + 4 + $bioMax)
$o = 0
[Array]::Copy((Pad-Utf8 $j.nationality $stateLen), 0, $blob, $o, $stateLen); $o += $stateLen
[Array]::Copy((Pad-Utf8 $j.name $nameLen), 0, $blob, $o, $nameLen); $o += $nameLen
[Array]::Copy((To-BE4([uint32]$j.dob)), 0, $blob, $o, 4); $o += 4
[Array]::Copy((To-BE4([uint32]$j.passport_expiry)), 0, $blob, $o, 4); $o += 4
[Array]::Clear($blob, $o, $bioMax)
[Array]::Copy($bioRaw, 0, $blob, $o, [Math]::Min($bioRaw.Length, $bioMax))

$tmp = [System.IO.Path]::GetTempFileName()
$tmpSig = [System.IO.Path]::GetTempFileName()
try {
    [System.IO.File]::WriteAllBytes($tmp, $blob)
    & openssl dgst -sha256 -sign $PrivateKeyPath -out $tmpSig $tmp
    if ($LASTEXITCODE -ne 0) { Write-Error "openssl sign failed: $LASTEXITCODE" }
    $sigB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($tmpSig))
    $j.sig = $sigB64
    $j | ConvertTo-Json | Set-Content -LiteralPath $JsonPath -Encoding UTF8
    Write-Host "Updated sig in $JsonPath"
}
finally {
    Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpSig -ErrorAction SilentlyContinue
}
